from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from wazuh_sysmon_triage.clients.opensearch_client import OpenSearchClient
from wazuh_sysmon_triage.models.raw import RawHit


@dataclass
class FetchResult:
    hits: list[RawHit]
    truncated: bool
    reason: str | None
    fetched_count: int


DEFAULT_EVENT_IDS = (1, 11)


def build_sysmon_query(
    start: str,
    end: str,
    agent_id: str | None = None,
    agent_name: str | None = None,
    event_ids: Iterable[int] | None = None,
    size: int = 1000,
    agent_mode: str = "any",
) -> dict[str, Any]:
    """
    Build the OpenSearch DSL query for Sysmon EID 1 and 11 in Wazuh alerts.

    Uses @timestamp as the canonical time filter and matches agent by ID or name.
    Event ID matching is tolerant of numeric or string mappings.
    """
    ids = list(event_ids or DEFAULT_EVENT_IDS)
    ids_str = [str(value) for value in ids]

    eid_should = [
        {"terms": {"data.win.system.eventID": ids}},
        {"terms": {"data.win.system.eventID": ids_str}},
        {
            "query_string": {
                "query": " OR ".join(ids_str),
                "default_field": "data.win.system.eventID",
            }
        },
    ]

    filters: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": start, "lte": end}}},
        {"bool": {"should": eid_should, "minimum_should_match": 1}},
    ]

    if agent_id and agent_name:
        if agent_mode == "all":
            filters.insert(
                1,
                {
                    "bool": {
                        "filter": [
                            {"term": {"agent.id": agent_id}},
                            {"term": {"agent.name": agent_name}},
                        ]
                    }
                },
            )
        else:
            filters.insert(
                1,
                {
                    "bool": {
                        "should": [
                            {"term": {"agent.id": agent_id}},
                            {"term": {"agent.name": agent_name}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            )
    elif agent_id:
        filters.insert(1, {"term": {"agent.id": agent_id}})
    elif agent_name:
        filters.insert(1, {"term": {"agent.name": agent_name}})

    return {
        "size": size,
        "sort": [{"@timestamp": "asc"}, {"_shard_doc": "asc"}],
        "query": {"bool": {"filter": filters}},
        "_source": [
            "@timestamp",
            "agent.id",
            "agent.name",
            "agent.ip",
            "rule.id",
            "rule.description",
            "rule.mitre",
            "data.win.system.eventID",
            "data.win.eventdata.*",
            "data.win.system.computer",
            "data.win.system.channel",
            "data.win.system.eventRecordID",
        ],
    }


def _to_iso(value: str | datetime) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def fetch_sysmon_events(
    client: OpenSearchClient,
    index_pattern: str,
    start_dt: str | datetime,
    end_dt: str | datetime,
    agent_id: str | None,
    agent_name: str | None,
    event_ids: Sequence[int] = (1, 11),
    page_size: int = 1000,
    agent_mode: str = "any",
    run_id: str | None = None,
    case_id: str | None = None,
    max_events: int = 20000,
    max_pages: int = 200,
) -> FetchResult:
    """
    Fetch Sysmon events using a PIT and search_after pagination.
    """
    query_body = build_sysmon_query(
        start=_to_iso(start_dt),
        end=_to_iso(end_dt),
        agent_id=agent_id,
        agent_name=agent_name,
        event_ids=event_ids,
        size=page_size,
        agent_mode=agent_mode,
    )

    search_after: list[Any] | None = None
    hits: list[RawHit] = []
    truncated = False
    reason: str | None = None
    pages = 0

    pit_id: str | None = None
    try:
        pit_id = client.create_pit(index_pattern, run_id=run_id, case_id=case_id)
    except ValueError as exc:
        # Fallback for deployments without PIT support.
        if "PIT API not supported" not in str(exc):
            raise

    try:
        while True:
            if pages >= max_pages:
                truncated = True
                reason = "max-pages"
                break
            pages += 1

            if pit_id:
                response = client.search(
                    pit_id,
                    query_body,
                    search_after=search_after,
                    run_id=run_id,
                    case_id=case_id,
                )
            else:
                # Without PIT, use a stable, general-purpose tie-breaker.
                query_no_pit = dict(query_body)
                query_no_pit["sort"] = [{"@timestamp": "asc"}, {"_id": "asc"}]
                response = client.search_index(
                    index_pattern,
                    query_no_pit,
                    search_after=search_after,
                    run_id=run_id,
                    case_id=case_id,
                )

            page_hits: list[RawHit] = response.get("hits", {}).get("hits", [])
            if not page_hits:
                break
            for hit in page_hits:
                hits.append(hit)
                if len(hits) >= max_events:
                    truncated = True
                    reason = "max-events"
                    break
            if truncated:
                break
            last_sort = page_hits[-1].get("sort")
            if not isinstance(last_sort, list):
                break
            search_after = last_sort
    finally:
        if pit_id:
            client.delete_pit(pit_id, run_id=run_id, case_id=case_id)

    return FetchResult(
        hits=hits,
        truncated=truncated,
        reason=reason,
        fetched_count=len(hits),
    )


def fetch_data(agent_id: str, start: str, end: str, agent_name: str | None = None) -> dict:
    """
    Build a query for data based on agent selectors and time range.

    Args:
        agent_id (str): The ID of the agent to fetch data for.
        start (str): The start time in ISO8601 format.
        end (str): The end time in ISO8601 format.
        agent_name (Optional[str]): The agent name to match (optional).

    Returns:
        dict: A dictionary containing the query structure.
    """
    return {
        "agent_id": agent_id,
        "agent_name": agent_name,
        "start": start,
        "end": end,
        "query": build_sysmon_query(
            start=start,
            end=end,
            agent_id=agent_id,
            agent_name=agent_name,
        ),
    }


def fetch_all_agents(start: str, end: str) -> dict:
    """
    Fetch data for all agents within the specified time range.

    Args:
        start (str): The start time in ISO8601 format.
        end (str): The end time in ISO8601 format.

    Returns:
        dict: A dictionary containing the fetched data for all agents.
    """
    return {
        "start": start,
        "end": end,
        "query": build_sysmon_query(start=start, end=end),
    }
