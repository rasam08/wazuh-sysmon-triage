from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from wazuh_sysmon_triage.clients.opensearch_client import OpenSearchClient
from wazuh_sysmon_triage.models.raw import RawHit

LOGGER = logging.getLogger(__name__)


@dataclass
class FetchResult:
    hits: list[RawHit]
    truncated: bool
    reason: str | None
    fetched_count: int
    pages: int = 0
    pagination_mode: str = "unknown"


DEFAULT_SYSMON_EVENT_IDS = (1, 3, 5, 10, 11, 12, 13, 14, 22, 23, 26)
DEFAULT_WINDOWS_SECURITY_EVENT_IDS = (4624, 4697, 4698)
DEFAULT_EVENT_IDS = DEFAULT_SYSMON_EVENT_IDS + DEFAULT_WINDOWS_SECURITY_EVENT_IDS
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
WINDOWS_SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"


def _event_id_filter(ids: list[int]) -> dict[str, Any]:
    ids_str = [str(value) for value in ids]
    return {
        "bool": {
            "should": [
                {"terms": {"data.win.system.eventID": ids}},
                {"terms": {"data.win.system.eventID": ids_str}},
                {
                    "query_string": {
                        "query": " OR ".join(ids_str),
                        "default_field": "data.win.system.eventID",
                    }
                },
            ],
            "minimum_should_match": 1,
        }
    }


def _provider_filter(provider: str) -> dict[str, Any]:
    return {
        "bool": {
            "should": [
                {"term": {"data.win.system.providerName": provider}},
                {"term": {"data.win.system.providerName.keyword": provider}},
            ],
            "minimum_should_match": 1,
        }
    }


def _field_value_filter(field: str, values: list[int]) -> dict[str, Any]:
    text_values = [str(value) for value in values]
    return {
        "bool": {
            "should": [
                {"terms": {field: values}},
                {"terms": {field: text_values}},
            ],
            "minimum_should_match": 1,
        }
    }


def build_sysmon_query(
    start: str,
    end: str,
    agent_id: str | None = None,
    agent_name: str | None = None,
    event_ids: Iterable[int] | None = None,
    size: int = 1000,
    agent_mode: str = "all",
) -> dict[str, Any]:
    """
    Build the OpenSearch DSL query for supported Sysmon and Windows Security evidence.

    Uses @timestamp as the canonical time filter and matches agent by ID or name.
    Event ID matching is tolerant of numeric or string mappings.
    """
    ids = list(event_ids or DEFAULT_EVENT_IDS)
    sysmon_ids = [value for value in ids if value in DEFAULT_SYSMON_EVENT_IDS]
    security_ids = [value for value in ids if value in DEFAULT_WINDOWS_SECURITY_EVENT_IDS]
    other_ids = [
        value
        for value in ids
        if value not in DEFAULT_SYSMON_EVENT_IDS
        and value not in DEFAULT_WINDOWS_SECURITY_EVENT_IDS
    ]
    evidence_groups: list[dict[str, Any]] = []
    if sysmon_ids:
        evidence_groups.append(
            {
                "bool": {
                    "filter": [
                        _event_id_filter(sysmon_ids),
                        _provider_filter(SYSMON_PROVIDER),
                    ]
                }
            }
        )
    if security_ids:
        security_event_groups: list[dict[str, Any]] = []
        if 4624 in security_ids:
            security_event_groups.append(
                {
                    "bool": {
                        "filter": [
                            _event_id_filter([4624]),
                            _field_value_filter("data.win.eventdata.logonType", [3, 10]),
                        ]
                    }
                }
            )
        action_ids = [value for value in security_ids if value in {4697, 4698}]
        if action_ids:
            security_event_groups.append(_event_id_filter(action_ids))
        evidence_groups.append(
            {
                "bool": {
                    "filter": [
                        _provider_filter(WINDOWS_SECURITY_PROVIDER),
                        {
                            "bool": {
                                "should": security_event_groups,
                                "minimum_should_match": 1,
                            }
                        },
                    ]
                }
            }
        )
    if other_ids:
        evidence_groups.append(_event_id_filter(other_ids))

    filters: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": start, "lte": end}}},
        {"bool": {"should": evidence_groups, "minimum_should_match": 1}},
    ]

    if agent_mode not in {"all", "any"}:
        raise ValueError("agent_mode must be 'all' or 'any'")

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
            "timestamp",
            "agent.id",
            "agent.name",
            "agent.ip",
            "rule.id",
            "rule.description",
            "rule.level",
            "rule.groups",
            "rule.mitre",
            "data.win.system.eventID",
            "data.win.eventdata.*",
            "data.win.system.computer",
            "data.win.system.channel",
            "data.win.system.eventRecordID",
            "data.win.system.providerName",
        ],
    }


def _to_iso(value: str | datetime) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _validated_page_hits(response: dict[str, Any]) -> list[RawHit]:
    if response.get("timed_out") is True:
        raise ValueError("OpenSearch search timed out; evidence completeness is unknown")

    shards = response.get("_shards")
    if isinstance(shards, dict):
        failed = int(shards.get("failed") or 0)
        if failed:
            raise ValueError(
                f"OpenSearch search reported {failed} failed shard(s); "
                "evidence completeness is unknown"
            )

    hits_wrapper = response.get("hits")
    if not isinstance(hits_wrapper, dict):
        raise ValueError("OpenSearch response is missing the hits object")
    page_hits = hits_wrapper.get("hits")
    if not isinstance(page_hits, list):
        raise ValueError("OpenSearch response hits.hits is not a list")
    if not all(isinstance(hit, dict) for hit in page_hits):
        raise ValueError("OpenSearch response contains a malformed hit")
    return page_hits


def fetch_sysmon_events(
    client: OpenSearchClient,
    index_pattern: str,
    start_dt: str | datetime,
    end_dt: str | datetime,
    agent_id: str | None,
    agent_name: str | None,
    event_ids: Sequence[int] = DEFAULT_EVENT_IDS,
    page_size: int = 1000,
    agent_mode: str = "all",
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

    if page_size <= 0 or max_events <= 0 or max_pages <= 0:
        raise ValueError("page_size, max_events, and max_pages must be positive")

    search_after: list[Any] | None = None
    hits: list[RawHit] = []
    truncated = False
    reason: str | None = None
    pages = 0
    pit_id: str | None = None
    scroll_id: str | None = None
    pagination_mode = "pit"

    try:
        pit_id = client.create_pit(index_pattern, run_id=run_id, case_id=case_id)
    except ValueError as exc:
        if "PIT API not supported" not in str(exc):
            raise
        pagination_mode = "scroll"
        LOGGER.warning("PIT unavailable; using OpenSearch scroll pagination")

    try:
        while True:
            if pages >= max_pages:
                truncated = True
                reason = "max-pages"
                break

            remaining = max_events - len(hits)
            request_size = max(1, min(page_size, remaining + 1))
            page_query = dict(query_body)
            page_query["size"] = request_size

            if pit_id:
                response = client.search(
                    pit_id,
                    page_query,
                    search_after=search_after,
                    run_id=run_id,
                    case_id=case_id,
                )
            elif scroll_id is None:
                page_query["sort"] = ["_doc"]
                response = client.start_scroll(
                    index_pattern,
                    page_query,
                    run_id=run_id,
                    case_id=case_id,
                )
            else:
                response = client.continue_scroll(
                    scroll_id,
                    run_id=run_id,
                    case_id=case_id,
                )
            pages += 1

            page_hits = _validated_page_hits(response)
            response_pit_id = response.get("pit_id")
            if isinstance(response_pit_id, str) and response_pit_id:
                pit_id = response_pit_id
            response_scroll_id = response.get("_scroll_id")
            if isinstance(response_scroll_id, str) and response_scroll_id:
                scroll_id = response_scroll_id

            if not page_hits:
                break

            if len(page_hits) > remaining:
                hits.extend(page_hits[:remaining])
                truncated = True
                reason = "max-events"
                break
            hits.extend(page_hits)

            if len(page_hits) < request_size:
                break

            if pit_id:
                last_sort = page_hits[-1].get("sort")
                if not isinstance(last_sort, list) or not last_sort:
                    raise ValueError(
                        "OpenSearch PIT page is missing sort values; "
                        "evidence completeness is unknown"
                    )
                search_after = last_sort
            elif scroll_id is None:
                raise ValueError(
                    "OpenSearch scroll response is missing _scroll_id; "
                    "evidence completeness is unknown"
                )
    finally:
        if pit_id:
            try:
                client.delete_pit(pit_id, run_id=run_id, case_id=case_id)
            except Exception as exc:
                LOGGER.warning("Failed to delete PIT during cleanup: %s", exc)
        if scroll_id:
            try:
                client.delete_scroll(scroll_id, run_id=run_id, case_id=case_id)
            except Exception as exc:
                LOGGER.warning("Failed to delete scroll during cleanup: %s", exc)

    return FetchResult(
        hits=hits,
        truncated=truncated,
        reason=reason,
        fetched_count=len(hits),
        pages=pages,
        pagination_mode=pagination_mode,
    )


def fetch_data(
    agent_id: str, start: str, end: str, agent_name: str | None = None
) -> dict[str, Any]:
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


def fetch_all_agents(start: str, end: str) -> dict[str, Any]:
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
