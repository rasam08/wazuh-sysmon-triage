from typing import Any

import pytest

from wazuh_sysmon_triage.pipeline.fetch import (
    DEFAULT_EVENT_IDS,
    DEFAULT_SYSMON_EVENT_IDS,
    DEFAULT_WINDOWS_SECURITY_EVENT_IDS,
    SYSMON_PROVIDER,
    WINDOWS_SECURITY_PROVIDER,
    build_sysmon_query,
    fetch_sysmon_events,
)


class FakeFetchClient:
    def __init__(self, responses: list[dict[str, Any]], *, pit_supported: bool = True) -> None:
        self.responses = list(responses)
        self.pit_supported = pit_supported
        self.deleted_pits: list[str] = []
        self.deleted_scrolls: list[str] = []
        self.search_after_values: list[list[Any] | None] = []
        self.scroll_query: dict[str, Any] | None = None
        self.continued_scrolls: list[str] = []

    def create_pit(self, index_pattern: str, **_: Any) -> str:
        if not self.pit_supported:
            raise ValueError("PIT API not supported by this OpenSearch endpoint")
        return "pit-1"

    def search(
        self,
        pit_id: str,
        query_body: dict[str, Any],
        search_after: list[Any] | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        self.search_after_values.append(search_after)
        return self.responses.pop(0)

    def delete_pit(self, pit_id: str, **_: Any) -> None:
        self.deleted_pits.append(pit_id)

    def start_scroll(
        self,
        index_pattern: str,
        query_body: dict[str, Any],
        **_: Any,
    ) -> dict[str, Any]:
        self.scroll_query = query_body
        return self.responses.pop(0)

    def continue_scroll(self, scroll_id: str, **_: Any) -> dict[str, Any]:
        self.continued_scrolls.append(scroll_id)
        return self.responses.pop(0)

    def delete_scroll(self, scroll_id: str, **_: Any) -> None:
        self.deleted_scrolls.append(scroll_id)


def _response(*hits: dict[str, Any], scroll_id: str | None = None) -> dict[str, Any]:
    response: dict[str, Any] = {
        "timed_out": False,
        "_shards": {"failed": 0},
        "hits": {"hits": list(hits)},
    }
    if scroll_id:
        response["_scroll_id"] = scroll_id
    return response


def _hit(number: int) -> dict[str, Any]:
    return {
        "_index": "wazuh-alerts-test",
        "_id": f"doc-{number}",
        "_source": {"@timestamp": f"2024-01-01T00:00:{number:02d}Z"},
        "sort": [f"2024-01-01T00:00:{number:02d}Z", number],
    }


def _fetch(client: FakeFetchClient, **overrides: Any) -> Any:
    arguments = {
        "client": client,
        "index_pattern": "wazuh-alerts-*",
        "start_dt": "2024-01-01T00:00:00Z",
        "end_dt": "2024-01-01T01:00:00Z",
        "agent_id": "999",
        "agent_name": "agent-test",
        "page_size": 2,
        "max_events": 10,
        "max_pages": 10,
    }
    arguments.update(overrides)
    return fetch_sysmon_events(**arguments)


def _extract_filters(query: dict) -> list:
    return query["query"]["bool"]["filter"]


def _find_evidence_group(filters: list, provider: str) -> dict:
    for item in filters:
        for group in item.get("bool", {}).get("should", []):
            nested = group.get("bool", {}).get("filter", [])
            provider_terms = [
                clause
                for clause in nested
                if "providerName" in str(clause.get("bool", {}).get("should", []))
            ]
            if provider_terms and provider in str(provider_terms):
                return group
    raise AssertionError(f"Evidence group not found for {provider}")


def _group_eid_should(group: dict) -> list:
    pending = list(group["bool"]["filter"])
    while pending:
        clause = pending.pop()
        should = clause.get("bool", {}).get("should", [])
        if any("data.win.system.eventID" in item.get("terms", {}) for item in should):
            return should
        pending.extend(should)
        pending.extend(clause.get("bool", {}).get("filter", []))
    raise AssertionError("EID filter not found in provider group")


def _find_agent_filter(filters: list) -> dict:
    for item in filters:
        if "term" in item and ("agent.id" in item["term"] or "agent.name" in item["term"]):
            return item
        if "bool" in item and ("should" in item["bool"] or "filter" in item["bool"]):
            nested = item["bool"].get("should") or item["bool"].get("filter") or []
            if any(
                "agent.id" in clause.get("term", {}) or "agent.name" in clause.get("term", {})
                for clause in nested
            ):
                return item
    raise AssertionError("Agent filter not found")


def test_query_includes_numeric_and_string_eids() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_id="999",
    )
    filters = _extract_filters(query)
    sysmon_should = _group_eid_should(_find_evidence_group(filters, SYSMON_PROVIDER))
    security_group = _find_evidence_group(filters, WINDOWS_SECURITY_PROVIDER)

    assert set(DEFAULT_EVENT_IDS) == {
        *DEFAULT_SYSMON_EVENT_IDS,
        *DEFAULT_WINDOWS_SECURITY_EVENT_IDS,
    }
    assert {"terms": {"data.win.system.eventID": list(DEFAULT_SYSMON_EVENT_IDS)}} in sysmon_should
    assert {
        "terms": {
            "data.win.system.eventID": [str(value) for value in DEFAULT_SYSMON_EVENT_IDS]
        }
    } in sysmon_should
    assert "data.win.eventdata.logonType" in str(security_group)
    assert "[4624]" in str(security_group)
    assert "[4697, 4698]" in str(security_group)
    assert all(str(value) in str(query) for value in DEFAULT_WINDOWS_SECURITY_EVENT_IDS)


def test_query_supports_custom_event_ids() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_id="999",
        event_ids=[1, 3, 11],
    )
    filters = _extract_filters(query)
    should = _group_eid_should(_find_evidence_group(filters, SYSMON_PROVIDER))

    assert {"terms": {"data.win.system.eventID": [1, 3, 11]}} in should
    assert {"terms": {"data.win.system.eventID": ["1", "3", "11"]}} in should
    assert any(clause.get("query_string", {}).get("query") == "1 OR 3 OR 11" for clause in should)


def test_agent_filters_id_only() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_id="999",
    )
    filters = _extract_filters(query)
    agent_filter = _find_agent_filter(filters)
    assert agent_filter == {"term": {"agent.id": "999"}}


def test_agent_filters_name_only() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_name="agent-test",
    )
    filters = _extract_filters(query)
    agent_filter = _find_agent_filter(filters)
    assert agent_filter == {"term": {"agent.name": "agent-test"}}


def test_agent_filters_any_mode() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_id="999",
        agent_name="agent-test",
        agent_mode="any",
    )
    filters = _extract_filters(query)
    agent_filter = _find_agent_filter(filters)
    assert agent_filter["bool"]["minimum_should_match"] == 1
    assert {"term": {"agent.id": "999"}} in agent_filter["bool"]["should"]
    assert {"term": {"agent.name": "agent-test"}} in agent_filter["bool"]["should"]


def test_agent_filters_all_mode() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_id="999",
        agent_name="agent-test",
        agent_mode="all",
    )
    filters = _extract_filters(query)
    agent_filter = _find_agent_filter(filters)
    assert {"term": {"agent.id": "999"}} in agent_filter["bool"]["filter"]
    assert {"term": {"agent.name": "agent-test"}} in agent_filter["bool"]["filter"]


def test_agent_filters_default_to_all_mode() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_id="999",
        agent_name="agent-test",
    )

    agent_filter = _find_agent_filter(_extract_filters(query))

    assert {"term": {"agent.id": "999"}} in agent_filter["bool"]["filter"]
    assert {"term": {"agent.name": "agent-test"}} in agent_filter["bool"]["filter"]


def test_invalid_agent_mode_fails_closed() -> None:
    with pytest.raises(ValueError, match="agent_mode"):
        build_sysmon_query(
            start="2024-01-01T00:00:00Z",
            end="2024-01-01T01:00:00Z",
            agent_id="999",
            agent_mode="sometimes",
        )


def test_fetch_exact_event_cap_checks_for_an_extra_hit() -> None:
    client = FakeFetchClient([_response(_hit(1), _hit(2)), _response()])

    result = _fetch(client, page_size=2, max_events=2)

    assert result.fetched_count == 2
    assert result.truncated is False
    assert result.reason is None
    assert result.pages == 2
    assert result.pagination_mode == "pit"
    assert client.deleted_pits == ["pit-1"]


def test_fetch_marks_a_confirmed_event_overflow_as_truncated() -> None:
    client = FakeFetchClient([_response(_hit(1), _hit(2), _hit(3))])

    result = _fetch(client, page_size=10, max_events=2)

    assert [hit["_id"] for hit in result.hits] == ["doc-1", "doc-2"]
    assert result.truncated is True
    assert result.reason == "max-events"


def test_fetch_rejects_timed_out_or_failed_shard_responses() -> None:
    timed_out = FakeFetchClient(
        [{"timed_out": True, "_shards": {"failed": 0}, "hits": {"hits": []}}]
    )
    failed_shard = FakeFetchClient(
        [{"timed_out": False, "_shards": {"failed": 1}, "hits": {"hits": []}}]
    )

    with pytest.raises(ValueError, match="timed out"):
        _fetch(timed_out)
    with pytest.raises(ValueError, match="failed shard"):
        _fetch(failed_shard)

    assert timed_out.deleted_pits == ["pit-1"]
    assert failed_shard.deleted_pits == ["pit-1"]


def test_fetch_rejects_pit_pages_without_sort_values() -> None:
    client = FakeFetchClient([_response({"_id": "doc-1", "_source": {}})])

    with pytest.raises(ValueError, match="missing sort values"):
        _fetch(client, page_size=1)


def test_fetch_falls_back_to_scroll_when_pit_is_unavailable() -> None:
    client = FakeFetchClient(
        [_response(_hit(1), scroll_id="scroll-1"), _response(scroll_id="scroll-2")],
        pit_supported=False,
    )

    result = _fetch(client, page_size=1)

    assert result.fetched_count == 1
    assert result.truncated is False
    assert result.pagination_mode == "scroll"
    assert client.scroll_query is not None
    assert client.scroll_query["sort"] == ["_doc"]
    assert client.continued_scrolls == ["scroll-1"]
    assert client.deleted_scrolls == ["scroll-2"]
