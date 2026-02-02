from wazuh_sysmon_triage.pipeline.fetch import build_sysmon_query


def _extract_filters(query: dict) -> list:
    return query["query"]["bool"]["filter"]


def _find_eid_filter(filters: list) -> dict:
    for item in filters:
        if "bool" in item and "should" in item["bool"]:
            should = item["bool"]["should"]
            if any("data.win.system.eventID" in clause.get("terms", {}) for clause in should):
                return item
    raise AssertionError("EID filter not found")


def _find_agent_filter(filters: list) -> dict:
    for item in filters:
        if "term" in item and ("agent.id" in item["term"] or "agent.name" in item["term"]):
            return item
        if "bool" in item and ("should" in item["bool"] or "filter" in item["bool"]):
            nested = item["bool"].get("should") or item["bool"].get("filter") or []
            if any("agent.id" in clause.get("term", {}) or "agent.name" in clause.get("term", {}) for clause in nested):
                return item
    raise AssertionError("Agent filter not found")


def test_query_includes_numeric_and_string_eids() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_id="010",
    )
    filters = _extract_filters(query)
    eid_filter = _find_eid_filter(filters)
    should = eid_filter["bool"]["should"]

    assert {"terms": {"data.win.system.eventID": [1, 11]}} in should
    assert {"terms": {"data.win.system.eventID": ["1", "11"]}} in should
    assert any("query_string" in clause for clause in should)


def test_agent_filters_id_only() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_id="010",
    )
    filters = _extract_filters(query)
    agent_filter = _find_agent_filter(filters)
    assert agent_filter == {"term": {"agent.id": "010"}}


def test_agent_filters_name_only() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_name="anon",
    )
    filters = _extract_filters(query)
    agent_filter = _find_agent_filter(filters)
    assert agent_filter == {"term": {"agent.name": "anon"}}


def test_agent_filters_any_mode() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_id="010",
        agent_name="anon",
        agent_mode="any",
    )
    filters = _extract_filters(query)
    agent_filter = _find_agent_filter(filters)
    assert agent_filter["bool"]["minimum_should_match"] == 1
    assert {"term": {"agent.id": "010"}} in agent_filter["bool"]["should"]
    assert {"term": {"agent.name": "anon"}} in agent_filter["bool"]["should"]


def test_agent_filters_all_mode() -> None:
    query = build_sysmon_query(
        start="2024-01-01T00:00:00Z",
        end="2024-01-01T01:00:00Z",
        agent_id="010",
        agent_name="anon",
        agent_mode="all",
    )
    filters = _extract_filters(query)
    agent_filter = _find_agent_filter(filters)
    assert {"term": {"agent.id": "010"}} in agent_filter["bool"]["filter"]
    assert {"term": {"agent.name": "anon"}} in agent_filter["bool"]["filter"]
