from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from wazuh_sysmon_triage.pipeline.investigate import (
    anchor_from_hit,
    build_alert_lookup_query,
    fetch_investigation_anchor,
)


def _anchor_hit(document_id: str = "alert-123") -> dict[str, Any]:
    return {
        "_index": "wazuh-alerts-4.x-2024.01.01",
        "_id": document_id,
        "_source": {
            "@timestamp": "2024-01-01T00:00:02Z",
            "timestamp": "2024-01-01T00:00:01Z",
            "agent": {"id": "001", "name": "HOST-A", "ip": "192.0.2.5"},
            "rule": {
                "id": "92000",
                "level": 12,
                "description": "Triggering behavior",
                "groups": ["windows", "sysmon"],
                "mitre": {"id": ["T1059.001"]},
            },
            "data": {
                "win": {
                    "system": {"eventID": "1", "computer": "HOST-A"},
                    "eventdata": {"UtcTime": "2024-01-01T00:00:00Z"},
                }
            },
        },
    }


class FakeAnchorClient:
    def __init__(self, hits: list[dict[str, Any]]) -> None:
        self.hits = hits
        self.query: dict[str, Any] | None = None

    def search_index(self, _index: str, query: dict[str, Any], **_: Any) -> dict[str, Any]:
        self.query = query
        return {
            "timed_out": False,
            "_shards": {"failed": 0},
            "hits": {"hits": self.hits},
        }


def test_anchor_prefers_occurrence_time_and_preserves_provenance() -> None:
    anchor = anchor_from_hit(_anchor_hit())

    assert anchor.timestamp == datetime(2024, 1, 1, tzinfo=UTC)
    assert anchor.agent_id == "001"
    assert anchor.computer == "HOST-A"
    assert anchor.rule_id == "92000"
    assert anchor.source_ref.document_id == "alert-123"
    assert len(anchor.source_ref.raw_digest or "") == 64
    assert anchor.context_window(before=timedelta(minutes=5), after=timedelta(minutes=10)) == (
        datetime(2023, 12, 31, 23, 55, tzinfo=UTC),
        datetime(2024, 1, 1, 0, 10, tzinfo=UTC),
    )


def test_alert_lookup_is_exact_and_fails_on_ambiguous_indices() -> None:
    query = build_alert_lookup_query("alert-123")
    assert query["query"] == {"ids": {"values": ["alert-123"]}}

    client = FakeAnchorClient([_anchor_hit(), _anchor_hit()])
    with pytest.raises(ValueError, match="multiple indices"):
        fetch_investigation_anchor(
            client,  # type: ignore[arg-type]
            index_pattern="wazuh-alerts-*",
            document_id="alert-123",
        )


def test_alert_lookup_fails_when_agent_identity_is_missing() -> None:
    hit = _anchor_hit()
    hit["_source"].pop("agent")
    client = FakeAnchorClient([hit])

    with pytest.raises(ValueError, match="does not identify an agent"):
        fetch_investigation_anchor(
            client,  # type: ignore[arg-type]
            index_pattern="wazuh-alerts-*",
            document_id="alert-123",
        )
