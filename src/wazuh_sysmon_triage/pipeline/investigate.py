from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from wazuh_sysmon_triage.clients.opensearch_client import OpenSearchClient
from wazuh_sysmon_triage.models.evidence import SourceRef
from wazuh_sysmon_triage.models.raw import RawHit

from .fetch import _validated_page_hits
from .normalize import _as_mapping, _parse_dt, _source_ref, _to_int, get_ci


@dataclass(frozen=True)
class InvestigationAnchor:
    document_id: str
    index: str | None
    timestamp: datetime
    agent_id: str | None
    agent_name: str | None
    agent_ip: str | None
    computer: str | None
    event_id: int | None
    rule_id: str | None
    rule_level: int | None
    rule_description: str | None
    rule_groups: list[str]
    mitre: Any
    source_ref: SourceRef

    def context_window(self, *, before: timedelta, after: timedelta) -> tuple[datetime, datetime]:
        return (self.timestamp - before, self.timestamp + after)

    def to_payload(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "index": self.index,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "agent": {
                "id": self.agent_id,
                "name": self.agent_name,
                "ip": self.agent_ip,
            },
            "computer": self.computer,
            "event_id": self.event_id,
            "rule": {
                "id": self.rule_id,
                "level": self.rule_level,
                "description": self.rule_description,
                "groups": self.rule_groups,
                "mitre": self.mitre,
            },
            "source_ref": self.source_ref.model_dump(mode="json"),
        }


def build_alert_lookup_query(document_id: str) -> dict[str, Any]:
    value = document_id.strip()
    if not value:
        raise ValueError("Wazuh alert document ID cannot be empty")
    return {
        "size": 2,
        "query": {"ids": {"values": [value]}},
        "_source": [
            "@timestamp",
            "timestamp",
            "agent.*",
            "rule.*",
            "data.win.system.*",
            "data.win.eventdata.*",
        ],
    }


def anchor_from_hit(hit: Mapping[str, Any]) -> InvestigationAnchor:
    source = _as_mapping(hit.get("_source"))
    if not source:
        raise ValueError("Wazuh alert lookup returned a hit without _source")
    document_id = hit.get("_id")
    if document_id is None:
        raise ValueError("Wazuh alert lookup returned a hit without _id")

    agent = _as_mapping(source.get("agent"))
    rule = _as_mapping(source.get("rule"))
    win = _as_mapping(_as_mapping(source.get("data")).get("win"))
    system = _as_mapping(win.get("system"))
    eventdata = _as_mapping(win.get("eventdata"))
    timestamp = (
        _parse_dt(get_ci(eventdata, "utcTime"))
        or _parse_dt(source.get("timestamp"))
        or _parse_dt(source.get("@timestamp"))
    )
    if timestamp is None:
        raise ValueError("Wazuh alert has no valid occurrence, Wazuh, or index timestamp")

    groups_raw = get_ci(rule, "groups")
    if groups_raw is None:
        groups: list[str] = []
    elif isinstance(groups_raw, str):
        groups = [groups_raw]
    else:
        groups = [str(item) for item in groups_raw]

    index = hit.get("_index")
    return InvestigationAnchor(
        document_id=str(document_id),
        index=str(index) if index is not None else None,
        timestamp=timestamp,
        agent_id=str(get_ci(agent, "id")) if get_ci(agent, "id") is not None else None,
        agent_name=(str(get_ci(agent, "name")) if get_ci(agent, "name") is not None else None),
        agent_ip=str(get_ci(agent, "ip")) if get_ci(agent, "ip") is not None else None,
        computer=(
            str(get_ci(system, "computer")) if get_ci(system, "computer") is not None else None
        ),
        event_id=_to_int(get_ci(system, "eventID")),
        rule_id=str(get_ci(rule, "id")) if get_ci(rule, "id") is not None else None,
        rule_level=_to_int(get_ci(rule, "level")),
        rule_description=(
            str(get_ci(rule, "description")) if get_ci(rule, "description") is not None else None
        ),
        rule_groups=groups,
        mitre=get_ci(rule, "mitre"),
        source_ref=_source_ref(hit, source, system, wrapped=True),
    )


def fetch_investigation_anchor(
    client: OpenSearchClient,
    *,
    index_pattern: str,
    document_id: str,
    run_id: str | None = None,
    case_id: str | None = None,
) -> InvestigationAnchor:
    response = client.search_index(
        index_pattern,
        build_alert_lookup_query(document_id),
        run_id=run_id,
        case_id=case_id,
    )
    hits: list[RawHit] = _validated_page_hits(response)
    if not hits:
        raise ValueError(f"Wazuh alert document '{document_id}' was not found")
    if len(hits) > 1:
        raise ValueError(
            f"Wazuh alert document '{document_id}' exists in multiple indices; "
            "narrow --index-pattern so the anchor is unambiguous"
        )
    anchor = anchor_from_hit(hits[0])
    if not anchor.agent_id and not anchor.agent_name:
        raise ValueError("Wazuh alert does not identify an agent for contextual collection")
    return anchor
