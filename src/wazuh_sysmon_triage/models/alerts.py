from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from wazuh_sysmon_triage.models.evidence import SourceRef
from wazuh_sysmon_triage.models.findings import EvidenceStrength

FindingKind = Literal[
    "observed_pattern",
    "correlated_pattern",
    "aggregate_pattern",
    "hypothesis",
]


def _to_utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    raise TypeError("Unsupported datetime value")


def _to_int(value: Any) -> int:
    if isinstance(value, bool):
        raise TypeError("Boolean is not a valid integer")
    return int(value)


def _to_str(value: Any) -> str:
    if value is None:
        raise TypeError("None is not a valid string")
    return str(value)


def _to_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


class Alert(BaseModel):
    """A transparent local rule match, not a verdict about maliciousness."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str | None = None
    utc_time: datetime
    rule_id: str | None = None
    rule_name: str | None = None
    primary_event_id: int | None = None
    alert_type: str
    category: Literal[
        "process_behavior",
        "network_behavior",
        "persistence_behavior",
        "credential_access_behavior",
        "remote_activity_behavior",
        "policy_pattern",
        "developer_tooling",
        "aggregate_behavior",
        "unknown",
    ] = "unknown"
    finding_kind: FindingKind = "observed_pattern"
    evidence_strength: EvidenceStrength = EvidenceStrength.DETERMINISTIC
    reason: str
    host_key: str
    image: str
    command_line: str | None = None
    parent_image: str | None = None
    source_host_key: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    process_guid: str
    tags: list[str] = Field(default_factory=list)
    evidence_refs: list[SourceRef] = Field(default_factory=list)
    suppressed_related_rules: list[str] = Field(default_factory=list)
    suppressed_related_count: int = 0

    _coerce_alert_id = field_validator("alert_id", mode="before")(_to_optional_str)
    _coerce_utc_time = field_validator("utc_time", mode="before")(_to_utc)
    _coerce_rule_id = field_validator("rule_id", mode="before")(_to_optional_str)
    _coerce_rule_name = field_validator("rule_name", mode="before")(_to_optional_str)
    _coerce_alert_type = field_validator("alert_type", mode="before")(_to_str)
    _coerce_reason = field_validator("reason", mode="before")(_to_str)
    _coerce_host_key = field_validator("host_key", mode="before")(_to_str)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_command_line = field_validator("command_line", mode="before")(_to_optional_str)
    _coerce_parent_image = field_validator("parent_image", mode="before")(_to_optional_str)
    _coerce_source_host_key = field_validator("source_host_key", mode="before")(
        _to_optional_str
    )
    _coerce_source_ip = field_validator("source_ip", mode="before")(_to_optional_str)
    _coerce_destination_ip = field_validator("destination_ip", mode="before")(_to_optional_str)
    _coerce_process_guid = field_validator("process_guid", mode="before")(_to_str)

    @field_validator("evidence_strength", mode="before")
    @classmethod
    def _coerce_evidence_strength(cls, value: Any) -> EvidenceStrength:
        if isinstance(value, EvidenceStrength):
            return value
        return EvidenceStrength(str(value).lower())

    @field_validator("destination_port", mode="before")
    @classmethod
    def _coerce_destination_port(cls, value: Any) -> int | None:
        if value is None:
            return None
        return _to_int(value)

    @field_validator("source_port", mode="before")
    @classmethod
    def _coerce_source_port(cls, value: Any) -> int | None:
        if value is None:
            return None
        return _to_int(value)

    @field_validator("primary_event_id", mode="before")
    @classmethod
    def _coerce_primary_event_id(cls, value: Any) -> int | None:
        if value is None:
            return None
        return _to_int(value)

    @field_validator("suppressed_related_count", mode="before")
    @classmethod
    def _coerce_suppressed_related_count(cls, value: Any) -> int:
        return _to_int(value)

    @field_validator("tags", "suppressed_related_rules", mode="before")
    @classmethod
    def _coerce_string_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]
