from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from wazuh_sysmon_triage.models.evidence import SourceRef


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


def _to_float(value: Any) -> float:
    if isinstance(value, bool):
        raise TypeError("Boolean is not a valid float")
    return float(value)


def _to_str(value: Any) -> str:
    if value is None:
        raise TypeError("None is not a valid string")
    return str(value)


def _to_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


class EvidenceStrength(StrEnum):
    DETERMINISTIC = "deterministic"
    STRONG = "strong"
    CIRCUMSTANTIAL = "circumstantial"
    UNRESOLVED = "unresolved"


class ProcessNode(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: str = "process_node"
    host_key: str
    guid: str
    pid: int
    image: str
    cmdline: str | None = None
    user: str | None = None
    hashes: str | None = None
    integrity_level: str | None = None
    created_at: datetime | None = None
    terminated_at: datetime | None = None
    first_seen: datetime
    last_seen: datetime
    synthetic: bool = False
    tags: list[str] = Field(default_factory=list)
    source_refs: list[SourceRef] = Field(default_factory=list)

    _coerce_host_key = field_validator("host_key", mode="before")(_to_str)
    _coerce_guid = field_validator("guid", mode="before")(_to_str)
    _coerce_pid = field_validator("pid", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_cmdline = field_validator("cmdline", mode="before")(_to_optional_str)
    _coerce_user = field_validator("user", mode="before")(_to_optional_str)
    _coerce_hashes = field_validator("hashes", mode="before")(_to_optional_str)
    _coerce_integrity_level = field_validator("integrity_level", mode="before")(_to_optional_str)
    _coerce_created_at = field_validator("created_at", mode="before")(
        lambda value: None if value is None else _to_utc(value)
    )
    _coerce_terminated_at = field_validator("terminated_at", mode="before")(
        lambda value: None if value is None else _to_utc(value)
    )
    _coerce_first_seen = field_validator("first_seen", mode="before")(_to_utc)
    _coerce_last_seen = field_validator("last_seen", mode="before")(_to_utc)


class ProcessEdge(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: str = "process_edge"
    host_key: str
    parent_guid: str
    child_guid: str
    relationship_strength: EvidenceStrength
    reason: str
    evidence_refs: list[SourceRef] = Field(default_factory=list)

    _coerce_host_key = field_validator("host_key", mode="before")(_to_str)
    _coerce_parent_guid = field_validator("parent_guid", mode="before")(_to_str)
    _coerce_child_guid = field_validator("child_guid", mode="before")(_to_str)
    _coerce_reason = field_validator("reason", mode="before")(_to_str)


class Artifact(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: str = "artifact"

    host_key: str
    path: str
    created_at: datetime
    creating_process_guid: str | None = None
    creating_image: str | None = None
    relationship_strength: EvidenceStrength
    reason: str | None = None
    tags: list[str] = Field(default_factory=list)
    evidence_refs: list[SourceRef] = Field(default_factory=list)

    _coerce_host_key = field_validator("host_key", mode="before")(_to_str)
    _coerce_path = field_validator("path", mode="before")(_to_str)
    _coerce_created_at = field_validator("created_at", mode="before")(_to_utc)
    _coerce_creating_guid = field_validator("creating_process_guid", mode="before")(
        _to_optional_str
    )
    _coerce_creating_image = field_validator("creating_image", mode="before")(_to_optional_str)

    @field_validator("relationship_strength", mode="before")
    @classmethod
    def _coerce_relationship_strength(cls, value: Any) -> EvidenceStrength:
        if isinstance(value, EvidenceStrength):
            return value
        return EvidenceStrength(str(value).lower())

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_tags(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]


class IncidentSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: str = "incident_summary"
    time_range: tuple[datetime, datetime]
    agent: str | None = None
    agent_id: str | None = None
    host_keys: list[str] = Field(default_factory=list)
    key_processes: list[ProcessNode] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    narrative_bullets: list[str] = Field(default_factory=list)

    @field_validator("time_range", mode="before")
    @classmethod
    def _coerce_time_range(cls, value: Any) -> tuple[datetime, datetime]:
        if isinstance(value, (list, tuple)) and len(value) == 2:
            start = _to_utc(value[0])
            end = _to_utc(value[1])
            return (start, end)
        raise TypeError("time_range must be a 2-item list or tuple")

    _coerce_agent = field_validator("agent", mode="before")(_to_optional_str)
    _coerce_agent_id = field_validator("agent_id", mode="before")(_to_optional_str)

    @field_validator("mitre", mode="before")
    @classmethod
    def _coerce_mitre_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]

    @field_validator("narrative_bullets", mode="before")
    @classmethod
    def _coerce_narrative_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]


class RemoteActivityLead(BaseModel):
    """A bounded evidence relationship, not a maliciousness or lateral-movement verdict."""

    model_config = ConfigDict(extra="forbid")

    kind: str = "remote_activity_lead"
    target_host_key: str
    source_host_key: str | None = None
    source_host_resolution: Literal[
        "exact_agent_ip",
        "exact_host_name",
        "ambiguous",
        "unresolved",
    ]
    source_ip: str | None = None
    source_port: int | None = None
    workstation_name: str | None = None
    account: str
    logon_type: int
    logon_id: str
    logon_at: datetime
    action_at: datetime
    action_event_id: int
    action_type: Literal["service_install", "scheduled_task_created"]
    action_resource: str
    action_details: str | None = None
    evidence_strength: EvidenceStrength
    reason: str
    evidence_refs: list[SourceRef] = Field(default_factory=list)

    _coerce_target_host_key = field_validator("target_host_key", mode="before")(_to_str)
    _coerce_source_host_key = field_validator("source_host_key", mode="before")(
        _to_optional_str
    )
    _coerce_source_ip = field_validator("source_ip", mode="before")(_to_optional_str)
    _coerce_source_port = field_validator("source_port", mode="before")(
        lambda value: None if value is None else _to_int(value)
    )
    _coerce_workstation_name = field_validator("workstation_name", mode="before")(
        _to_optional_str
    )
    _coerce_account = field_validator("account", mode="before")(_to_str)
    _coerce_logon_type = field_validator("logon_type", mode="before")(_to_int)
    _coerce_logon_id = field_validator("logon_id", mode="before")(_to_str)
    _coerce_logon_at = field_validator("logon_at", mode="before")(_to_utc)
    _coerce_action_at = field_validator("action_at", mode="before")(_to_utc)
    _coerce_action_event_id = field_validator("action_event_id", mode="before")(_to_int)
    _coerce_action_resource = field_validator("action_resource", mode="before")(_to_str)
    _coerce_action_details = field_validator("action_details", mode="before")(_to_optional_str)
    _coerce_reason = field_validator("reason", mode="before")(_to_str)

    @field_validator("evidence_strength", mode="before")
    @classmethod
    def _coerce_evidence_strength(cls, value: Any) -> EvidenceStrength:
        if isinstance(value, EvidenceStrength):
            return value
        return EvidenceStrength(str(value).lower())
