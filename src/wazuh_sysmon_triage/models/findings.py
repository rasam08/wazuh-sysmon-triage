from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _to_utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
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


def _to_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


class ProcessNode(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: str = "process_node"
    guid: str
    pid: int
    image: str
    cmdline: Optional[str] = None
    user: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    synthetic: bool = False
    tags: List[str] = Field(default_factory=list)

    _coerce_guid = field_validator("guid", mode="before")(_to_str)
    _coerce_pid = field_validator("pid", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_cmdline = field_validator("cmdline", mode="before")(_to_optional_str)
    _coerce_user = field_validator("user", mode="before")(_to_optional_str)
    _coerce_first_seen = field_validator("first_seen", mode="before")(_to_utc)
    _coerce_last_seen = field_validator("last_seen", mode="before")(_to_utc)


class ProcessEdge(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: str = "process_edge"
    parent_guid: str
    child_guid: str
    reason: str

    _coerce_parent_guid = field_validator("parent_guid", mode="before")(_to_str)
    _coerce_child_guid = field_validator("child_guid", mode="before")(_to_str)
    _coerce_reason = field_validator("reason", mode="before")(_to_str)


class Artifact(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: str = "artifact"
    class Confidence(str, Enum):
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"

    path: str
    created_at: datetime
    creating_process_guid: Optional[str] = None
    creating_image: Optional[str] = None
    confidence: Confidence
    reason: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    _coerce_path = field_validator("path", mode="before")(_to_str)
    _coerce_created_at = field_validator("created_at", mode="before")(_to_utc)
    _coerce_creating_guid = field_validator("creating_process_guid", mode="before")(_to_optional_str)
    _coerce_creating_image = field_validator("creating_image", mode="before")(_to_optional_str)
    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, value: Any) -> "Artifact.Confidence":
        if isinstance(value, Artifact.Confidence):
            return value
        text = str(value).upper()
        if text in {"HIGH", "MEDIUM", "LOW"}:
            return Artifact.Confidence(text)
        raise ValueError("confidence must be HIGH, MEDIUM, or LOW")

    @field_validator("tags", mode="before")
    @classmethod
    def _coerce_tags(cls, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]


class IncidentSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: str = "incident_summary"
    time_range: Tuple[datetime, datetime]
    agent: Optional[str] = None
    key_processes: List[ProcessNode] = Field(default_factory=list)
    artifacts: List[Artifact] = Field(default_factory=list)
    mitre: List[str] = Field(default_factory=list)
    narrative_bullets: List[str] = Field(default_factory=list)

    @field_validator("time_range", mode="before")
    @classmethod
    def _coerce_time_range(cls, value: Any) -> Tuple[datetime, datetime]:
        if isinstance(value, (list, tuple)) and len(value) == 2:
            start = _to_utc(value[0])
            end = _to_utc(value[1])
            return (start, end)
        raise TypeError("time_range must be a 2-item list or tuple")

    _coerce_agent = field_validator("agent", mode="before")(_to_optional_str)

    @field_validator("mitre", mode="before")
    @classmethod
    def _coerce_mitre_list(cls, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]

    @field_validator("narrative_bullets", mode="before")
    @classmethod
    def _coerce_narrative_list(cls, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]