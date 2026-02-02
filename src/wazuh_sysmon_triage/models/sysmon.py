from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


def _to_optional_utc(value: Any) -> datetime | None:
    if value is None:
        return None
    return _to_utc(value)


def _to_int(value: Any) -> int:
    if isinstance(value, bool):
        raise TypeError("Boolean is not a valid integer")
    return int(value)


def _to_optional_int(value: Any) -> int | None:
    if value is None:
        return None
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


class BaseEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    event_id: int = Field(..., description="Sysmon event ID")
    timestamp: datetime
    agent_id: str | None = None
    agent_name: str | None = None
    agent_ip: str | None = None
    rule_id: str | None = None
    rule_description: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    computer: str | None = None
    channel: str | None = None
    record_id: str | None = None
    kind: str = "sysmon"
    event_type: str

    _coerce_event_id = field_validator("event_id", mode="before")(_to_int)
    _coerce_timestamp = field_validator("timestamp", mode="before")(_to_utc)
    _coerce_agent_id = field_validator("agent_id", mode="before")(_to_optional_str)
    _coerce_agent_name = field_validator("agent_name", mode="before")(_to_optional_str)
    _coerce_agent_ip = field_validator("agent_ip", mode="before")(_to_optional_str)
    _coerce_rule_id = field_validator("rule_id", mode="before")(_to_optional_str)
    _coerce_rule_description = field_validator("rule_description", mode="before")(_to_optional_str)
    _coerce_computer = field_validator("computer", mode="before")(_to_optional_str)
    _coerce_channel = field_validator("channel", mode="before")(_to_optional_str)
    _coerce_record_id = field_validator("record_id", mode="before")(_to_optional_str)

    @field_validator("mitre_techniques", mode="before")
    @classmethod
    def _coerce_mitre_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]


class ProcessCreateEvent(BaseEvent):
    event_id: int = Field(1, description="Sysmon EID 1")
    event_type: str = "process_create"

    process_guid: str
    process_id: int
    image: str
    command_line: str | None = None
    current_directory: str | None = None
    user: str | None = None
    parent_process_guid: str | None = None
    parent_process_id: int | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    hashes: str | None = None
    integrity_level: str | None = None

    _coerce_process_guid = field_validator("process_guid", mode="before")(_to_str)
    _coerce_process_id = field_validator("process_id", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_command_line = field_validator("command_line", mode="before")(_to_optional_str)
    _coerce_current_directory = field_validator("current_directory", mode="before")(
        _to_optional_str
    )
    _coerce_user = field_validator("user", mode="before")(_to_optional_str)
    _coerce_parent_guid = field_validator("parent_process_guid", mode="before")(_to_optional_str)
    _coerce_parent_pid = field_validator("parent_process_id", mode="before")(_to_optional_int)
    _coerce_parent_image = field_validator("parent_image", mode="before")(_to_optional_str)
    _coerce_parent_command_line = field_validator("parent_command_line", mode="before")(
        _to_optional_str
    )
    _coerce_hashes = field_validator("hashes", mode="before")(_to_optional_str)
    _coerce_integrity_level = field_validator("integrity_level", mode="before")(_to_optional_str)


class FileCreateEvent(BaseEvent):
    event_id: int = Field(11, description="Sysmon EID 11")
    event_type: str = "file_create"

    process_guid: str
    process_id: int
    image: str
    target_filename: str
    creation_utc_time: datetime | None = None
    user: str | None = None

    _coerce_process_guid = field_validator("process_guid", mode="before")(_to_str)
    _coerce_process_id = field_validator("process_id", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_target_filename = field_validator("target_filename", mode="before")(_to_str)
    _coerce_creation_utc = field_validator("creation_utc_time", mode="before")(_to_optional_utc)
    _coerce_user = field_validator("user", mode="before")(_to_optional_str)


class NetworkConnectEvent(BaseEvent):
    event_id: int = Field(3, description="Sysmon EID 3")
    event_type: str = "network_connect"

    process_guid: str
    process_id: int
    image: str
    destination_ip: str
    destination_port: int
    protocol: str | None = None

    _coerce_process_guid = field_validator("process_guid", mode="before")(_to_str)
    _coerce_process_id = field_validator("process_id", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_destination_ip = field_validator("destination_ip", mode="before")(_to_str)
    _coerce_destination_port = field_validator("destination_port", mode="before")(_to_int)
    _coerce_protocol = field_validator("protocol", mode="before")(_to_optional_str)


SysmonEvent = ProcessCreateEvent | FileCreateEvent | NetworkConnectEvent
