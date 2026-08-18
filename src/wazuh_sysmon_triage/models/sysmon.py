from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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

    event_id: int = Field(..., description="Source Windows event ID")
    timestamp: datetime
    wazuh_timestamp: datetime | None = None
    indexed_at: datetime | None = None
    agent_id: str | None = None
    agent_name: str | None = None
    agent_ip: str | None = None
    rule_id: str | None = None
    rule_level: int | None = None
    rule_description: str | None = None
    rule_groups: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    computer: str | None = None
    channel: str | None = None
    record_id: str | None = None
    provider: str | None = None
    host_key: str | None = None
    source_ref: SourceRef = Field(default_factory=lambda: SourceRef(source_type="constructed"))
    parse_warnings: list[str] = Field(default_factory=list)
    kind: str = "sysmon"
    event_type: str

    _coerce_event_id = field_validator("event_id", mode="before")(_to_int)
    _coerce_timestamp = field_validator("timestamp", mode="before")(_to_utc)
    _coerce_wazuh_timestamp = field_validator("wazuh_timestamp", mode="before")(_to_optional_utc)
    _coerce_indexed_at = field_validator("indexed_at", mode="before")(_to_optional_utc)
    _coerce_agent_id = field_validator("agent_id", mode="before")(_to_optional_str)
    _coerce_agent_name = field_validator("agent_name", mode="before")(_to_optional_str)
    _coerce_agent_ip = field_validator("agent_ip", mode="before")(_to_optional_str)
    _coerce_rule_id = field_validator("rule_id", mode="before")(_to_optional_str)
    _coerce_rule_level = field_validator("rule_level", mode="before")(_to_optional_int)
    _coerce_rule_description = field_validator("rule_description", mode="before")(_to_optional_str)
    _coerce_computer = field_validator("computer", mode="before")(_to_optional_str)
    _coerce_channel = field_validator("channel", mode="before")(_to_optional_str)
    _coerce_record_id = field_validator("record_id", mode="before")(_to_optional_str)
    _coerce_provider = field_validator("provider", mode="before")(_to_optional_str)
    _coerce_host_key = field_validator("host_key", mode="before")(_to_optional_str)

    @field_validator("mitre_techniques", mode="before")
    @classmethod
    def _coerce_mitre_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]

    @field_validator("rule_groups", "parse_warnings", mode="before")
    @classmethod
    def _coerce_string_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return [str(item) for item in value]

    @model_validator(mode="after")
    def _set_host_key(self) -> BaseEvent:
        if self.host_key:
            return self
        parts: list[str] = []
        if self.agent_id:
            parts.append(f"agent:{self.agent_id.strip().lower()}")
        if self.computer:
            parts.append(f"computer:{self.computer.strip().lower()}")
        if not parts and self.agent_name:
            parts.append(f"agent-name:{self.agent_name.strip().lower()}")
        if not parts and self.source_ref.raw_digest:
            parts.append(f"unknown:{self.source_ref.raw_digest[:16]}")
        self.host_key = "|".join(parts) if parts else "unknown:constructed"
        return self


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


class ProcessTerminateEvent(BaseEvent):
    event_id: int = Field(5, description="Sysmon EID 5")
    event_type: str = "process_terminate"

    process_guid: str
    process_id: int
    image: str
    user: str | None = None

    _coerce_process_guid = field_validator("process_guid", mode="before")(_to_str)
    _coerce_process_id = field_validator("process_id", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_user = field_validator("user", mode="before")(_to_optional_str)


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


class FileDeleteEvent(BaseEvent):
    event_id: int = Field(..., description="Sysmon EID 23 or 26")
    event_type: str = "file_delete"

    process_guid: str
    process_id: int
    image: str
    target_filename: str
    user: str | None = None
    hashes: str | None = None
    is_executable: str | None = None
    archived: str | None = None

    _coerce_process_guid = field_validator("process_guid", mode="before")(_to_str)
    _coerce_process_id = field_validator("process_id", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_target_filename = field_validator("target_filename", mode="before")(_to_str)
    _coerce_user = field_validator("user", mode="before")(_to_optional_str)
    _coerce_hashes = field_validator("hashes", mode="before")(_to_optional_str)
    _coerce_is_executable = field_validator("is_executable", mode="before")(_to_optional_str)
    _coerce_archived = field_validator("archived", mode="before")(_to_optional_str)


class NetworkConnectEvent(BaseEvent):
    event_id: int = Field(3, description="Sysmon EID 3")
    event_type: str = "network_connect"

    process_guid: str
    process_id: int
    image: str
    destination_ip: str
    destination_port: int
    destination_hostname: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    source_hostname: str | None = None
    protocol: str | None = None
    initiated: bool | None = None
    user: str | None = None

    _coerce_process_guid = field_validator("process_guid", mode="before")(_to_str)
    _coerce_process_id = field_validator("process_id", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_destination_ip = field_validator("destination_ip", mode="before")(_to_str)
    _coerce_destination_port = field_validator("destination_port", mode="before")(_to_int)
    _coerce_destination_hostname = field_validator("destination_hostname", mode="before")(
        _to_optional_str
    )
    _coerce_source_ip = field_validator("source_ip", mode="before")(_to_optional_str)
    _coerce_source_port = field_validator("source_port", mode="before")(_to_optional_int)
    _coerce_source_hostname = field_validator("source_hostname", mode="before")(_to_optional_str)
    _coerce_protocol = field_validator("protocol", mode="before")(_to_optional_str)
    _coerce_user = field_validator("user", mode="before")(_to_optional_str)

    @field_validator("initiated", mode="before")
    @classmethod
    def _coerce_initiated(cls, value: Any) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"true", "1", "yes"}:
            return True
        if text in {"false", "0", "no"}:
            return False
        raise ValueError("initiated must be a boolean value")


class RegistryEvent(BaseEvent):
    event_id: int = Field(..., description="Sysmon EID 12, 13, or 14")
    event_type: str = "registry_event"

    process_guid: str
    process_id: int
    image: str
    registry_event_type: str
    target_object: str
    details: str | None = None
    new_name: str | None = None
    user: str | None = None

    _coerce_process_guid = field_validator("process_guid", mode="before")(_to_str)
    _coerce_process_id = field_validator("process_id", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_registry_event_type = field_validator("registry_event_type", mode="before")(_to_str)
    _coerce_target_object = field_validator("target_object", mode="before")(_to_str)
    _coerce_details = field_validator("details", mode="before")(_to_optional_str)
    _coerce_new_name = field_validator("new_name", mode="before")(_to_optional_str)
    _coerce_user = field_validator("user", mode="before")(_to_optional_str)


class ProcessAccessEvent(BaseEvent):
    event_id: int = Field(10, description="Sysmon EID 10")
    event_type: str = "process_access"

    process_guid: str
    process_id: int
    image: str
    target_process_guid: str
    target_process_id: int
    target_image: str
    granted_access: str
    source_thread_id: int | None = None
    call_trace: str | None = None
    user: str | None = None
    target_user: str | None = None

    _coerce_process_guid = field_validator("process_guid", mode="before")(_to_str)
    _coerce_process_id = field_validator("process_id", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_target_process_guid = field_validator("target_process_guid", mode="before")(_to_str)
    _coerce_target_process_id = field_validator("target_process_id", mode="before")(_to_int)
    _coerce_target_image = field_validator("target_image", mode="before")(_to_str)
    _coerce_granted_access = field_validator("granted_access", mode="before")(_to_str)
    _coerce_source_thread_id = field_validator("source_thread_id", mode="before")(_to_optional_int)
    _coerce_call_trace = field_validator("call_trace", mode="before")(_to_optional_str)
    _coerce_user = field_validator("user", mode="before")(_to_optional_str)
    _coerce_target_user = field_validator("target_user", mode="before")(_to_optional_str)


class DnsQueryEvent(BaseEvent):
    event_id: int = Field(22, description="Sysmon EID 22")
    event_type: str = "dns_query"

    process_guid: str
    process_id: int
    image: str
    query_name: str
    query_status: str | None = None
    query_results: str | None = None
    user: str | None = None

    _coerce_process_guid = field_validator("process_guid", mode="before")(_to_str)
    _coerce_process_id = field_validator("process_id", mode="before")(_to_int)
    _coerce_image = field_validator("image", mode="before")(_to_str)
    _coerce_query_name = field_validator("query_name", mode="before")(_to_str)
    _coerce_query_status = field_validator("query_status", mode="before")(_to_optional_str)
    _coerce_query_results = field_validator("query_results", mode="before")(_to_optional_str)
    _coerce_user = field_validator("user", mode="before")(_to_optional_str)


class RemoteLogonEvent(BaseEvent):
    event_id: int = Field(4624, description="Windows Security EID 4624")
    event_type: str = "successful_logon"
    kind: str = "windows_security"

    logon_type: int
    target_user_name: str
    target_domain_name: str | None = None
    target_user_sid: str | None = None
    target_logon_id: str
    user: str
    source_ip: str | None = None
    source_port: int | None = None
    workstation_name: str | None = None
    process_id: int | None = None
    process_name: str | None = None
    logon_process_name: str | None = None
    authentication_package_name: str | None = None
    elevated_token: str | None = None
    restricted_admin_mode: str | None = None

    _coerce_logon_type = field_validator("logon_type", mode="before")(_to_int)
    _coerce_target_user_name = field_validator("target_user_name", mode="before")(_to_str)
    _coerce_target_domain_name = field_validator("target_domain_name", mode="before")(
        _to_optional_str
    )
    _coerce_target_user_sid = field_validator("target_user_sid", mode="before")(
        _to_optional_str
    )
    _coerce_target_logon_id = field_validator("target_logon_id", mode="before")(_to_str)
    _coerce_user = field_validator("user", mode="before")(_to_str)
    _coerce_source_ip = field_validator("source_ip", mode="before")(_to_optional_str)
    _coerce_source_port = field_validator("source_port", mode="before")(_to_optional_int)
    _coerce_workstation_name = field_validator("workstation_name", mode="before")(
        _to_optional_str
    )
    _coerce_process_id = field_validator("process_id", mode="before")(_to_optional_int)
    _coerce_process_name = field_validator("process_name", mode="before")(_to_optional_str)
    _coerce_logon_process_name = field_validator("logon_process_name", mode="before")(
        _to_optional_str
    )
    _coerce_authentication_package_name = field_validator(
        "authentication_package_name", mode="before"
    )(_to_optional_str)
    _coerce_elevated_token = field_validator("elevated_token", mode="before")(
        _to_optional_str
    )
    _coerce_restricted_admin_mode = field_validator(
        "restricted_admin_mode", mode="before"
    )(_to_optional_str)


class ServiceInstallEvent(BaseEvent):
    event_id: int = Field(4697, description="Windows Security EID 4697")
    event_type: str = "service_install"
    kind: str = "windows_security"

    subject_user_name: str
    subject_domain_name: str | None = None
    subject_user_sid: str | None = None
    subject_logon_id: str
    user: str
    service_name: str
    service_file_name: str
    service_type: str | None = None
    service_start_type: str | None = None
    service_account: str | None = None

    _coerce_subject_user_name = field_validator("subject_user_name", mode="before")(_to_str)
    _coerce_subject_domain_name = field_validator("subject_domain_name", mode="before")(
        _to_optional_str
    )
    _coerce_subject_user_sid = field_validator("subject_user_sid", mode="before")(
        _to_optional_str
    )
    _coerce_subject_logon_id = field_validator("subject_logon_id", mode="before")(_to_str)
    _coerce_user = field_validator("user", mode="before")(_to_str)
    _coerce_service_name = field_validator("service_name", mode="before")(_to_str)
    _coerce_service_file_name = field_validator("service_file_name", mode="before")(_to_str)
    _coerce_service_type = field_validator("service_type", mode="before")(_to_optional_str)
    _coerce_service_start_type = field_validator("service_start_type", mode="before")(
        _to_optional_str
    )
    _coerce_service_account = field_validator("service_account", mode="before")(
        _to_optional_str
    )


class ScheduledTaskCreatedEvent(BaseEvent):
    event_id: int = Field(4698, description="Windows Security EID 4698")
    event_type: str = "scheduled_task_created"
    kind: str = "windows_security"

    subject_user_name: str
    subject_domain_name: str | None = None
    subject_user_sid: str | None = None
    subject_logon_id: str
    user: str
    task_name: str
    task_content: str | None = None
    client_process_id: int | None = None
    parent_process_id: int | None = None

    _coerce_subject_user_name = field_validator("subject_user_name", mode="before")(_to_str)
    _coerce_subject_domain_name = field_validator("subject_domain_name", mode="before")(
        _to_optional_str
    )
    _coerce_subject_user_sid = field_validator("subject_user_sid", mode="before")(
        _to_optional_str
    )
    _coerce_subject_logon_id = field_validator("subject_logon_id", mode="before")(_to_str)
    _coerce_user = field_validator("user", mode="before")(_to_str)
    _coerce_task_name = field_validator("task_name", mode="before")(_to_str)
    _coerce_task_content = field_validator("task_content", mode="before")(_to_optional_str)
    _coerce_client_process_id = field_validator("client_process_id", mode="before")(
        _to_optional_int
    )
    _coerce_parent_process_id = field_validator("parent_process_id", mode="before")(
        _to_optional_int
    )


ProcessLinkedEvent = (
    ProcessCreateEvent
    | ProcessTerminateEvent
    | FileCreateEvent
    | FileDeleteEvent
    | NetworkConnectEvent
    | RegistryEvent
    | ProcessAccessEvent
    | DnsQueryEvent
)

CanonicalEvent = (
    ProcessLinkedEvent
    | RemoteLogonEvent
    | ServiceInstallEvent
    | ScheduledTaskCreatedEvent
)

# Backwards-compatible type alias retained for existing integrations.
SysmonEvent = CanonicalEvent
