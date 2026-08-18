from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from wazuh_sysmon_triage.models.evidence import SourceRef
from wazuh_sysmon_triage.models.raw import RawHit
from wazuh_sysmon_triage.models.sysmon import (
    DnsQueryEvent,
    FileCreateEvent,
    FileDeleteEvent,
    NetworkConnectEvent,
    ProcessAccessEvent,
    ProcessCreateEvent,
    ProcessTerminateEvent,
    RegistryEvent,
    RemoteLogonEvent,
    ScheduledTaskCreatedEvent,
    ServiceInstallEvent,
    SysmonEvent,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class NormalizeReport:
    dropped_count: int = 0
    dropped_by_reason: dict[str, int] = field(default_factory=dict)
    invalid_timestamp_count: int = 0
    invalid_timestamp_by_eid: dict[str, int] = field(default_factory=dict)
    unsupported_count: int = 0
    unsupported_by_eid: dict[str, int] = field(default_factory=dict)
    dropped_events: list[dict[str, Any]] = field(default_factory=list)


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_windows_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16 if text.lower().startswith("0x") else 10)
    except ValueError:
        return None


def _qualified_account(domain: Any, user: Any) -> str:
    user_text = str(user).strip() if user is not None else ""
    domain_text = str(domain).strip() if domain is not None else ""
    return f"{domain_text}\\{user_text}" if domain_text else user_text


def _parse_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return None


def get_ci(mapping: Mapping[str, Any] | None, *keys: str) -> Any:
    if not mapping:
        return None
    lowered = {str(candidate).lower(): value for candidate, value in mapping.items()}
    for key in keys:
        if key.lower() in lowered:
            return lowered[key.lower()]
    return None


def _normalize_mitre(value: Any) -> list[str]:
    normalized: list[str] = []

    def append_ids(candidate: Any) -> None:
        if candidate is None:
            return
        if isinstance(candidate, str):
            text = candidate.strip()
            if text and text not in normalized:
                normalized.append(text)
            return
        if isinstance(candidate, Mapping):
            append_ids(get_ci(candidate, "id"))
            return
        if isinstance(candidate, Iterable):
            for item in candidate:
                append_ids(item)
            return
        text = str(candidate).strip()
        if text and text not in normalized:
            normalized.append(text)

    append_ids(value)
    return normalized


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    return {}


def _raw_digest(source: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        source,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _source_ref(
    hit: Mapping[str, Any],
    source: Mapping[str, Any],
    system: Mapping[str, Any],
    *,
    wrapped: bool,
) -> SourceRef:
    document_id = hit.get("_id")
    index = hit.get("_index")
    return SourceRef(
        source_type="opensearch_hit" if wrapped else "wazuh_json",
        index=str(index) if index is not None else None,
        document_id=str(document_id) if document_id is not None else None,
        provider=str(get_ci(system, "providerName"))
        if get_ci(system, "providerName") is not None
        else None,
        channel=str(get_ci(system, "channel")) if get_ci(system, "channel") is not None else None,
        record_id=str(get_ci(system, "eventRecordID"))
        if get_ci(system, "eventRecordID") is not None
        else None,
        raw_digest=_raw_digest(source),
    )


def _normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(item) for item in value]
    return [str(value)]


def _timestamp_parse_status(value: Any) -> tuple[datetime | None, str]:
    if value is None:
        return None, "missing"
    parsed = _parse_dt(value)
    if parsed is None:
        return None, "invalid"
    return parsed, "ok"


def _missing_fields(
    values: dict[str, Any],
) -> list[str]:
    missing: list[str] = []
    for name, value in values.items():
        if value is None or value == "":
            missing.append(name)
    return missing


def _record_drop(
    report: NormalizeReport,
    *,
    reason: str,
    event_id: int | None,
    hit: RawHit,
    collect_dropped: bool,
    details: dict[str, Any] | None = None,
) -> None:
    report.dropped_count += 1
    report.dropped_by_reason[reason] = report.dropped_by_reason.get(reason, 0) + 1
    if reason == "invalid_timestamp":
        report.invalid_timestamp_count += 1
        eid_key = str(event_id) if event_id is not None else "unknown"
        report.invalid_timestamp_by_eid[eid_key] = (
            report.invalid_timestamp_by_eid.get(eid_key, 0) + 1
        )
    if reason == "unsupported_event_id":
        report.unsupported_count += 1
        eid_key = str(event_id) if event_id is not None else "unknown"
        report.unsupported_by_eid[eid_key] = report.unsupported_by_eid.get(eid_key, 0) + 1
    if collect_dropped:
        report.dropped_events.append(
            {
                "reason": reason,
                "event_id": event_id,
                "details": details or {},
                "raw_hit": hit,
            }
        )


def normalize_data(raw_data: Iterable[RawHit]) -> list[SysmonEvent]:
    """
    Normalize raw OpenSearch hits into SysmonEvent models.
    """
    normalized, _ = normalize_data_with_report(raw_data, collect_dropped=False)
    return normalized


def normalize_data_with_report(
    raw_data: Iterable[RawHit],
    *,
    collect_dropped: bool = False,
) -> tuple[list[SysmonEvent], NormalizeReport]:
    """
    Normalize raw OpenSearch hits into SysmonEvent models and collect drop metrics.
    """
    normalized: list[SysmonEvent] = []
    report = NormalizeReport()

    for hit in raw_data:
        hit_mapping = _as_mapping(hit)
        wrapped = isinstance(hit_mapping.get("_source"), Mapping)
        source = _as_mapping(hit_mapping.get("_source")) if wrapped else hit_mapping
        agent = _as_mapping(source.get("agent"))
        rule = _as_mapping(source.get("rule"))
        data = _as_mapping(source.get("data"))
        win = _as_mapping(data.get("win"))
        system = _as_mapping(win.get("system"))
        eventdata = _as_mapping(win.get("eventdata"))

        event_id_raw = get_ci(system, "eventID")
        event_id = _to_int(event_id_raw)
        if event_id is None:
            LOGGER.warning("Dropping event missing eventID")
            _record_drop(
                report,
                reason="missing_event_id",
                event_id=None,
                hit=hit,
                collect_dropped=collect_dropped,
            )
            continue

        provider_name = get_ci(system, "providerName")
        if event_id in {4624, 4697, 4698} and str(provider_name or "").casefold() != (
            "microsoft-windows-security-auditing"
        ):
            LOGGER.warning("Dropping Windows Security event with unexpected provider")
            _record_drop(
                report,
                reason="unexpected_provider_windows_security",
                event_id=event_id,
                hit=hit,
                collect_dropped=collect_dropped,
                details={"providerName": provider_name},
            )
            continue

        utc_time_raw = get_ci(eventdata, "utcTime")
        wazuh_time_raw = source.get("timestamp")
        indexed_time_raw = source.get("@timestamp")
        timestamp_utc, utc_status = _timestamp_parse_status(utc_time_raw)
        timestamp_wazuh, wazuh_status = _timestamp_parse_status(wazuh_time_raw)
        timestamp_indexed, indexed_status = _timestamp_parse_status(indexed_time_raw)
        timestamp = timestamp_utc or timestamp_wazuh or timestamp_indexed
        if not timestamp:
            reason = (
                "invalid_timestamp"
                if "invalid" in {utc_status, wazuh_status, indexed_status}
                else "missing_timestamp"
            )
            LOGGER.warning("Dropping event missing or invalid timestamp")
            _record_drop(
                report,
                reason=reason,
                event_id=event_id,
                hit=hit,
                collect_dropped=collect_dropped,
                details={
                    "utcTime": utc_time_raw,
                    "timestamp": wazuh_time_raw,
                    "@timestamp": indexed_time_raw,
                },
            )
            continue

        parse_warnings: list[str] = []
        if utc_status == "invalid":
            parse_warnings.append("invalid_sysmon_utc_time")
        if wazuh_status == "invalid":
            parse_warnings.append("invalid_wazuh_timestamp")
        if indexed_status == "invalid":
            parse_warnings.append("invalid_indexed_timestamp")

        common = {
            "event_id": event_id,
            "timestamp": timestamp,
            "wazuh_timestamp": timestamp_wazuh,
            "indexed_at": timestamp_indexed,
            "agent_id": get_ci(agent, "id"),
            "agent_name": get_ci(agent, "name"),
            "agent_ip": get_ci(agent, "ip"),
            "rule_id": get_ci(rule, "id"),
            "rule_level": _to_int(get_ci(rule, "level")),
            "rule_description": get_ci(rule, "description"),
            "rule_groups": _normalize_string_list(get_ci(rule, "groups")),
            "mitre_techniques": _normalize_mitre(get_ci(rule, "mitre")),
            "computer": get_ci(system, "computer"),
            "channel": get_ci(system, "channel"),
            "record_id": get_ci(system, "eventRecordID"),
            "provider": provider_name,
            "source_ref": _source_ref(
                hit_mapping,
                source,
                system,
                wrapped=wrapped,
            ),
            "parse_warnings": parse_warnings,
        }

        if event_id == 1:
            process_guid = get_ci(eventdata, "processGuid")
            process_id = _to_int(get_ci(eventdata, "processId"))
            image = get_ci(eventdata, "image")
            missing = _missing_fields(
                {
                    "processGuid": process_guid,
                    "processId": process_id,
                    "image": image,
                }
            )
            if missing:
                LOGGER.warning("Dropping EID 1 missing required fields")
                _record_drop(
                    report,
                    reason="missing_required_fields_eid1",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert isinstance(process_guid, str)
            assert process_id is not None
            assert isinstance(image, str)
            normalized.append(
                ProcessCreateEvent(
                    **common,
                    process_guid=process_guid,
                    process_id=process_id,
                    image=image,
                    command_line=get_ci(eventdata, "commandLine"),
                    current_directory=get_ci(eventdata, "currentDirectory"),
                    user=get_ci(eventdata, "user"),
                    parent_process_guid=get_ci(eventdata, "parentProcessGuid"),
                    parent_process_id=_to_int(get_ci(eventdata, "parentProcessId")),
                    parent_image=get_ci(eventdata, "parentImage"),
                    parent_command_line=get_ci(eventdata, "parentCommandLine"),
                    hashes=get_ci(eventdata, "hashes"),
                    integrity_level=get_ci(eventdata, "integrityLevel"),
                )
            )
        elif event_id == 5:
            process_guid = get_ci(eventdata, "processGuid")
            process_id = _to_int(get_ci(eventdata, "processId"))
            image = get_ci(eventdata, "image")
            missing = _missing_fields(
                {
                    "processGuid": process_guid,
                    "processId": process_id,
                    "image": image,
                }
            )
            if missing:
                LOGGER.warning("Dropping EID 5 missing required fields")
                _record_drop(
                    report,
                    reason="missing_required_fields_eid5",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert isinstance(process_guid, str)
            assert process_id is not None
            assert isinstance(image, str)
            normalized.append(
                ProcessTerminateEvent(
                    **common,
                    process_guid=process_guid,
                    process_id=process_id,
                    image=image,
                    user=get_ci(eventdata, "user"),
                )
            )
        elif event_id == 11:
            process_guid = get_ci(eventdata, "processGuid")
            process_id = _to_int(get_ci(eventdata, "processId"))
            image = get_ci(eventdata, "image")
            target_filename = get_ci(eventdata, "targetFilename")
            missing = _missing_fields(
                {
                    "processGuid": process_guid,
                    "processId": process_id,
                    "image": image,
                    "targetFilename": target_filename,
                }
            )
            if missing:
                LOGGER.warning("Dropping EID 11 missing required fields")
                _record_drop(
                    report,
                    reason="missing_required_fields_eid11",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert isinstance(process_guid, str)
            assert process_id is not None
            assert isinstance(image, str)
            assert isinstance(target_filename, str)
            normalized.append(
                FileCreateEvent(
                    **common,
                    process_guid=process_guid,
                    process_id=process_id,
                    image=image,
                    target_filename=target_filename,
                    creation_utc_time=_parse_dt(get_ci(eventdata, "creationUtcTime")),
                    user=get_ci(eventdata, "user"),
                )
            )
        elif event_id in {23, 26}:
            process_guid = get_ci(eventdata, "processGuid")
            process_id = _to_int(get_ci(eventdata, "processId"))
            image = get_ci(eventdata, "image")
            target_filename = get_ci(eventdata, "targetFilename")
            missing = _missing_fields(
                {
                    "processGuid": process_guid,
                    "processId": process_id,
                    "image": image,
                    "targetFilename": target_filename,
                }
            )
            if missing:
                LOGGER.warning("Dropping file-delete event missing required fields")
                _record_drop(
                    report,
                    reason=f"missing_required_fields_eid{event_id}",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert isinstance(process_guid, str)
            assert process_id is not None
            assert isinstance(image, str)
            assert isinstance(target_filename, str)
            normalized.append(
                FileDeleteEvent(
                    **common,
                    process_guid=process_guid,
                    process_id=process_id,
                    image=image,
                    target_filename=target_filename,
                    user=get_ci(eventdata, "user"),
                    hashes=get_ci(eventdata, "hashes"),
                    is_executable=get_ci(eventdata, "isExecutable"),
                    archived=get_ci(eventdata, "archived"),
                )
            )
        elif event_id == 3:
            process_guid = get_ci(eventdata, "processGuid")
            process_id = _to_int(get_ci(eventdata, "processId"))
            image = get_ci(eventdata, "image")
            dest_ip = get_ci(eventdata, "destinationIp")
            dest_port = _to_int(get_ci(eventdata, "destinationPort"))
            protocol = get_ci(eventdata, "protocol")
            missing = _missing_fields(
                {
                    "processGuid": process_guid,
                    "processId": process_id,
                    "image": image,
                    "destinationIp": dest_ip,
                    "destinationPort": dest_port,
                }
            )
            if missing:
                LOGGER.warning("Dropping EID 3 missing required fields")
                _record_drop(
                    report,
                    reason="missing_required_fields_eid3",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert isinstance(process_guid, str)
            assert process_id is not None
            assert isinstance(image, str)
            assert isinstance(dest_ip, str)
            assert dest_port is not None
            normalized.append(
                NetworkConnectEvent(
                    **common,
                    process_guid=process_guid,
                    process_id=process_id,
                    image=image,
                    destination_ip=dest_ip,
                    destination_port=dest_port,
                    destination_hostname=get_ci(eventdata, "destinationHostname"),
                    source_ip=get_ci(eventdata, "sourceIp"),
                    source_port=_to_int(get_ci(eventdata, "sourcePort")),
                    source_hostname=get_ci(eventdata, "sourceHostname"),
                    protocol=protocol,
                    initiated=get_ci(eventdata, "initiated"),
                    user=get_ci(eventdata, "user"),
                )
            )
        elif event_id in {12, 13, 14}:
            process_guid = get_ci(eventdata, "processGuid")
            process_id = _to_int(get_ci(eventdata, "processId"))
            image = get_ci(eventdata, "image")
            registry_event_type = get_ci(eventdata, "eventType")
            target_object = get_ci(eventdata, "targetObject")
            missing = _missing_fields(
                {
                    "processGuid": process_guid,
                    "processId": process_id,
                    "image": image,
                    "eventType": registry_event_type,
                    "targetObject": target_object,
                }
            )
            if missing:
                LOGGER.warning("Dropping registry event missing required fields")
                _record_drop(
                    report,
                    reason=f"missing_required_fields_eid{event_id}",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert process_id is not None
            normalized.append(
                RegistryEvent(
                    **common,
                    process_guid=process_guid,
                    process_id=process_id,
                    image=image,
                    registry_event_type=registry_event_type,
                    target_object=target_object,
                    details=get_ci(eventdata, "details"),
                    new_name=get_ci(eventdata, "newName"),
                    user=get_ci(eventdata, "user"),
                )
            )
        elif event_id == 10:
            process_guid = get_ci(eventdata, "sourceProcessGuid")
            process_id = _to_int(get_ci(eventdata, "sourceProcessId"))
            image = get_ci(eventdata, "sourceImage")
            target_process_guid = get_ci(eventdata, "targetProcessGuid")
            target_process_id = _to_int(get_ci(eventdata, "targetProcessId"))
            target_image = get_ci(eventdata, "targetImage")
            granted_access = get_ci(eventdata, "grantedAccess")
            missing = _missing_fields(
                {
                    "sourceProcessGuid": process_guid,
                    "sourceProcessId": process_id,
                    "sourceImage": image,
                    "targetProcessGuid": target_process_guid,
                    "targetProcessId": target_process_id,
                    "targetImage": target_image,
                    "grantedAccess": granted_access,
                }
            )
            if missing:
                LOGGER.warning("Dropping EID 10 missing required fields")
                _record_drop(
                    report,
                    reason="missing_required_fields_eid10",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert process_id is not None
            assert target_process_id is not None
            normalized.append(
                ProcessAccessEvent(
                    **common,
                    process_guid=process_guid,
                    process_id=process_id,
                    image=image,
                    target_process_guid=target_process_guid,
                    target_process_id=target_process_id,
                    target_image=target_image,
                    granted_access=granted_access,
                    source_thread_id=_to_int(get_ci(eventdata, "sourceThreadId")),
                    call_trace=get_ci(eventdata, "callTrace"),
                    user=get_ci(eventdata, "sourceUser", "user"),
                    target_user=get_ci(eventdata, "targetUser"),
                )
            )
        elif event_id == 22:
            process_guid = get_ci(eventdata, "processGuid")
            process_id = _to_int(get_ci(eventdata, "processId"))
            image = get_ci(eventdata, "image")
            query_name = get_ci(eventdata, "queryName")
            missing = _missing_fields(
                {
                    "processGuid": process_guid,
                    "processId": process_id,
                    "image": image,
                    "queryName": query_name,
                }
            )
            if missing:
                LOGGER.warning("Dropping EID 22 missing required fields")
                _record_drop(
                    report,
                    reason="missing_required_fields_eid22",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert process_id is not None
            normalized.append(
                DnsQueryEvent(
                    **common,
                    process_guid=process_guid,
                    process_id=process_id,
                    image=image,
                    query_name=query_name,
                    query_status=get_ci(eventdata, "queryStatus"),
                    query_results=get_ci(eventdata, "queryResults"),
                    user=get_ci(eventdata, "user"),
                )
            )
        elif event_id == 4624:
            logon_type = _to_int(get_ci(eventdata, "logonType"))
            target_user_name = get_ci(eventdata, "targetUserName")
            target_logon_id = get_ci(eventdata, "targetLogonId")
            missing = _missing_fields(
                {
                    "logonType": logon_type,
                    "targetUserName": target_user_name,
                    "targetLogonId": target_logon_id,
                }
            )
            if missing:
                LOGGER.warning("Dropping EID 4624 missing required fields")
                _record_drop(
                    report,
                    reason="missing_required_fields_eid4624",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert logon_type is not None
            assert isinstance(target_user_name, str)
            assert isinstance(target_logon_id, str)
            target_domain_name = get_ci(eventdata, "targetDomainName")
            normalized.append(
                RemoteLogonEvent(
                    **common,
                    logon_type=logon_type,
                    target_user_name=target_user_name,
                    target_domain_name=target_domain_name,
                    target_user_sid=get_ci(eventdata, "targetUserSid"),
                    target_logon_id=target_logon_id,
                    user=_qualified_account(target_domain_name, target_user_name),
                    source_ip=get_ci(eventdata, "ipAddress", "sourceNetworkAddress"),
                    source_port=_to_windows_int(get_ci(eventdata, "ipPort", "sourcePort")),
                    workstation_name=get_ci(eventdata, "workstationName"),
                    process_id=_to_windows_int(get_ci(eventdata, "processId")),
                    process_name=get_ci(eventdata, "processName"),
                    logon_process_name=get_ci(eventdata, "logonProcessName"),
                    authentication_package_name=get_ci(
                        eventdata, "authenticationPackageName"
                    ),
                    elevated_token=get_ci(eventdata, "elevatedToken"),
                    restricted_admin_mode=get_ci(eventdata, "restrictedAdminMode"),
                )
            )
        elif event_id == 4697:
            subject_user_name = get_ci(eventdata, "subjectUserName")
            subject_logon_id = get_ci(eventdata, "subjectLogonId")
            service_name = get_ci(eventdata, "serviceName")
            service_file_name = get_ci(eventdata, "serviceFileName")
            missing = _missing_fields(
                {
                    "subjectUserName": subject_user_name,
                    "subjectLogonId": subject_logon_id,
                    "serviceName": service_name,
                    "serviceFileName": service_file_name,
                }
            )
            if missing:
                LOGGER.warning("Dropping EID 4697 missing required fields")
                _record_drop(
                    report,
                    reason="missing_required_fields_eid4697",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert isinstance(subject_user_name, str)
            assert isinstance(subject_logon_id, str)
            assert isinstance(service_name, str)
            assert isinstance(service_file_name, str)
            subject_domain_name = get_ci(eventdata, "subjectDomainName")
            normalized.append(
                ServiceInstallEvent(
                    **common,
                    subject_user_name=subject_user_name,
                    subject_domain_name=subject_domain_name,
                    subject_user_sid=get_ci(eventdata, "subjectUserSid"),
                    subject_logon_id=subject_logon_id,
                    user=_qualified_account(subject_domain_name, subject_user_name),
                    service_name=service_name,
                    service_file_name=service_file_name,
                    service_type=get_ci(eventdata, "serviceType"),
                    service_start_type=get_ci(eventdata, "serviceStartType"),
                    service_account=get_ci(eventdata, "serviceAccount"),
                )
            )
        elif event_id == 4698:
            subject_user_name = get_ci(eventdata, "subjectUserName")
            subject_logon_id = get_ci(eventdata, "subjectLogonId")
            task_name = get_ci(eventdata, "taskName")
            missing = _missing_fields(
                {
                    "subjectUserName": subject_user_name,
                    "subjectLogonId": subject_logon_id,
                    "taskName": task_name,
                }
            )
            if missing:
                LOGGER.warning("Dropping EID 4698 missing required fields")
                _record_drop(
                    report,
                    reason="missing_required_fields_eid4698",
                    event_id=event_id,
                    hit=hit,
                    collect_dropped=collect_dropped,
                    details={"missing": missing},
                )
                continue
            assert isinstance(subject_user_name, str)
            assert isinstance(subject_logon_id, str)
            assert isinstance(task_name, str)
            subject_domain_name = get_ci(eventdata, "subjectDomainName")
            normalized.append(
                ScheduledTaskCreatedEvent(
                    **common,
                    subject_user_name=subject_user_name,
                    subject_domain_name=subject_domain_name,
                    subject_user_sid=get_ci(eventdata, "subjectUserSid"),
                    subject_logon_id=subject_logon_id,
                    user=_qualified_account(subject_domain_name, subject_user_name),
                    task_name=task_name,
                    task_content=get_ci(eventdata, "taskContent"),
                    client_process_id=_to_windows_int(get_ci(eventdata, "clientProcessId")),
                    parent_process_id=_to_windows_int(get_ci(eventdata, "parentProcessId")),
                )
            )
        else:
            _record_drop(
                report,
                reason="unsupported_event_id",
                event_id=event_id,
                hit=hit,
                collect_dropped=collect_dropped,
            )
            continue

    return sorted(normalized, key=lambda item: item.timestamp), report
