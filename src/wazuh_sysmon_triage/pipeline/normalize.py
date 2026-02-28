from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from wazuh_sysmon_triage.models.raw import RawHit
from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessCreateEvent,
    SysmonEvent,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class NormalizeReport:
    dropped_count: int = 0
    dropped_by_reason: dict[str, int] = field(default_factory=dict)
    invalid_timestamp_count: int = 0
    invalid_timestamp_by_eid: dict[str, int] = field(default_factory=dict)
    dropped_events: list[dict[str, Any]] = field(default_factory=list)


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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
    for key in keys:
        variants = {
            key,
            key[:1].upper() + key[1:],
            key[:1].lower() + key[1:],
            key.lower(),
            key.upper(),
        }
        for variant in variants:
            if variant in mapping:
                return mapping[variant]
    return None


def _normalize_mitre(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        if "id" in value:
            return [str(value["id"])]
        return [str(item) for item in value.values()]
    return [str(item) for item in value]


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
        source = hit.get("_source") or {}
        agent = source.get("agent") or {}
        rule = source.get("rule") or {}
        data = source.get("data") or {}
        win = data.get("win") or {}
        system = win.get("system") or {}
        eventdata = win.get("eventdata") or {}

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

        utc_time_raw = get_ci(eventdata, "utcTime")
        source_time_raw = source.get("@timestamp")
        timestamp_utc, utc_status = _timestamp_parse_status(utc_time_raw)
        timestamp_source, source_status = _timestamp_parse_status(source_time_raw)
        timestamp = timestamp_utc or timestamp_source
        if not timestamp:
            reason = (
                "invalid_timestamp"
                if utc_status == "invalid" or source_status == "invalid"
                else "missing_timestamp"
            )
            LOGGER.warning("Dropping event missing or invalid timestamp")
            _record_drop(
                report,
                reason=reason,
                event_id=event_id,
                hit=hit,
                collect_dropped=collect_dropped,
                details={"utcTime": utc_time_raw, "@timestamp": source_time_raw},
            )
            continue

        common = {
            "event_id": event_id,
            "timestamp": timestamp,
            "agent_id": get_ci(agent, "id"),
            "agent_name": get_ci(agent, "name"),
            "agent_ip": get_ci(agent, "ip"),
            "rule_id": get_ci(rule, "id"),
            "rule_description": get_ci(rule, "description"),
            "mitre_techniques": _normalize_mitre(get_ci(rule, "mitre")),
            "computer": get_ci(system, "computer"),
            "channel": get_ci(system, "channel"),
            "record_id": get_ci(system, "eventRecordID"),
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
                    protocol=protocol,
                )
            )
        else:
            continue

    return sorted(normalized, key=lambda item: item.timestamp), report
