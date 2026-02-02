from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from wazuh_sysmon_triage.models.raw import RawHit
from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessCreateEvent,
    SysmonEvent,
)


LOGGER = logging.getLogger(__name__)


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
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
    return None


def get_ci(mapping: Optional[Dict[str, Any]], *keys: str) -> Any:
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


def _normalize_mitre(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        if "id" in value:
            return [str(value["id"])]
        return [str(item) for item in value.values()]
    return [str(item) for item in value]


def normalize_data(raw_data: Iterable[RawHit]) -> List[SysmonEvent]:
    """
    Normalize raw OpenSearch hits into SysmonEvent models.
    """
    normalized: List[SysmonEvent] = []

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
            continue

        timestamp = _parse_dt(get_ci(eventdata, "utcTime")) or _parse_dt(source.get("@timestamp"))
        if not timestamp:
            LOGGER.warning("Dropping event missing timestamp")
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
            if not process_guid or process_id is None or not image:
                LOGGER.warning("Dropping EID 1 missing required fields")
                continue
            model = ProcessCreateEvent(
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
            normalized.append(model)
        elif event_id == 11:
            process_guid = get_ci(eventdata, "processGuid")
            process_id = _to_int(get_ci(eventdata, "processId"))
            image = get_ci(eventdata, "image")
            target_filename = get_ci(eventdata, "targetFilename")
            if not process_guid or process_id is None or not image or not target_filename:
                LOGGER.warning("Dropping EID 11 missing required fields")
                continue
            model = FileCreateEvent(
                **common,
                process_guid=process_guid,
                process_id=process_id,
                image=image,
                target_filename=target_filename,
                creation_utc_time=_parse_dt(get_ci(eventdata, "creationUtcTime")),
                user=get_ci(eventdata, "user"),
            )
            normalized.append(model)
        elif event_id == 3:
            process_guid = get_ci(eventdata, "processGuid")
            process_id = _to_int(get_ci(eventdata, "processId"))
            image = get_ci(eventdata, "image")
            dest_ip = get_ci(eventdata, "destinationIp")
            dest_port = _to_int(get_ci(eventdata, "destinationPort"))
            protocol = get_ci(eventdata, "protocol")
            if not process_guid or process_id is None or not image or not dest_ip or dest_port is None:
                LOGGER.warning("Dropping EID 3 missing required fields")
                continue
            model = NetworkConnectEvent(
                **common,
                process_guid=process_guid,
                process_id=process_id,
                image=image,
                destination_ip=dest_ip,
                destination_port=dest_port,
                protocol=protocol,
            )
            normalized.append(model)
        else:
            continue

    return sorted(normalized, key=lambda item: item.timestamp)