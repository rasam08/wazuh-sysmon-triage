from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from collections.abc import Iterable
from typing import Any

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    ProcessCreateEvent,
    SysmonEvent,
)
from wazuh_sysmon_triage.pipeline.network_utils import destination_class

from .detect_types import (
    DEFAULT_ALLOWLIST_BASENAMES,
    ENCODED_COMMAND_FLAG_RE,
    MICROSOFT_IP_PREFIXES,
    SCRIPT_EXTENSIONS,
    TEMP_MARKERS,
    USER_WRITABLE_MARKERS,
)


def _basename(path: str | None) -> str:
    if not path:
        return ""
    return os.path.basename(path).lower()


def normalize_allowlist_basenames(values: Iterable[str] | None = None) -> set[str]:
    if values is None:
        return set(DEFAULT_ALLOWLIST_BASENAMES)
    normalized = {_basename(value) for value in values if value}
    normalized = {value for value in normalized if value}
    return set(DEFAULT_ALLOWLIST_BASENAMES) | normalized


def _rule_name(rule: dict[str, Any]) -> str:
    return str(rule.get("name") or "unnamed_suppression")


def _destination_class(value: str | None) -> str | None:
    return destination_class(value)


def _matches_pattern(value: str | None, pattern: str | None) -> bool:
    if not pattern:
        return True
    if not value:
        return False
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def _matches_regex(value: str | None, pattern: str | None) -> bool:
    if not pattern:
        return True
    if not value:
        return False
    try:
        return bool(re.search(pattern, value, flags=re.IGNORECASE))
    except re.error:
        return False


def _matches_suppression_rule(
    rule: dict[str, Any],
    *,
    image: str | None,
    user: str | None,
    destination_ip: str | None,
    destination_port: int | None,
) -> bool:
    if rule.get("enabled") is False:
        return False
    if not _matches_pattern(image, rule.get("image_glob")):
        return False
    if not _matches_regex(image, rule.get("image_regex")):
        return False

    expected_user = rule.get("user")
    if expected_user and (not user or user.lower() != str(expected_user).lower()):
        return False

    expected_ports = rule.get("destination_ports") or []
    if expected_ports and destination_port not in {int(port) for port in expected_ports}:
        return False

    expected_class = rule.get("destination_class")
    if expected_class:
        actual_class = _destination_class(destination_ip)
        if actual_class != expected_class:
            return False

    return True


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False


def is_allowlisted_image(
    image: str | None,
    allowlist_basenames: set[str] | None = None,
) -> bool:
    allowlist = allowlist_basenames or set(DEFAULT_ALLOWLIST_BASENAMES)
    return _basename(image) in allowlist


def _score_to_reason(prefix: str, hits: list[str]) -> str:
    if not hits:
        return prefix
    return f"{prefix}: {', '.join(hits)}"


def _has_encoded_command_flag(command: str) -> bool:
    return bool(ENCODED_COMMAND_FLAG_RE.search(command))


def _is_microsoft_destination(ip: str | None) -> bool:
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in MICROSOFT_IP_PREFIXES)


def _temp_script_write(files: list[FileCreateEvent]) -> bool:
    for event in files:
        path = (event.target_filename or "").lower()
        if any(marker in path for marker in TEMP_MARKERS) and path.endswith(SCRIPT_EXTENSIONS):
            return True
    return False


def _is_user_writable_path(value: str | None) -> bool:
    lower = (value or "").lower()
    return any(marker in lower for marker in USER_WRITABLE_MARKERS)


def _event_host_label(event: SysmonEvent) -> str:
    return event.agent_name or event.computer or event.agent_id or "unknown-host"


def _host_key(value: str) -> str:
    return value.lower()


def _safe_tag_value(value: str) -> str:
    return re.sub(r"[^a-z0-9_.:-]", "_", value.lower())


def _alert_dedup_key(alert: Alert) -> tuple[str, str, str, str, int]:
    minute_bucket = alert.utc_time.replace(second=0, microsecond=0).isoformat()
    return (
        alert.alert_type,
        alert.process_guid,
        minute_bucket,
        alert.destination_ip or "",
        alert.destination_port if alert.destination_port is not None else -1,
    )


def sort_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    return sorted(
        alerts,
        key=lambda alert: (
            -alert.score,
            alert.utc_time,
            alert.alert_type,
            alert.process_guid,
            alert.image,
        ),
    )


def _event_user(event: SysmonEvent, process_create: ProcessCreateEvent | None) -> str | None:
    return getattr(event, "user", None) or (process_create.user if process_create else None)


def _event_key(event: SysmonEvent) -> str:
    return "|".join(
        [
            str(event.event_id),
            event.timestamp.isoformat(),
            getattr(event, "process_guid", ""),
            getattr(event, "image", ""),
            str(getattr(event, "destination_ip", "")),
            str(getattr(event, "destination_port", "")),
            str(getattr(event, "target_filename", "")),
        ]
    )


def _default_routing_why(alert: Alert) -> str:
    return f"Routed to {alert.queue}: category={alert.category}, confidence={alert.confidence}"


def _apply_role_tags_and_routing(alert: Alert, role_tags: set[str]) -> Alert:
    if role_tags:
        alert.tags = sorted({*alert.tags, *role_tags})
    alert.routing_why = alert.routing_why or _default_routing_why(alert)
    return alert

