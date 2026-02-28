from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, TypedDict

from wazuh_sysmon_triage.models.alerts import Alert, has_randomish_token
from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessCreateEvent,
    SysmonEvent,
)

DEFAULT_ALLOWLIST_BASENAMES = {
    "msmpeng.exe",
    "mpcmdrun.exe",
    "nissrv.exe",
    "mpdefendercoreservice.exe",
    "svchost.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
}

LOLBIN_BASENAMES = {
    "rundll32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

WEB_FETCH_RE = re.compile(r"\b(invoke-webrequest|iwr|wget|curl)\b", flags=re.IGNORECASE)
DEV_TOOLING_RE = re.compile(
    r"powershelleditorservices|start-editorservices|\\\.vscode\\|microsoft vs code|vscode",
    flags=re.IGNORECASE,
)
ENCODED_COMMAND_FLAG_RE = re.compile(
    r"(?<![a-z0-9])-(?:enc|encodedcommand)(?![a-z])",
    flags=re.IGNORECASE,
)
ADVANCED_INJECTION_RE = re.compile(
    r"definedynamicassembly|definepinvokemethod|reflection\.emit|pidgenx\.dll|pkeyhelper\.dll",
    flags=re.IGNORECASE,
)
POLICY_BYPASS_RE = re.compile(r"-noprofile|-nop|-executionpolicy\s+bypass", flags=re.IGNORECASE)
MICROSOFT_IP_PREFIXES = ("13.", "20.", "40.", "52.", "104.", "131.107.", "150.171.")
SCRIPT_EXTENSIONS = (".ps1", ".bat", ".cmd", ".vbs", ".js", ".exe", ".dll")
TEMP_MARKERS = ("\\temp\\", "\\appdata\\local\\temp\\")
USER_WRITABLE_MARKERS = (
    "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\downloads\\",
)
BURST_WINDOW_SECONDS = 120
BURST_MIN_PROCESSES = 6
BEACON_MIN_CONNECTIONS = 3
BEACON_MAX_JITTER_RATIO = 0.35
BEACON_MIN_AVG_SECONDS = 10
BEACON_MAX_AVG_SECONDS = 900
BURST_SUSPICIOUS_BASENAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "schtasks.exe",
    *LOLBIN_BASENAMES,
}

AlertCategory = Literal[
    "malware_execution",
    "c2_outbound",
    "persistence",
    "policy_violation",
    "developer_tooling",
    "unknown",
]
AlertQueue = Literal["soc_malware", "soc_policy", "soc_dev", "soc_info"]
AlertConfidence = Literal["low", "medium", "high"]


class RuleMetadata(TypedDict):
    rule_id: str
    rule_name: str
    primary_event_id: int


RULE_METADATA: dict[str, RuleMetadata] = {
    "powershell_dev_tooling": {
        "rule_id": "BATCAVE-PS-DEV-001",
        "rule_name": "PowerShell Developer Tooling",
        "primary_event_id": 1,
    },
    "powershell_policy_bypass": {
        "rule_id": "BATCAVE-PS-POLICY-001",
        "rule_name": "PowerShell Policy Bypass Pattern",
        "primary_event_id": 1,
    },
    "powershell_obfuscation": {
        "rule_id": "BATCAVE-PS-001",
        "rule_name": "PowerShell Obfuscation / Download",
        "primary_event_id": 1,
    },
    "powershell_advanced_injection": {
        "rule_id": "BATCAVE-PS-ADV-001",
        "rule_name": "PowerShell Advanced Injection",
        "primary_event_id": 1,
    },
    "lolbin_outbound": {
        "rule_id": "BATCAVE-NET-001",
        "rule_name": "LOLBins Outbound",
        "primary_event_id": 3,
    },
    "suspicious_path_outbound": {
        "rule_id": "BATCAVE-NET-002",
        "rule_name": "Suspicious Path Outbound",
        "primary_event_id": 3,
    },
    "persistence_schtasks_create": {
        "rule_id": "BATCAVE-PERSIST-001",
        "rule_name": "Persistence via schtasks /Create",
        "primary_event_id": 1,
    },
    "beacon_like_outbound": {
        "rule_id": "BATCAVE-NET-003",
        "rule_name": "Beacon-like Outbound Pattern",
        "primary_event_id": 3,
    },
    "burst_suspicious_processes": {
        "rule_id": "BATCAVE-BEHAV-001",
        "rule_name": "Burst Suspicious Process Fan-out",
        "primary_event_id": 1,
    },
    "executive_hot_host": {
        "rule_id": "BATCAVE-META-001",
        "rule_name": "Executive Hot Host Risk Accumulation",
        "primary_event_id": 1,
    },
}


@dataclass
class DetectionRunResult:
    alerts: list[Alert]
    suppressed_alerts: int = 0
    suppressed_events: int = 0
    suppression_hits: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionContexts:
    process_creates: dict[str, list[ProcessCreateEvent]]
    network_by_guid: dict[str, list[NetworkConnectEvent]]
    files_by_guid: dict[str, list[FileCreateEvent]]
    children_by_parent: dict[str, list[ProcessCreateEvent]]


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
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "private"
        return "public"
    except ValueError:
        return None


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


def _build_process_context(events: list[SysmonEvent]) -> dict[str, list[ProcessCreateEvent]]:
    by_guid: defaultdict[str, list[ProcessCreateEvent]] = defaultdict(list)
    for event in events:
        if isinstance(event, ProcessCreateEvent):
            by_guid[event.process_guid].append(event)
    for rows in by_guid.values():
        rows.sort(key=lambda row: row.timestamp)
    return dict(by_guid)


def _build_network_context(events: list[SysmonEvent]) -> dict[str, list[NetworkConnectEvent]]:
    by_guid: defaultdict[str, list[NetworkConnectEvent]] = defaultdict(list)
    for event in events:
        if isinstance(event, NetworkConnectEvent):
            by_guid[event.process_guid].append(event)
    for rows in by_guid.values():
        rows.sort(key=lambda row: row.timestamp)
    return dict(by_guid)


def _build_file_context(events: list[SysmonEvent]) -> dict[str, list[FileCreateEvent]]:
    by_guid: defaultdict[str, list[FileCreateEvent]] = defaultdict(list)
    for event in events:
        if isinstance(event, FileCreateEvent) and event.process_guid:
            by_guid[event.process_guid].append(event)
    for rows in by_guid.values():
        rows.sort(key=lambda row: row.timestamp)
    return dict(by_guid)


def _build_children_context(events: list[SysmonEvent]) -> dict[str, list[ProcessCreateEvent]]:
    by_parent: defaultdict[str, list[ProcessCreateEvent]] = defaultdict(list)
    for event in events:
        if isinstance(event, ProcessCreateEvent) and event.parent_process_guid:
            by_parent[event.parent_process_guid].append(event)
    for rows in by_parent.values():
        rows.sort(key=lambda row: row.timestamp)
    return dict(by_parent)


def _build_detection_contexts(events: list[SysmonEvent]) -> DetectionContexts:
    return DetectionContexts(
        process_creates=_build_process_context(events),
        network_by_guid=_build_network_context(events),
        files_by_guid=_build_file_context(events),
        children_by_parent=_build_children_context(events),
    )


def _find_process_create(
    process_creates: dict[str, list[ProcessCreateEvent]],
    process_guid: str,
    ts: datetime,
) -> ProcessCreateEvent | None:
    rows = process_creates.get(process_guid) or []
    if not rows:
        return None
    selected = None
    for row in rows:
        if row.timestamp <= ts:
            selected = row
        else:
            break
    return selected or rows[0]


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


def _role_tags_for_event(event: SysmonEvent, context_roles: dict[str, dict[str, Any]]) -> set[str]:
    if not context_roles:
        return set()

    image = (getattr(event, "image", "") or "").lower()
    user = (getattr(event, "user", "") or "").lower()
    agent_name = (getattr(event, "agent_name", "") or "").lower()
    hostname = (getattr(event, "computer", "") or "").lower()

    tags: set[str] = set()
    for role_name, matcher in context_roles.items():
        if not isinstance(matcher, dict):
            continue
        agent_names = [str(value).lower() for value in matcher.get("agent_names", [])]
        users = [str(value).lower() for value in matcher.get("users", [])]
        hostnames = [str(value).lower() for value in matcher.get("hostnames", [])]
        image_contains = [str(value).lower() for value in matcher.get("process_image_contains", [])]

        matched = False
        if agent_name and agent_name in agent_names:
            matched = True
        if user and user in users:
            matched = True
        if hostname and hostname in hostnames:
            matched = True
        if image and any(piece and piece in image for piece in image_contains):
            matched = True

        if matched:
            if role_name.lower().startswith("developer"):
                tags.add("role:developer")
            else:
                tags.add(f"role:{role_name.lower()}")
    return tags


def _base_alert(
    *,
    event: ProcessCreateEvent | NetworkConnectEvent,
    alert_type: str,
    score: int,
    reason: str,
    category: AlertCategory,
    queue: AlertQueue,
    confidence: AlertConfidence,
    tags: list[str],
    command_line: str | None = None,
    parent_image: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
) -> Alert:
    metadata = RULE_METADATA.get(alert_type)
    rule_id = metadata["rule_id"] if metadata else None
    rule_name = metadata["rule_name"] if metadata else None
    primary_event_id = metadata["primary_event_id"] if metadata else None
    return Alert(
        utc_time=event.timestamp,
        score=max(0, min(score, 100)),
        rule_id=rule_id,
        rule_name=rule_name,
        primary_event_id=primary_event_id,
        alert_type=alert_type,
        category=category,
        queue=queue,
        confidence=confidence,
        reason=reason,
        image=getattr(event, "image", "") or "",
        command_line=command_line,
        parent_image=parent_image,
        destination_ip=destination_ip,
        destination_port=destination_port,
        process_guid=getattr(event, "process_guid", "") or "",
        tags=tags,
        routing_why=f"Routed to {queue}: category={category}, confidence={confidence}",
    )


def _detect_powershell(
    event: ProcessCreateEvent,
    *,
    role_tags: set[str],
    networks: list[NetworkConnectEvent],
    files: list[FileCreateEvent],
    children: list[ProcessCreateEvent],
    network_context_by_guid: dict[str, list[NetworkConnectEvent]],
) -> list[Alert]:
    image_base = _basename(event.image)
    if image_base not in {"powershell.exe", "pwsh.exe"}:
        return []

    cmd = (event.command_line or "").lower()
    alerts: list[Alert] = []

    obfuscation_hits: list[str] = []
    if _has_encoded_command_flag(cmd):
        obfuscation_hits.append("encoded command")
    if "invoke-expression" in cmd or re.search(r"\biex\b", cmd):
        obfuscation_hits.append("Invoke-Expression")
    if "downloadstring" in cmd:
        obfuscation_hits.append("DownloadString")
    if "frombase64string" in cmd:
        obfuscation_hits.append("FromBase64String")
    if WEB_FETCH_RE.search(cmd):
        obfuscation_hits.append("web fetch primitive")

    policy_hits: list[str] = []
    if "-noprofile" in cmd or "-nop" in cmd:
        policy_hits.append("no-profile flag")
    if "-executionpolicy" in cmd and "bypass" in cmd:
        policy_hits.append("execution policy bypass")

    dev_hits: list[str] = []
    if DEV_TOOLING_RE.search(cmd) or DEV_TOOLING_RE.search(event.image or ""):
        dev_hits.append("PowerShellEditorServices / VS Code pattern")

    advanced_hits: list[str] = []
    if ADVANCED_INJECTION_RE.search(cmd):
        advanced_hits.append("advanced reflection/injection pattern")

    base_tags = {"batcave", "powershell", "execution", *role_tags}

    if dev_hits:
        dev_tags = sorted({*base_tags, "tool:vscode"})
        alerts.append(
            _base_alert(
                event=event,
                alert_type="powershell_dev_tooling",
                score=10,
                reason=_score_to_reason("PowerShell developer tooling", dev_hits),
                category="developer_tooling",
                queue="soc_dev",
                confidence="low",
                tags=dev_tags,
                command_line=event.command_line,
                parent_image=event.parent_image,
            )
        )

    if policy_hits and not obfuscation_hits and not advanced_hits:
        policy_tags = sorted({*base_tags, "policy:bypass"})
        alerts.append(
            _base_alert(
                event=event,
                alert_type="powershell_policy_bypass",
                score=30,
                reason=_score_to_reason("PowerShell policy bypass", policy_hits),
                category="policy_violation",
                queue="soc_policy",
                confidence="medium",
                tags=policy_tags,
                command_line=event.command_line,
                parent_image=event.parent_image,
            )
        )

    if obfuscation_hits:
        score = 70 + (15 if len(obfuscation_hits) >= 2 else 0) + (10 if len(obfuscation_hits) >= 3 else 0)
        obfuscation_tags = set(base_tags)
        obfuscation_tags.add("signal:obfuscation")
        alerts.append(
            _base_alert(
                event=event,
                alert_type="powershell_obfuscation",
                score=score,
                reason=_score_to_reason("PowerShell obfuscation/download", obfuscation_hits),
                category="malware_execution",
                queue="soc_malware",
                confidence="high",
                tags=sorted(obfuscation_tags),
                command_line=event.command_line,
                parent_image=event.parent_image,
            )
        )

    if advanced_hits:
        advanced_tags = set(base_tags)
        advanced_tags.add("signal:advanced_injection")
        alert = _base_alert(
            event=event,
            alert_type="powershell_advanced_injection",
            score=55,
            reason=_score_to_reason("PowerShell advanced injection pattern", advanced_hits),
            category="policy_violation",
            queue="soc_policy",
            confidence="medium",
            tags=sorted(advanced_tags),
            command_line=event.command_line,
            parent_image=event.parent_image,
        )

        has_public_non_ms = any(
            _is_public_ip(net.destination_ip) and not _is_microsoft_destination(net.destination_ip)
            for net in networks
        )
        has_temp_drop = _temp_script_write(files)
        has_lolbin_net = any(
            _basename(child.image) in LOLBIN_BASENAMES
            and any(network_context_by_guid.get(child.process_guid, []))
            for child in children
        )
        if has_public_non_ms or has_temp_drop or has_lolbin_net:
            alert.category = "malware_execution"
            alert.queue = "soc_malware"
            alert.confidence = "high"
            alert.score = max(alert.score, 80)
            alert.tags = sorted({*alert.tags, "escalator:advanced_combo"})
            alert.routing_why = "Escalated to soc_malware: advanced injection paired with high-risk behavior"
        alerts.append(alert)

    for alert in alerts:
        has_public_dest = any(_is_public_ip(net.destination_ip) for net in networks)
        has_public_non_ms = any(
            _is_public_ip(net.destination_ip) and not _is_microsoft_destination(net.destination_ip)
            for net in networks
        )
        if has_public_dest:
            alert.tags = sorted({*alert.tags, "dest:public"})
        if any(_is_microsoft_destination(net.destination_ip) for net in networks):
            alert.tags = sorted({*alert.tags, "dest:microsoft_asn"})

        has_lolbin_network_spawn = any(
            _basename(child.image) in LOLBIN_BASENAMES
            and any(network_context_by_guid.get(child.process_guid, []))
            for child in children
        )
        has_temp_drop = _temp_script_write(files)
        escalator_triggered = False
        escalator_reason = None

        if (
            alert.alert_type == "powershell_obfuscation"
            and has_public_non_ms
            and (has_lolbin_network_spawn or has_temp_drop)
        ):
            escalator_triggered = True
            escalator_reason = "Escalated: obfuscation + public non-Microsoft outbound + post-execution risk"
        elif alert.alert_type == "powershell_obfuscation" and has_public_non_ms and has_public_dest:
            escalator_triggered = True
            escalator_reason = "Escalated: encoded/obfuscated PowerShell with public non-Microsoft outbound"

        if escalator_triggered:
            alert.queue = "soc_malware"
            alert.category = "malware_execution"
            alert.confidence = "high"
            alert.score = max(alert.score, 90)
            alert.tags = sorted({*alert.tags, "escalator:critical_combo"})
            alert.routing_why = escalator_reason

        is_developer = "role:developer" in alert.tags
        if is_developer and alert.category == "developer_tooling":
            alert.score = min(alert.score, 15)
            alert.queue = "soc_dev"
            alert.confidence = "low"
            alert.routing_why = (
                alert.routing_why
                or "Routed to soc_dev: developer tooling context with low-risk editor services pattern"
            )
        elif (
            is_developer
            and alert.category == "policy_violation"
            and "escalator:critical_combo" not in alert.tags
            and "escalator:advanced_combo" not in alert.tags
        ):
            alert.score = max(0, alert.score - 5)
            alert.routing_why = (
                alert.routing_why
                or "Routed to soc_policy: policy-relevant behavior on developer context (dampened, not suppressed)"
            )
        else:
            alert.routing_why = (
                alert.routing_why
                or f"Routed to {alert.queue}: category={alert.category}, confidence={alert.confidence}"
            )

    dedup: dict[tuple[str, str, str, str, int], Alert] = {}
    for alert in alerts:
        key = _alert_dedup_key(alert)
        existing = dedup.get(key)
        if existing is None or alert.score > existing.score:
            dedup[key] = alert
    return list(dedup.values())


def _detect_schtasks(event: ProcessCreateEvent) -> Alert | None:
    if _basename(event.image) != "schtasks.exe":
        return None

    cmd = (event.command_line or "").lower()
    if "/create" not in cmd:
        return None

    score = 70
    hits = ["scheduled task creation"]

    if has_randomish_token(event.command_line):
        score += 15
        hits.append("random-ish task token")

    if (
        "powershell" in cmd
        or "cmd /c" in cmd
        or "\\temp\\" in cmd
        or "\\appdata\\" in cmd
    ):
        score += 15
        hits.append("suspicious task action")

    if "/ru system" in cmd or "/rl highest" in cmd:
        score += 10
        hits.append("high-privilege task context")

    return Alert(
        utc_time=event.timestamp,
        score=min(score, 100),
        rule_id=RULE_METADATA["persistence_schtasks_create"]["rule_id"],
        rule_name=RULE_METADATA["persistence_schtasks_create"]["rule_name"],
        primary_event_id=RULE_METADATA["persistence_schtasks_create"]["primary_event_id"],
        alert_type="persistence_schtasks_create",
        category="persistence",
        queue="soc_malware",
        confidence="high",
        reason=_score_to_reason("Suspicious scheduled task persistence", hits),
        image=event.image,
        command_line=event.command_line,
        parent_image=event.parent_image,
        process_guid=event.process_guid,
        tags=["batcave", "persistence", "schtasks"],
    )


def _detect_lolbin_outbound(
    event: NetworkConnectEvent,
    process_create: ProcessCreateEvent | None,
) -> Alert | None:
    if _basename(event.image) not in LOLBIN_BASENAMES:
        return None

    score = 60
    hits = ["LOLBin outbound network connection"]

    if _is_public_ip(event.destination_ip):
        score += 20
        hits.append("public destination")
    if event.destination_port in {80, 443}:
        score += 10
        hits.append("web port")

    return Alert(
        utc_time=event.timestamp,
        score=min(score, 100),
        rule_id=RULE_METADATA["lolbin_outbound"]["rule_id"],
        rule_name=RULE_METADATA["lolbin_outbound"]["rule_name"],
        primary_event_id=RULE_METADATA["lolbin_outbound"]["primary_event_id"],
        alert_type="lolbin_outbound",
        category="c2_outbound",
        queue="soc_malware",
        confidence="high" if _is_public_ip(event.destination_ip) else "medium",
        reason=_score_to_reason("LOLBin outbound traffic", hits),
        image=event.image,
        command_line=process_create.command_line if process_create else None,
        parent_image=process_create.parent_image if process_create else None,
        destination_ip=event.destination_ip,
        destination_port=event.destination_port,
        process_guid=event.process_guid,
        tags=[
            "batcave",
            "lolbin",
            "network",
            "dest:public" if _is_public_ip(event.destination_ip) else "dest:private",
            "dest:microsoft_asn" if _is_microsoft_destination(event.destination_ip) else "dest:non_microsoft",
        ],
    )


def _detect_suspicious_path_outbound(
    event: NetworkConnectEvent,
    process_create: ProcessCreateEvent | None,
) -> Alert | None:
    image_lower = (event.image or "").lower()
    if not any(
        marker in image_lower
        for marker in ("\\appdata\\roaming\\", "\\appdata\\local\\temp\\", "\\programdata\\")
    ):
        return None

    score = 50
    hits = ["process launched from suspicious path"]

    if _is_public_ip(event.destination_ip):
        score += 20
        hits.append("public destination")
    if event.destination_port in {80, 443}:
        score += 10
        hits.append("web port")

    return Alert(
        utc_time=event.timestamp,
        score=min(score, 100),
        rule_id=RULE_METADATA["suspicious_path_outbound"]["rule_id"],
        rule_name=RULE_METADATA["suspicious_path_outbound"]["rule_name"],
        primary_event_id=RULE_METADATA["suspicious_path_outbound"]["primary_event_id"],
        alert_type="suspicious_path_outbound",
        category="policy_violation",
        queue="soc_policy",
        confidence="medium",
        reason=_score_to_reason("Suspicious-path outbound traffic", hits),
        image=event.image,
        command_line=process_create.command_line if process_create else None,
        parent_image=process_create.parent_image if process_create else None,
        destination_ip=event.destination_ip,
        destination_port=event.destination_port,
        process_guid=event.process_guid,
        tags=[
            "batcave",
            "suspicious-path",
            "network",
            "dest:public" if _is_public_ip(event.destination_ip) else "dest:private",
            "dest:microsoft_asn" if _is_microsoft_destination(event.destination_ip) else "dest:non_microsoft",
        ],
    )


def _is_user_writable_path(value: str | None) -> bool:
    lower = (value or "").lower()
    return any(marker in lower for marker in USER_WRITABLE_MARKERS)


def _event_host_label(event: SysmonEvent) -> str:
    return event.agent_name or event.computer or event.agent_id or "unknown-host"


def _host_key(value: str) -> str:
    return value.lower()


def _safe_tag_value(value: str) -> str:
    return re.sub(r"[^a-z0-9_.:-]", "_", value.lower())


def _detect_beacon_like_outbound(contexts: DetectionContexts) -> list[Alert]:
    grouped: defaultdict[tuple[str, str, int], list[NetworkConnectEvent]] = defaultdict(list)
    for guid, rows in contexts.network_by_guid.items():
        for event in rows:
            if not _is_public_ip(event.destination_ip):
                continue
            if _is_microsoft_destination(event.destination_ip):
                continue
            if is_allowlisted_image(event.image):
                continue
            grouped[(guid, event.destination_ip, event.destination_port)].append(event)

    alerts: list[Alert] = []
    for (guid, destination_ip, destination_port), rows in grouped.items():
        if len(rows) < BEACON_MIN_CONNECTIONS:
            continue

        rows = sorted(rows, key=lambda item: item.timestamp)
        intervals: list[float] = []
        for idx in range(1, len(rows)):
            delta = (rows[idx].timestamp - rows[idx - 1].timestamp).total_seconds()
            if delta > 0:
                intervals.append(delta)
        if len(intervals) < BEACON_MIN_CONNECTIONS - 1:
            continue

        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < BEACON_MIN_AVG_SECONDS or avg_interval > BEACON_MAX_AVG_SECONDS:
            continue

        jitter_ratio = (max(intervals) - min(intervals)) / avg_interval if avg_interval else 1.0
        if jitter_ratio > BEACON_MAX_JITTER_RATIO:
            continue

        anchor = rows[-1]
        process_create = _find_process_create(contexts.process_creates, guid, anchor.timestamp)
        score = 65
        score += 15
        if len(rows) >= 5:
            score += 10
        if jitter_ratio <= 0.15:
            score += 5

        reason = (
            "Beacon-like outbound pattern: "
            f"{len(rows)} connections to {destination_ip}:{destination_port} "
            f"every ~{avg_interval:.0f}s (jitter {jitter_ratio * 100:.0f}%)"
        )

        alerts.append(
            _base_alert(
                event=anchor,
                alert_type="beacon_like_outbound",
                score=min(score, 100),
                reason=reason,
                category="c2_outbound",
                queue="soc_malware",
                confidence="high" if len(rows) >= 4 else "medium",
                tags=[
                    "batcave",
                    "beacon",
                    "network",
                    "dest:public",
                    "dest:non_microsoft",
                ],
                command_line=process_create.command_line if process_create else None,
                parent_image=process_create.parent_image if process_create else None,
                destination_ip=destination_ip,
                destination_port=destination_port,
            )
        )

    return alerts


def _is_burst_candidate(event: ProcessCreateEvent) -> bool:
    base = _basename(event.image)
    if base in BURST_SUSPICIOUS_BASENAMES:
        return True
    return _is_user_writable_path(event.image)


def _detect_burst_spread(
    contexts: DetectionContexts,
) -> list[Alert]:
    by_host: defaultdict[str, list[ProcessCreateEvent]] = defaultdict(list)
    host_labels: dict[str, str] = {}

    for rows in contexts.process_creates.values():
        for event in rows:
            if is_allowlisted_image(event.image):
                continue
            if not _is_burst_candidate(event):
                continue
            host_label = _event_host_label(event)
            key = _host_key(host_label)
            host_labels[key] = host_label
            by_host[key].append(event)

    alerts: list[Alert] = []
    for key, rows in by_host.items():
        if len(rows) < BURST_MIN_PROCESSES:
            continue

        rows = sorted(rows, key=lambda item: item.timestamp)
        best_window: tuple[int, int, int] | None = None
        start = 0

        for end in range(len(rows)):
            while (rows[end].timestamp - rows[start].timestamp).total_seconds() > BURST_WINDOW_SECONDS:
                start += 1
            window_rows = rows[start : end + 1]
            process_guids = {item.process_guid for item in window_rows}
            network_backed = sum(
                1 for guid in process_guids if contexts.network_by_guid.get(guid)
            )

            has_burst = len(process_guids) >= BURST_MIN_PROCESSES or (
                len(process_guids) >= 4 and network_backed >= 3
            )
            if not has_burst:
                continue

            if best_window is None:
                best_window = (start, end, network_backed)
                continue

            prev_start, prev_end, prev_network_backed = best_window
            prev_count = len({item.process_guid for item in rows[prev_start : prev_end + 1]})
            current_count = len(process_guids)
            if current_count > prev_count or (
                current_count == prev_count and network_backed > prev_network_backed
            ):
                best_window = (start, end, network_backed)

        if best_window is None:
            continue

        window_start, window_end, network_backed = best_window
        window_rows = rows[window_start : window_end + 1]
        process_guids = {item.process_guid for item in window_rows}
        family_count = len({_basename(item.image) for item in window_rows if _basename(item.image)})
        host_label = host_labels.get(key, "unknown-host")
        anchor = window_rows[-1]
        duration = max(1, int((anchor.timestamp - window_rows[0].timestamp).total_seconds()))

        score = min(100, 55 + len(process_guids) * 5 + min(network_backed, 5) * 4)
        confidence: AlertConfidence = "high" if len(process_guids) >= 8 or network_backed >= 4 else "medium"
        reason = (
            f"Burst suspicious process fan-out on host {host_label}: "
            f"{len(process_guids)} process launches in {duration}s "
            f"across {family_count} families ({network_backed} with outbound traffic)"
        )

        alerts.append(
            _base_alert(
                event=anchor,
                alert_type="burst_suspicious_processes",
                score=score,
                reason=reason,
                category="malware_execution",
                queue="soc_malware",
                confidence=confidence,
                tags=[
                    "batcave",
                    "burst",
                    "fanout",
                    f"host:{_safe_tag_value(host_label)}",
                ],
                command_line=anchor.command_line,
                parent_image=anchor.parent_image,
            )
        )

    return alerts


def _host_label_from_guid(
    process_guid: str,
    contexts: DetectionContexts,
) -> str:
    process_rows = contexts.process_creates.get(process_guid) or []
    if process_rows:
        return _event_host_label(process_rows[0])
    network_rows = contexts.network_by_guid.get(process_guid) or []
    if network_rows:
        return _event_host_label(network_rows[0])
    return "unknown-host"


def _detect_hot_host_meta_alerts(
    alerts: list[Alert],
    contexts: DetectionContexts,
) -> list[Alert]:
    grouped: defaultdict[str, list[Alert]] = defaultdict(list)
    host_labels: dict[str, str] = {}

    for alert in alerts:
        if alert.alert_type == "executive_hot_host":
            continue
        host_label = _host_label_from_guid(alert.process_guid, contexts)
        key = _host_key(host_label)
        host_labels[key] = host_label
        grouped[key].append(alert)

    hot_alerts: list[Alert] = []
    for key, rows in grouped.items():
        if len(rows) < 3:
            continue

        total_score = sum(alert.score for alert in rows)
        high_count = sum(1 for alert in rows if alert.score >= 85)
        unique_types = len({alert.alert_type for alert in rows})
        if total_score < 180 and high_count < 2:
            continue
        if unique_types < 2 and high_count < 2:
            continue

        anchor = max(rows, key=lambda alert: (alert.score, alert.utc_time))
        host_label = host_labels.get(key, "unknown-host")
        metadata = RULE_METADATA["executive_hot_host"]
        score = min(100, 70 + high_count * 10 + min(unique_types * 3, 15))

        hot_alerts.append(
            Alert(
                utc_time=anchor.utc_time,
                score=score,
                rule_id=metadata["rule_id"],
                rule_name=metadata["rule_name"],
                primary_event_id=metadata["primary_event_id"],
                alert_type="executive_hot_host",
                category="malware_execution",
                queue="soc_malware",
                confidence="high",
                reason=(
                    f"Hot host risk accumulation on {host_label}: "
                    f"{len(rows)} alerts, total score {total_score}, "
                    f"{high_count} high-severity, {unique_types} alert types"
                ),
                routing_why="Escalated to soc_malware: cumulative host risk exceeded threshold",
                image=anchor.image,
                command_line=anchor.command_line,
                parent_image=anchor.parent_image,
                destination_ip=anchor.destination_ip,
                destination_port=anchor.destination_port,
                process_guid=anchor.process_guid,
                tags=[
                    "batcave",
                    "meta",
                    "hot-host",
                    f"host:{_safe_tag_value(host_label)}",
                ],
            )
        )

    return hot_alerts


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


def _collect_process_alerts(
    event: ProcessCreateEvent,
    *,
    role_tags: set[str],
    contexts: DetectionContexts,
) -> tuple[list[Alert], ProcessCreateEvent | None]:
    event_alerts: list[Alert] = []
    event_alerts.extend(
        _detect_powershell(
            event,
            role_tags=role_tags,
            networks=contexts.network_by_guid.get(event.process_guid, []),
            files=contexts.files_by_guid.get(event.process_guid, []),
            children=contexts.children_by_parent.get(event.process_guid, []),
            network_context_by_guid=contexts.network_by_guid,
        )
    )

    schtasks_alert = _detect_schtasks(event)
    if schtasks_alert:
        event_alerts.append(_apply_role_tags_and_routing(schtasks_alert, role_tags))

    return event_alerts, event


def _collect_network_alerts(
    event: NetworkConnectEvent,
    *,
    role_tags: set[str],
    contexts: DetectionContexts,
) -> tuple[list[Alert], ProcessCreateEvent | None]:
    event_alerts: list[Alert] = []
    process_create = _find_process_create(
        contexts.process_creates,
        event.process_guid,
        event.timestamp,
    )

    lolbin_alert = _detect_lolbin_outbound(event, process_create)
    if lolbin_alert:
        event_alerts.append(_apply_role_tags_and_routing(lolbin_alert, role_tags))

    path_alert = _detect_suspicious_path_outbound(event, process_create)
    if path_alert:
        event_alerts.append(_apply_role_tags_and_routing(path_alert, role_tags))

    return event_alerts, process_create


def _collect_event_alerts(
    event: SysmonEvent,
    *,
    contexts: DetectionContexts,
    context_roles: dict[str, dict[str, Any]],
) -> tuple[list[Alert], ProcessCreateEvent | None]:
    role_tags = _role_tags_for_event(event, context_roles)
    if isinstance(event, ProcessCreateEvent):
        return _collect_process_alerts(event, role_tags=role_tags, contexts=contexts)
    if isinstance(event, NetworkConnectEvent):
        return _collect_network_alerts(event, role_tags=role_tags, contexts=contexts)
    return [], None


def _matching_suppression_rules(
    rules: list[dict[str, Any]],
    *,
    image: str | None,
    user: str | None,
    destination_ip: str | None,
    destination_port: int | None,
) -> list[dict[str, Any]]:
    return [
        rule
        for rule in rules
        if _matches_suppression_rule(
            rule,
            image=image,
            user=user,
            destination_ip=destination_ip,
            destination_port=destination_port,
        )
    ]


def run_detection(
    events: Iterable[SysmonEvent],
    *,
    allowlist_basenames: Iterable[str] | None = None,
    suppression_rules: list[dict[str, Any]] | None = None,
    allowlist_override_rules: list[dict[str, Any]] | None = None,
    context_roles: dict[str, dict[str, Any]] | None = None,
) -> DetectionRunResult:
    event_list = list(events)
    contexts = _build_detection_contexts(event_list)
    alerts: list[Alert] = []
    allowlist = normalize_allowlist_basenames(allowlist_basenames)
    suppression_hits: dict[str, int] = defaultdict(int)
    suppressed_events: set[str] = set()
    suppressed_alerts = 0

    rules = list(suppression_rules or [])
    allowlist_rules = list(allowlist_override_rules or [])
    active_context_roles = context_roles or {}

    for event in event_list:
        event_alerts, process_create = _collect_event_alerts(
            event,
            contexts=contexts,
            context_roles=active_context_roles,
        )

        image = getattr(event, "image", None)
        image_base = _basename(image)
        if image_base in allowlist:
            suppressed_events.add(_event_key(event))
            if image_base:
                suppression_hits[f"allowlist:{image_base}"] += 1
            if event_alerts:
                suppressed_alerts += len(event_alerts)
            continue

        if not event_alerts:
            continue

        user = _event_user(event, process_create)
        destination_ip = getattr(event, "destination_ip", None)
        destination_port = getattr(event, "destination_port", None)

        override = _matching_suppression_rules(
            allowlist_rules,
            image=image,
            user=user,
            destination_ip=destination_ip,
            destination_port=destination_port,
        )
        if override:
            alerts.extend(event_alerts)
            continue

        matched = _matching_suppression_rules(
            rules,
            image=image,
            user=user,
            destination_ip=destination_ip,
            destination_port=destination_port,
        )
        if matched:
            suppressed_alerts += len(event_alerts)
            suppressed_events.add(_event_key(event))
            for rule in matched:
                suppression_hits[_rule_name(rule)] += len(event_alerts)
            continue

        alerts.extend(event_alerts)

    aggregate_alerts: list[Alert] = []
    aggregate_alerts.extend(_detect_beacon_like_outbound(contexts))
    aggregate_alerts.extend(_detect_burst_spread(contexts))
    if aggregate_alerts:
        alerts.extend(aggregate_alerts)

    alerts.extend(_detect_hot_host_meta_alerts(alerts, contexts))

    return DetectionRunResult(
        alerts=sort_alerts(alerts),
        suppressed_alerts=suppressed_alerts,
        suppressed_events=len(suppressed_events),
        suppression_hits=dict(sorted(suppression_hits.items())),
    )


def detect_alerts(
    events: Iterable[SysmonEvent],
    allowlist_basenames: Iterable[str] | None = None,
    context_roles: dict[str, dict[str, Any]] | None = None,
) -> list[Alert]:
    return run_detection(
        events,
        allowlist_basenames=allowlist_basenames,
        context_roles=context_roles,
    ).alerts


def filter_alerts(alerts: Iterable[Alert], min_score: int) -> list[Alert]:
    return [alert for alert in sort_alerts(alerts) if alert.score >= min_score]
