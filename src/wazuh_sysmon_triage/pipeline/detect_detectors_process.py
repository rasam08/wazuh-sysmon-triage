from __future__ import annotations

import re

from wazuh_sysmon_triage.models.alerts import Alert, has_randomish_token
from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessCreateEvent,
)

from .detect_types import (
    ADVANCED_INJECTION_RE,
    DEV_TOOLING_RE,
    LOLBIN_BASENAMES,
    RULE_METADATA,
    WEB_FETCH_RE,
    AlertCategory,
    AlertConfidence,
    AlertQueue,
)
from .detect_utils import (
    _alert_dedup_key,
    _basename,
    _has_encoded_command_flag,
    _is_microsoft_destination,
    _is_public_ip,
    _score_to_reason,
    _temp_script_write,
)


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
