from __future__ import annotations

import re
from collections.abc import Iterable

from wazuh_sysmon_triage.models.alerts import Alert, FindingKind
from wazuh_sysmon_triage.models.evidence import SourceRef
from wazuh_sysmon_triage.models.findings import EvidenceStrength
from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessAccessEvent,
    ProcessCreateEvent,
    RegistryEvent,
    SysmonEvent,
)

from .detect_types import (
    ADVANCED_INJECTION_RE,
    DEV_TOOLING_RE,
    LOLBIN_BASENAMES,
    RULE_METADATA,
    WEB_FETCH_RE,
    AlertCategory,
    ProcessKey,
)
from .detect_utils import (
    _alert_dedup_key,
    _basename,
    _has_encoded_command_flag,
    _hits_to_reason,
    _is_public_ip,
    _temp_script_write,
)


def _source_refs(events: Iterable[SysmonEvent]) -> list[SourceRef]:
    refs: list[SourceRef] = []
    identities: set[tuple[str, str | None, str | None, str | None]] = set()
    for event in events:
        ref = event.source_ref
        identity = (ref.source_type, ref.index, ref.document_id, ref.raw_digest)
        if identity in identities:
            continue
        identities.add(identity)
        refs.append(ref)
    return refs


def _base_alert(
    *,
    event: ProcessCreateEvent | NetworkConnectEvent | RegistryEvent | ProcessAccessEvent,
    alert_type: str,
    reason: str,
    category: AlertCategory,
    tags: list[str],
    finding_kind: FindingKind = "observed_pattern",
    evidence_strength: EvidenceStrength = EvidenceStrength.DETERMINISTIC,
    evidence_events: Iterable[SysmonEvent] = (),
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
        rule_id=rule_id,
        rule_name=rule_name,
        primary_event_id=primary_event_id,
        alert_type=alert_type,
        category=category,
        finding_kind=finding_kind,
        evidence_strength=evidence_strength,
        reason=reason,
        host_key=event.host_key or "unknown:constructed",
        image=getattr(event, "image", "") or "",
        command_line=command_line,
        parent_image=parent_image,
        destination_ip=destination_ip,
        destination_port=destination_port,
        process_guid=getattr(event, "process_guid", "") or "",
        tags=tags,
        evidence_refs=_source_refs([event, *evidence_events]),
    )


def _detect_powershell(
    event: ProcessCreateEvent,
    *,
    role_tags: set[str],
    networks: list[NetworkConnectEvent],
    files: list[FileCreateEvent],
    children: list[ProcessCreateEvent],
    network_context_by_process: dict[ProcessKey, list[NetworkConnectEvent]],
) -> list[Alert]:
    if _basename(event.image) not in {"powershell.exe", "pwsh.exe"}:
        return []

    cmd = (event.command_line or "").lower()
    alerts: list[Alert] = []

    encoded_or_download_hits: list[str] = []
    if _has_encoded_command_flag(cmd):
        encoded_or_download_hits.append("encoded-command flag")
    if "invoke-expression" in cmd or re.search(r"\biex\b", cmd):
        encoded_or_download_hits.append("Invoke-Expression token")
    if "downloadstring" in cmd:
        encoded_or_download_hits.append("DownloadString token")
    if "frombase64string" in cmd:
        encoded_or_download_hits.append("FromBase64String token")
    if WEB_FETCH_RE.search(cmd):
        encoded_or_download_hits.append("web-fetch command token")

    policy_hits: list[str] = []
    if "-noprofile" in cmd or "-nop" in cmd:
        policy_hits.append("no-profile flag")
    if "-executionpolicy" in cmd and "bypass" in cmd:
        policy_hits.append("execution-policy bypass flags")

    dev_hits: list[str] = []
    if DEV_TOOLING_RE.search(cmd) or DEV_TOOLING_RE.search(event.image or ""):
        dev_hits.append("PowerShellEditorServices or VS Code token")

    reflection_hits: list[str] = []
    if ADVANCED_INJECTION_RE.search(cmd):
        reflection_hits.append("reflection, native API, or named DLL token")

    base_tags = {"powershell", "execution", *role_tags}

    if dev_hits:
        alerts.append(
            _base_alert(
                event=event,
                alert_type="powershell_dev_tooling",
                reason=_hits_to_reason("PowerShell developer-tooling pattern observed", dev_hits),
                category="developer_tooling",
                tags=sorted({*base_tags, "tool:vscode"}),
                command_line=event.command_line,
                parent_image=event.parent_image,
            )
        )

    if policy_hits and not encoded_or_download_hits and not reflection_hits:
        alerts.append(
            _base_alert(
                event=event,
                alert_type="powershell_policy_bypass",
                reason=_hits_to_reason("PowerShell policy-related flags observed", policy_hits),
                category="policy_pattern",
                tags=sorted({*base_tags, "policy:bypass"}),
                command_line=event.command_line,
                parent_image=event.parent_image,
            )
        )

    if encoded_or_download_hits:
        alerts.append(
            _base_alert(
                event=event,
                alert_type="powershell_encoded_or_download_pattern",
                reason=_hits_to_reason(
                    "PowerShell encoded, dynamic, or download pattern observed",
                    encoded_or_download_hits,
                ),
                category="process_behavior",
                tags=sorted({*base_tags, "pattern:encoded_or_download"}),
                command_line=event.command_line,
                parent_image=event.parent_image,
            )
        )

    if reflection_hits:
        alerts.append(
            _base_alert(
                event=event,
                alert_type="powershell_reflection_or_native_api_pattern",
                reason=_hits_to_reason(
                    "PowerShell reflection or native-API pattern observed",
                    reflection_hits,
                ),
                category="process_behavior",
                tags=sorted({*base_tags, "pattern:reflection_or_native_api"}),
                command_line=event.command_line,
                parent_image=event.parent_image,
            )
        )

    has_public_dest = any(_is_public_ip(net.destination_ip) for net in networks)
    has_temp_drop = _temp_script_write(files)
    lolbin_children = [
        child
        for child in children
        if _basename(child.image) in LOLBIN_BASENAMES
        and network_context_by_process.get(
            (child.host_key or "unknown:constructed", child.process_guid)
        )
    ]

    related_evidence: list[SysmonEvent] = []
    context_hits: list[str] = []
    if has_public_dest:
        context_hits.append("same-process public network destination")
        related_evidence.extend(net for net in networks if _is_public_ip(net.destination_ip))
    if has_temp_drop:
        context_hits.append("same-process temporary script or binary creation")
        related_evidence.extend(files)
    if lolbin_children:
        context_hits.append("child LOLBin with network activity")
        related_evidence.extend(lolbin_children)

    if context_hits:
        for alert in alerts:
            if alert.alert_type not in {
                "powershell_encoded_or_download_pattern",
                "powershell_reflection_or_native_api_pattern",
            }:
                continue
            alert.finding_kind = "correlated_pattern"
            alert.evidence_strength = EvidenceStrength.STRONG
            alert.reason = f"{alert.reason}; correlated context: {', '.join(context_hits)}"
            alert.tags = sorted({*alert.tags, "context:multi_event"})
            alert.evidence_refs = _source_refs([event, *related_evidence])

    dedup: dict[tuple[str, str, str, str, int], Alert] = {}
    for alert in alerts:
        dedup.setdefault(_alert_dedup_key(alert), alert)
    return list(dedup.values())


def _detect_schtasks(event: ProcessCreateEvent) -> Alert | None:
    if _basename(event.image) != "schtasks.exe":
        return None

    cmd = (event.command_line or "").lower()
    if "/create" not in cmd:
        return None

    hits = ["/Create flag"]
    if "powershell" in cmd or "cmd /c" in cmd or "\\temp\\" in cmd or "\\appdata\\" in cmd:
        hits.append("task action contains an interpreter or user-writable path")
    if "/ru system" in cmd or "/rl highest" in cmd:
        hits.append("SYSTEM or highest-run-level flag")

    return _base_alert(
        event=event,
        alert_type="scheduled_task_create",
        reason=_hits_to_reason("Scheduled task creation observed", hits),
        category="persistence_behavior",
        tags=["persistence", "scheduled-task"],
        command_line=event.command_line,
        parent_image=event.parent_image,
    )
