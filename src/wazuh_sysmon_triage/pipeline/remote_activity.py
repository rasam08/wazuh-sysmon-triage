from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta
from typing import Literal

from wazuh_sysmon_triage.models.findings import EvidenceStrength, RemoteActivityLead
from wazuh_sysmon_triage.models.sysmon import (
    RemoteLogonEvent,
    ScheduledTaskCreatedEvent,
    ServiceInstallEvent,
    SysmonEvent,
)

REMOTE_LOGON_TYPES = {3, 10}
REMOTE_ACTION_WINDOW = timedelta(minutes=15)
RemoteActionEvent = ServiceInstallEvent | ScheduledTaskCreatedEvent
SourceHostResolution = Literal[
    "exact_agent_ip",
    "exact_host_name",
    "ambiguous",
    "unresolved",
]


def _text_key(value: str | None) -> str:
    return (value or "").strip().casefold()


def _ip_key(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or text == "-":
        return None
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return text.casefold()
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def _host_name_keys(event: SysmonEvent) -> set[str]:
    keys: set[str] = set()
    for value in (event.computer, event.agent_name):
        key = _text_key(value)
        if not key:
            continue
        keys.add(key)
        keys.add(key.split(".", maxsplit=1)[0])
    return keys


def _account_key(domain: str | None, user: str | None) -> str:
    user_key = _text_key(user)
    domain_key = _text_key(domain)
    return f"{domain_key}\\{user_key}" if domain_key else user_key


def _usable_logon_id(value: str | None) -> str | None:
    key = _text_key(value)
    if key in {"", "-", "0", "0x0"}:
        return None
    return key


def _action_account(action: RemoteActionEvent) -> str:
    return _account_key(action.subject_domain_name, action.subject_user_name)


def _action_resource(action: RemoteActionEvent) -> tuple[str, str | None]:
    if isinstance(action, ServiceInstallEvent):
        return action.service_name, action.service_file_name
    return action.task_name, action.task_content


def _resolve_source_host(
    logon: RemoteLogonEvent,
    events: list[SysmonEvent],
) -> tuple[str | None, SourceHostResolution]:
    target_host = logon.host_key or "unknown:constructed"
    source_ip = _ip_key(logon.source_ip)
    ip_candidates = {
        event.host_key or "unknown:constructed"
        for event in events
        if (event.host_key or "unknown:constructed") != target_host
        and source_ip is not None
        and _ip_key(event.agent_ip) == source_ip
    }
    if len(ip_candidates) == 1:
        return next(iter(ip_candidates)), "exact_agent_ip"
    if len(ip_candidates) > 1:
        return None, "ambiguous"

    workstation = _text_key(logon.workstation_name)
    if workstation and workstation != "-":
        name_candidates = {
            event.host_key or "unknown:constructed"
            for event in events
            if (event.host_key or "unknown:constructed") != target_host
            and workstation in _host_name_keys(event)
        }
        if len(name_candidates) == 1:
            return next(iter(name_candidates)), "exact_host_name"
        if len(name_candidates) > 1:
            return None, "ambiguous"
    return None, "unresolved"


def correlate_remote_activity(events: Iterable[SysmonEvent]) -> list[RemoteActivityLead]:
    """Relate remote logons to later service/task creation without asserting maliciousness."""
    event_list = sorted(events, key=lambda event: event.timestamp)
    logons_by_host: defaultdict[str, list[RemoteLogonEvent]] = defaultdict(list)
    actions: list[RemoteActionEvent] = []
    for event in event_list:
        if isinstance(event, RemoteLogonEvent) and event.logon_type in REMOTE_LOGON_TYPES:
            logons_by_host[event.host_key or "unknown:constructed"].append(event)
        elif isinstance(event, (ServiceInstallEvent, ScheduledTaskCreatedEvent)):
            actions.append(event)

    leads: list[RemoteActivityLead] = []
    for action in actions:
        target_host = action.host_key or "unknown:constructed"
        action_account = _action_account(action)
        candidates: list[tuple[int, float, RemoteLogonEvent, str]] = []
        for logon in logons_by_host.get(target_host, []):
            delta = action.timestamp - logon.timestamp
            if delta < timedelta(0) or delta > REMOTE_ACTION_WINDOW:
                continue
            target_logon_id = _usable_logon_id(logon.target_logon_id)
            subject_logon_id = _usable_logon_id(action.subject_logon_id)
            exact_logon_id = bool(
                target_logon_id
                and subject_logon_id
                and target_logon_id == subject_logon_id
            )
            exact_account = _account_key(
                logon.target_domain_name, logon.target_user_name
            ) == action_account
            if not exact_logon_id and not exact_account:
                continue
            match_basis = "exact_logon_id" if exact_logon_id else "exact_account"
            candidates.append(
                (0 if exact_logon_id else 1, delta.total_seconds(), logon, match_basis)
            )

        if not candidates:
            continue
        _rank, delta_seconds, logon, match_basis = min(
            candidates, key=lambda item: (item[0], item[1], item[2].timestamp)
        )
        strength = (
            EvidenceStrength.STRONG
            if match_basis == "exact_logon_id"
            else EvidenceStrength.CIRCUMSTANTIAL
        )
        source_host, resolution = _resolve_source_host(logon, event_list)
        resource, details = _action_resource(action)
        action_type: Literal["service_install", "scheduled_task_created"] = (
            "service_install"
            if isinstance(action, ServiceInstallEvent)
            else "scheduled_task_created"
        )
        action_label = (
            "service installation"
            if isinstance(action, ServiceInstallEvent)
            else "scheduled-task creation"
        )
        join_reason = (
            "TargetLogonId exactly matches SubjectLogonId"
            if match_basis == "exact_logon_id"
            else "the target and subject account names match, but the logon IDs do not"
        )
        source_reason = (
            f" Source host {source_host} matched the recorded source by "
            f"{'agent IP' if resolution == 'exact_agent_ip' else 'host name'}."
            if source_host
            else " The recorded source could not be resolved to exactly one collected host."
        )
        reason = (
            f"Security EID 4624 logon type {logon.logon_type} preceded Security EID "
            f"{action.event_id} {action_label} by {int(delta_seconds)} seconds on the same "
            f"host; {join_reason}.{source_reason} This is a remote-activity lead, not proof "
            "of malicious lateral movement."
        )
        leads.append(
            RemoteActivityLead(
                target_host_key=target_host,
                source_host_key=source_host,
                source_host_resolution=resolution,
                source_ip=logon.source_ip,
                source_port=logon.source_port,
                workstation_name=logon.workstation_name,
                account=logon.user,
                logon_type=logon.logon_type,
                logon_id=logon.target_logon_id,
                logon_at=logon.timestamp,
                action_at=action.timestamp,
                action_event_id=action.event_id,
                action_type=action_type,
                action_resource=resource,
                action_details=details,
                evidence_strength=strength,
                reason=reason,
                evidence_refs=[logon.source_ref, action.source_ref],
            )
        )

    return sorted(
        leads,
        key=lambda lead: (
            lead.action_at,
            lead.target_host_key,
            lead.action_event_id,
            lead.action_resource,
        ),
    )
