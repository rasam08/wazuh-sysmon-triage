from __future__ import annotations

import fnmatch
import re
from collections import defaultdict
from datetime import timedelta
from typing import Any

from wazuh_sysmon_triage.models.alerts import Alert
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
from wazuh_sysmon_triage.output_schema import OUTPUT_SCHEMA_VERSION
from wazuh_sysmon_triage.pipeline.network_utils import destination_class
from wazuh_sysmon_triage.windows_paths import windows_basename


def _event_fingerprint(event: SysmonEvent) -> tuple[Any, ...]:
    return (
        event.host_key,
        event.event_id,
        event.timestamp,
        getattr(event, "process_guid", ""),
        getattr(event, "process_id", None),
        getattr(event, "image", ""),
        getattr(event, "destination_ip", ""),
        getattr(event, "destination_port", None),
        getattr(event, "target_filename", ""),
        getattr(event, "target_object", ""),
        getattr(event, "query_name", ""),
        getattr(event, "target_process_guid", ""),
        getattr(event, "granted_access", ""),
        getattr(event, "target_logon_id", ""),
        getattr(event, "subject_logon_id", ""),
        getattr(event, "service_name", ""),
        getattr(event, "task_name", ""),
        getattr(event, "event_type", ""),
    )


def _serialize_event(event: SysmonEvent) -> dict[str, Any]:
    payload = event.model_dump(mode="json")
    payload["timestamp"] = event.timestamp.isoformat().replace("+00:00", "Z")
    return payload


def _matches_rule(
    rule: dict[str, Any],
    *,
    image: str | None,
    user: str | None,
    destination_ip: str | None,
    destination_port: int | None,
    destination_class: str | None,
) -> bool:
    if rule.get("enabled") is False:
        return False

    image_glob = rule.get("image_glob")
    if image_glob and not (image and fnmatch.fnmatch(image.lower(), str(image_glob).lower())):
        return False

    image_regex = rule.get("image_regex")
    if image_regex:
        if not image:
            return False
        try:
            if not re.search(str(image_regex), image, flags=re.IGNORECASE):
                return False
        except re.error:
            return False

    expected_user = rule.get("user")
    if expected_user and (not user or user.lower() != str(expected_user).lower()):
        return False

    expected_ports = rule.get("destination_ports") or []
    if expected_ports and destination_port not in {int(port) for port in expected_ports}:
        return False

    expected_class = rule.get("destination_class")
    if expected_class and destination_class != expected_class:
        return False

    return True


def _destination_class(value: str | None) -> str | None:
    return destination_class(value)


def _basename(path: str | None) -> str:
    return windows_basename(path)


def _suppression_summary(
    events: list[SysmonEvent],
    suppression_rules: list[dict[str, Any]],
    allowlist_override: list[dict[str, Any]],
    allowlist_basenames: set[str],
) -> tuple[int, list[str]]:
    matched_rules: set[str] = set()
    count = 0

    for event in events:
        image = getattr(event, "image", None)
        user = getattr(event, "user", None)
        destination_ip = getattr(event, "destination_ip", None)
        destination_port = getattr(event, "destination_port", None)
        destination_class = _destination_class(destination_ip)

        if any(
            _matches_rule(
                allow,
                image=image,
                user=user,
                destination_ip=destination_ip,
                destination_port=destination_port,
                destination_class=destination_class,
            )
            for allow in allowlist_override
        ):
            continue

        image_base = _basename(image)
        if image_base and image_base in allowlist_basenames:
            count += 1
            matched_rules.add(f"allowlist:{image_base}")
            continue

        hit = [
            rule
            for rule in suppression_rules
            if _matches_rule(
                rule,
                image=image,
                user=user,
                destination_ip=destination_ip,
                destination_port=destination_port,
                destination_class=destination_class,
            )
        ]
        if not hit:
            continue
        count += 1
        for rule in hit:
            matched_rules.add(str(rule.get("name") or "unnamed_suppression"))

    return count, sorted(matched_rules)


def assign_alert_ids(alerts: list[Alert]) -> list[Alert]:
    for idx, alert in enumerate(alerts, start=1):
        alert.alert_id = f"A{idx:03d}"
    return alerts


def build_pivot_bundles(
    alerts: list[Alert],
    events: list[SysmonEvent],
    *,
    max_ancestry_depth: int = 5,
    suppression_rules: list[dict[str, Any]] | None = None,
    allowlist_override: list[dict[str, Any]] | None = None,
    allowlist_basenames: list[str] | None = None,
) -> list[dict[str, Any]]:
    process_events = [event for event in events if isinstance(event, ProcessCreateEvent)]
    by_process: dict[tuple[str, str], list[ProcessCreateEvent]] = defaultdict(list)
    children_by_parent: dict[tuple[str, str], list[ProcessCreateEvent]] = defaultdict(list)
    for event in process_events:
        host_key = event.host_key or "unknown:constructed"
        by_process[(host_key, event.process_guid)].append(event)
        if event.parent_process_guid:
            children_by_parent[(host_key, event.parent_process_guid)].append(event)

    for rows in by_process.values():
        rows.sort(key=lambda row: row.timestamp)
    for rows in children_by_parent.values():
        rows.sort(key=lambda row: row.timestamp)

    bundles: list[dict[str, Any]] = []
    suppression_rules = suppression_rules or []
    allowlist_override = allowlist_override or []
    normalized_allowlist = {
        _basename(value) for value in (allowlist_basenames or []) if _basename(value)
    }

    for alert in alerts:
        process_key = (alert.host_key, alert.process_guid)
        process_rows = by_process.get(process_key, []) if alert.process_guid else []
        anchor: SysmonEvent | None = None
        if process_rows:
            if alert.primary_event_id == 1:
                anchor = min(
                    process_rows,
                    key=lambda row: abs((row.timestamp - alert.utc_time).total_seconds()),
                )
        if not anchor and alert.process_guid:
            candidates = [
                event
                for event in events
                if (event.host_key or "unknown:constructed") == alert.host_key
                and getattr(event, "process_guid", None) == alert.process_guid
                and (alert.primary_event_id is None or event.event_id == alert.primary_event_id)
            ]
            if candidates:
                anchor = min(
                    candidates,
                    key=lambda row: abs((row.timestamp - alert.utc_time).total_seconds()),
                )
        if not anchor and not alert.process_guid:
            candidates = [
                event
                for event in events
                if (event.host_key or "unknown:constructed") == alert.host_key
                and (alert.primary_event_id is None or event.event_id == alert.primary_event_id)
            ]
            if candidates:
                anchor = min(
                    candidates,
                    key=lambda row: abs((row.timestamp - alert.utc_time).total_seconds()),
                )
        if not anchor:
            continue

        ancestry: list[ProcessCreateEvent] = []
        current = anchor if isinstance(anchor, ProcessCreateEvent) else None
        depth = 0
        while current and current.parent_process_guid and depth < max_ancestry_depth:
            parent_rows = (
                by_process.get(
                    (current.host_key or "unknown:constructed", current.parent_process_guid)
                )
                or []
            )
            if not parent_rows:
                break
            parent = parent_rows[-1]
            ancestry.append(parent)
            current = parent
            depth += 1

        sibling_start = anchor.timestamp - timedelta(minutes=2)
        sibling_end = anchor.timestamp + timedelta(minutes=2)
        siblings: list[ProcessCreateEvent] = []
        if isinstance(anchor, ProcessCreateEvent) and anchor.parent_process_guid:
            siblings = [
                proc
                for proc in children_by_parent.get(
                    (anchor.host_key or "unknown:constructed", anchor.parent_process_guid),
                    [],
                )
                if sibling_start <= proc.timestamp <= sibling_end
                and proc.process_guid != anchor.process_guid
            ]

        tree_processes: set[tuple[str, str]] = {process_key} if alert.process_guid else set()
        stack = [process_key] if alert.process_guid else []
        while stack:
            parent_key = stack.pop()
            for child in children_by_parent.get(parent_key, []):
                child_key = (child.host_key or "unknown:constructed", child.process_guid)
                if child_key in tree_processes:
                    continue
                tree_processes.add(child_key)
                stack.append(child_key)

        net_start = anchor.timestamp - timedelta(minutes=5)
        net_end = anchor.timestamp + timedelta(minutes=5)

        files = [
            event
            for event in events
            if isinstance(event, FileCreateEvent)
            and (event.host_key or "unknown:constructed", event.process_guid) in tree_processes
            and net_start <= event.timestamp <= net_end
        ]
        file_deletions = [
            event
            for event in events
            if isinstance(event, FileDeleteEvent)
            and (event.host_key or "unknown:constructed", event.process_guid) in tree_processes
            and net_start <= event.timestamp <= net_end
        ]
        network = [
            event
            for event in events
            if isinstance(event, NetworkConnectEvent)
            and (event.host_key or "unknown:constructed", event.process_guid) in tree_processes
            and net_start <= event.timestamp <= net_end
        ]
        registry = [
            event
            for event in events
            if isinstance(event, RegistryEvent)
            and (event.host_key or "unknown:constructed", event.process_guid) in tree_processes
            and net_start <= event.timestamp <= net_end
        ]
        dns = [
            event
            for event in events
            if isinstance(event, DnsQueryEvent)
            and (event.host_key or "unknown:constructed", event.process_guid) in tree_processes
            and net_start <= event.timestamp <= net_end
        ]
        process_access = [
            event
            for event in events
            if isinstance(event, ProcessAccessEvent)
            and (event.host_key or "unknown:constructed", event.process_guid) in tree_processes
            and net_start <= event.timestamp <= net_end
        ]
        process_terminations = [
            event
            for event in events
            if isinstance(event, ProcessTerminateEvent)
            and (event.host_key or "unknown:constructed", event.process_guid) in tree_processes
            and net_start <= event.timestamp <= net_end
        ]
        native_start = anchor.timestamp - timedelta(minutes=15)
        native_end = anchor.timestamp + timedelta(minutes=2)
        authentication = [
            event
            for event in events
            if isinstance(event, RemoteLogonEvent)
            and (event.host_key or "unknown:constructed") == alert.host_key
            and native_start <= event.timestamp <= native_end
        ]
        service_installs = [
            event
            for event in events
            if isinstance(event, ServiceInstallEvent)
            and (event.host_key or "unknown:constructed") == alert.host_key
            and native_start <= event.timestamp <= native_end
        ]
        scheduled_tasks = [
            event
            for event in events
            if isinstance(event, ScheduledTaskCreatedEvent)
            and (event.host_key or "unknown:constructed") == alert.host_key
            and native_start <= event.timestamp <= native_end
        ]
        related_processes = [
            event
            for event in process_events
            if (event.host_key or "unknown:constructed", event.process_guid) in tree_processes
            and (event.host_key or "unknown:constructed", event.process_guid) != process_key
        ]

        all_related: list[SysmonEvent] = []
        seen: set[tuple[Any, ...]] = set()
        for row in [
            anchor,
            *ancestry,
            *siblings,
            *related_processes,
            *files,
            *file_deletions,
            *network,
            *registry,
            *dns,
            *process_access,
            *process_terminations,
            *authentication,
            *service_installs,
            *scheduled_tasks,
        ]:
            fp = _event_fingerprint(row)
            if fp in seen:
                continue
            seen.add(fp)
            all_related.append(row)

        suppressed_count, suppressed_rules = _suppression_summary(
            all_related,
            suppression_rules=suppression_rules,
            allowlist_override=allowlist_override,
            allowlist_basenames=normalized_allowlist,
        )
        alert.suppressed_related_count = suppressed_count
        alert.suppressed_related_rules = suppressed_rules

        bundle = {
            "schema_version": OUTPUT_SCHEMA_VERSION,
            "alert": {
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "alert_type": alert.alert_type,
                "category": alert.category,
                "finding_kind": alert.finding_kind,
                "evidence_strength": alert.evidence_strength.value,
                "primary_event_id": alert.primary_event_id,
                "utc_time": alert.utc_time.isoformat().replace("+00:00", "Z"),
                "host_key": alert.host_key,
                "process_guid": alert.process_guid,
                "source_host_key": alert.source_host_key,
                "source_ip": alert.source_ip,
                "source_port": alert.source_port,
                "reason": alert.reason,
                "evidence_refs": [ref.model_dump(mode="json") for ref in alert.evidence_refs],
            },
            "anchor_event": _serialize_event(anchor),
            "pivot_window": {
                "sibling_window": {
                    "start": sibling_start.isoformat().replace("+00:00", "Z"),
                    "end": sibling_end.isoformat().replace("+00:00", "Z"),
                },
                "network_window": {
                    "start": net_start.isoformat().replace("+00:00", "Z"),
                    "end": net_end.isoformat().replace("+00:00", "Z"),
                },
                "ancestry_depth_limit": max_ancestry_depth,
            },
            "counts": {
                "ancestry": len(ancestry),
                "siblings": len(siblings),
                "related_processes": len(related_processes),
                "file_artifacts": len(files),
                "file_deletions": len(file_deletions),
                "network_connections": len(network),
                "registry_events": len(registry),
                "dns_queries": len(dns),
                "process_access_events": len(process_access),
                "process_terminations": len(process_terminations),
                "authentication_events": len(authentication),
                "service_installs": len(service_installs),
                "scheduled_task_creations": len(scheduled_tasks),
            },
            "process_ancestry": [_serialize_event(event) for event in ancestry],
            "sibling_spawns": [_serialize_event(event) for event in siblings],
            "related_processes": [_serialize_event(event) for event in related_processes],
            "file_artifacts": [_serialize_event(event) for event in files],
            "file_deletions": [_serialize_event(event) for event in file_deletions],
            "network_connections": [_serialize_event(event) for event in network],
            "registry_activity": [_serialize_event(event) for event in registry],
            "dns_activity": [_serialize_event(event) for event in dns],
            "process_access_activity": [_serialize_event(event) for event in process_access],
            "process_terminations": [_serialize_event(event) for event in process_terminations],
            "authentication_activity": [_serialize_event(event) for event in authentication],
            "service_install_activity": [
                _serialize_event(event) for event in service_installs
            ],
            "scheduled_task_activity": [_serialize_event(event) for event in scheduled_tasks],
            "suppression_context": {
                "suppressed_related_event_count": suppressed_count,
                "matched_rules": suppressed_rules,
            },
        }
        bundles.append(bundle)

    return bundles
