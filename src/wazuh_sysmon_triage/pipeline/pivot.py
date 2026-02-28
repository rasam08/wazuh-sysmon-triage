from __future__ import annotations

import fnmatch
import os
import re
from collections import defaultdict
from datetime import timedelta
from typing import Any

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessCreateEvent,
    SysmonEvent,
)
from wazuh_sysmon_triage.output_schema import OUTPUT_SCHEMA_VERSION


def _event_fingerprint(event: SysmonEvent) -> tuple[Any, ...]:
    return (
        event.event_id,
        event.timestamp,
        getattr(event, "process_guid", ""),
        getattr(event, "process_id", None),
        getattr(event, "image", ""),
        getattr(event, "destination_ip", ""),
        getattr(event, "destination_port", None),
        getattr(event, "target_filename", ""),
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
    if not value:
        return None
    if value.startswith("10.") or value.startswith("192.168."):
        return "private"
    if value.startswith("172."):
        parts = value.split(".")
        if len(parts) >= 2 and 16 <= int(parts[1]) <= 31:
            return "private"
    if value.startswith("127."):
        return "private"
    return "public"


def _basename(path: str | None) -> str:
    if not path:
        return ""
    return os.path.basename(path).lower()


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
    by_guid: dict[str, list[ProcessCreateEvent]] = defaultdict(list)
    children_by_parent: dict[str, list[ProcessCreateEvent]] = defaultdict(list)
    for event in process_events:
        by_guid[event.process_guid].append(event)
        if event.parent_process_guid:
            children_by_parent[event.parent_process_guid].append(event)

    for rows in by_guid.values():
        rows.sort(key=lambda row: row.timestamp)
    for rows in children_by_parent.values():
        rows.sort(key=lambda row: row.timestamp)

    bundles: list[dict[str, Any]] = []
    suppression_rules = suppression_rules or []
    allowlist_override = allowlist_override or []
    normalized_allowlist = {
        _basename(value)
        for value in (allowlist_basenames or [])
        if _basename(value)
    }

    for alert in alerts:
        process_rows = by_guid.get(alert.process_guid, [])
        anchor: SysmonEvent | None = None
        if process_rows:
            if alert.primary_event_id == 1:
                anchor = min(
                    process_rows,
                    key=lambda row: abs((row.timestamp - alert.utc_time).total_seconds()),
                )
        if not anchor:
            candidates = [
                event
                for event in events
                if getattr(event, "process_guid", None) == alert.process_guid
                and (
                    alert.primary_event_id is None
                    or event.event_id == alert.primary_event_id
                )
            ]
            if candidates:
                anchor = min(candidates, key=lambda row: abs((row.timestamp - alert.utc_time).total_seconds()))
        if not anchor:
            continue

        ancestry: list[ProcessCreateEvent] = []
        current = anchor if isinstance(anchor, ProcessCreateEvent) else None
        depth = 0
        while current and current.parent_process_guid and depth < max_ancestry_depth:
            parent_rows = by_guid.get(current.parent_process_guid) or []
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
                for proc in children_by_parent.get(anchor.parent_process_guid, [])
                if sibling_start <= proc.timestamp <= sibling_end and proc.process_guid != anchor.process_guid
            ]

        tree_guids: set[str] = {alert.process_guid}
        stack = [alert.process_guid]
        while stack:
            guid = stack.pop()
            for child in children_by_parent.get(guid, []):
                if child.process_guid in tree_guids:
                    continue
                tree_guids.add(child.process_guid)
                stack.append(child.process_guid)

        net_start = anchor.timestamp - timedelta(minutes=5)
        net_end = anchor.timestamp + timedelta(minutes=5)

        files = [
            event
            for event in events
            if isinstance(event, FileCreateEvent) and event.process_guid in tree_guids
        ]
        network = [
            event
            for event in events
            if isinstance(event, NetworkConnectEvent)
            and event.process_guid in tree_guids
            and net_start <= event.timestamp <= net_end
        ]
        related_processes = [
            event
            for event in process_events
            if event.process_guid in tree_guids and event.process_guid != alert.process_guid
        ]

        all_related: list[SysmonEvent] = []
        seen: set[tuple[Any, ...]] = set()
        for row in [anchor, *ancestry, *siblings, *related_processes, *files, *network]:
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
                "score": alert.score,
                "alert_type": alert.alert_type,
                "primary_event_id": alert.primary_event_id,
                "utc_time": alert.utc_time.isoformat().replace("+00:00", "Z"),
                "process_guid": alert.process_guid,
                "reason": alert.reason,
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
                "network_connections": len(network),
            },
            "process_ancestry": [_serialize_event(event) for event in ancestry],
            "sibling_spawns": [_serialize_event(event) for event in siblings],
            "related_processes": [_serialize_event(event) for event in related_processes],
            "file_artifacts": [_serialize_event(event) for event in files],
            "network_connections": [_serialize_event(event) for event in network],
            "suppression_context": {
                "suppressed_related_event_count": suppressed_count,
                "matched_rules": suppressed_rules,
            },
        }
        bundles.append(bundle)

    return bundles
