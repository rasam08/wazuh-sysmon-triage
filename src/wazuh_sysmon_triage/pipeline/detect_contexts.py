from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessCreateEvent,
    SysmonEvent,
)

from .detect_types import DetectionContexts


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

