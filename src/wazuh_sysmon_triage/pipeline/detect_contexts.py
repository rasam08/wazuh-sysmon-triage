from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, TypeVar

from wazuh_sysmon_triage.models.sysmon import (
    DnsQueryEvent,
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessAccessEvent,
    ProcessCreateEvent,
    ProcessLinkedEvent,
    RegistryEvent,
    SysmonEvent,
)

from .detect_types import DetectionContexts, ProcessKey

EventT = TypeVar(
    "EventT",
    ProcessCreateEvent,
    NetworkConnectEvent,
    FileCreateEvent,
    RegistryEvent,
    DnsQueryEvent,
    ProcessAccessEvent,
)


def _process_key(event: ProcessLinkedEvent, guid: str | None = None) -> ProcessKey:
    return (event.host_key or "unknown:constructed", guid or event.process_guid)


def _group_by_process(  # noqa: UP047 -- project supports Python versions before PEP 695
    events: list[EventT],
) -> dict[ProcessKey, list[EventT]]:
    grouped: defaultdict[ProcessKey, list[EventT]] = defaultdict(list)
    for event in events:
        grouped[_process_key(event)].append(event)
    for rows in grouped.values():
        rows.sort(key=lambda row: row.timestamp)
    return dict(grouped)


def _build_children_context(
    events: list[SysmonEvent],
) -> dict[ProcessKey, list[ProcessCreateEvent]]:
    grouped: defaultdict[ProcessKey, list[ProcessCreateEvent]] = defaultdict(list)
    for event in events:
        if isinstance(event, ProcessCreateEvent) and event.parent_process_guid:
            grouped[_process_key(event, event.parent_process_guid)].append(event)
    for rows in grouped.values():
        rows.sort(key=lambda row: row.timestamp)
    return dict(grouped)


def _build_detection_contexts(events: list[SysmonEvent]) -> DetectionContexts:
    return DetectionContexts(
        process_creates=_group_by_process(
            [event for event in events if isinstance(event, ProcessCreateEvent)]
        ),
        network_by_process=_group_by_process(
            [event for event in events if isinstance(event, NetworkConnectEvent)]
        ),
        files_by_process=_group_by_process(
            [event for event in events if isinstance(event, FileCreateEvent)]
        ),
        registry_by_process=_group_by_process(
            [event for event in events if isinstance(event, RegistryEvent)]
        ),
        dns_by_process=_group_by_process(
            [event for event in events if isinstance(event, DnsQueryEvent)]
        ),
        process_access_by_source=_group_by_process(
            [event for event in events if isinstance(event, ProcessAccessEvent)]
        ),
        children_by_parent=_build_children_context(events),
    )


def _find_process_create(
    process_creates: dict[ProcessKey, list[ProcessCreateEvent]],
    host_key: str,
    process_guid: str,
    ts: datetime,
) -> ProcessCreateEvent | None:
    rows = process_creates.get((host_key, process_guid)) or []
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
