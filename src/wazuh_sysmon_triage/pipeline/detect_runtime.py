from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import NetworkConnectEvent, ProcessCreateEvent, SysmonEvent

from .detect_contexts import _build_detection_contexts, _find_process_create, _role_tags_for_event
from .detect_detectors_behavior import _detect_burst_spread, _detect_hot_host_meta_alerts
from .detect_detectors_network import (
    _detect_beacon_like_outbound,
    _detect_lolbin_outbound,
    _detect_suspicious_path_outbound,
)
from .detect_detectors_process import _detect_powershell, _detect_schtasks
from .detect_types import *  # noqa: F401,F403
from .detect_types import DetectionContexts, DetectionRunResult
from .detect_utils import *  # noqa: F401,F403
from .detect_utils import (
    _apply_role_tags_and_routing,
    _basename,
    _event_key,
    _event_user,
    _matches_suppression_rule,
    _rule_name,
    normalize_allowlist_basenames,
    sort_alerts,
)


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

