from __future__ import annotations

from collections import defaultdict

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.findings import EvidenceStrength
from wazuh_sysmon_triage.models.sysmon import NetworkConnectEvent, ProcessCreateEvent

from .detect_contexts import _find_process_create
from .detect_detectors_process import _base_alert
from .detect_types import (
    BEACON_MAX_AVG_SECONDS,
    BEACON_MAX_JITTER_RATIO,
    BEACON_MIN_AVG_SECONDS,
    BEACON_MIN_CONNECTIONS,
    DetectionContexts,
)
from .detect_utils import (
    _basename,
    _hits_to_reason,
    _is_public_ip,
    is_allowlisted_image,
)


def _detect_lolbin_outbound(
    event: NetworkConnectEvent,
    process_create: ProcessCreateEvent | None,
) -> Alert | None:
    from .detect_types import LOLBIN_BASENAMES

    if _basename(event.image) not in LOLBIN_BASENAMES:
        return None

    hits = ["LOLBin image made a network connection"]
    if _is_public_ip(event.destination_ip):
        hits.append("public destination")
    if event.destination_port in {80, 443}:
        hits.append("HTTP(S) destination port")

    return _base_alert(
        event=event,
        alert_type="lolbin_outbound",
        reason=_hits_to_reason("LOLBin network activity observed", hits),
        category="network_behavior",
        tags=["lolbin", "network"],
        command_line=process_create.command_line if process_create else None,
        parent_image=process_create.parent_image if process_create else None,
        destination_ip=event.destination_ip,
        destination_port=event.destination_port,
        evidence_events=[process_create] if process_create else [],
    )


def _detect_user_writable_path_outbound(
    event: NetworkConnectEvent,
    process_create: ProcessCreateEvent | None,
) -> Alert | None:
    image_lower = (event.image or "").lower()
    if not any(
        marker in image_lower
        for marker in ("\\appdata\\roaming\\", "\\appdata\\local\\temp\\", "\\programdata\\")
    ):
        return None

    hits = ["image path is in a user-writable location"]
    if _is_public_ip(event.destination_ip):
        hits.append("public destination")
    if event.destination_port in {80, 443}:
        hits.append("HTTP(S) destination port")

    return _base_alert(
        event=event,
        alert_type="user_writable_path_outbound",
        reason=_hits_to_reason("User-writable-path network activity observed", hits),
        category="network_behavior",
        tags=["user-writable-path", "network"],
        command_line=process_create.command_line if process_create else None,
        parent_image=process_create.parent_image if process_create else None,
        destination_ip=event.destination_ip,
        destination_port=event.destination_port,
        evidence_events=[process_create] if process_create else [],
    )


def _detect_periodic_outbound(contexts: DetectionContexts) -> list[Alert]:
    grouped: defaultdict[tuple[str, str, str, int], list[NetworkConnectEvent]] = defaultdict(list)
    for (host_key, guid), rows in contexts.network_by_process.items():
        for event in rows:
            if not _is_public_ip(event.destination_ip):
                continue
            if is_allowlisted_image(event.image):
                continue
            grouped[(host_key, guid, event.destination_ip, event.destination_port)].append(event)

    alerts: list[Alert] = []
    for (host_key, guid, destination_ip, destination_port), rows in grouped.items():
        if len(rows) < BEACON_MIN_CONNECTIONS:
            continue

        rows = sorted(rows, key=lambda item: item.timestamp)
        intervals = [
            (rows[idx].timestamp - rows[idx - 1].timestamp).total_seconds()
            for idx in range(1, len(rows))
            if (rows[idx].timestamp - rows[idx - 1].timestamp).total_seconds() > 0
        ]
        if len(intervals) < BEACON_MIN_CONNECTIONS - 1:
            continue

        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < BEACON_MIN_AVG_SECONDS or avg_interval > BEACON_MAX_AVG_SECONDS:
            continue

        jitter_ratio = (max(intervals) - min(intervals)) / avg_interval if avg_interval else 1.0
        if jitter_ratio > BEACON_MAX_JITTER_RATIO:
            continue

        anchor = rows[-1]
        process_create = _find_process_create(
            contexts.process_creates,
            host_key,
            guid,
            anchor.timestamp,
        )
        reason = (
            "Periodic outbound timing pattern observed: "
            f"{len(rows)} connections to {destination_ip}:{destination_port} "
            f"every ~{avg_interval:.0f}s (observed jitter {jitter_ratio * 100:.0f}%). "
            "Periodic timing alone does not establish beaconing."
        )

        alerts.append(
            _base_alert(
                event=anchor,
                alert_type="periodic_outbound_pattern",
                reason=reason,
                category="aggregate_behavior",
                finding_kind="hypothesis",
                evidence_strength=EvidenceStrength.CIRCUMSTANTIAL,
                tags=["periodic-network", "requires-context"],
                command_line=process_create.command_line if process_create else None,
                parent_image=process_create.parent_image if process_create else None,
                destination_ip=destination_ip,
                destination_port=destination_port,
                evidence_events=[*rows, *([process_create] if process_create else [])],
            )
        )

    return alerts
