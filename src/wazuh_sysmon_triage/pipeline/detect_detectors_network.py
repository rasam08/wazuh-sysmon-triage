from __future__ import annotations

from collections import defaultdict

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import NetworkConnectEvent, ProcessCreateEvent

from .detect_contexts import _find_process_create
from .detect_detectors_process import _base_alert
from .detect_types import (
    BEACON_MAX_AVG_SECONDS,
    BEACON_MAX_JITTER_RATIO,
    BEACON_MIN_AVG_SECONDS,
    BEACON_MIN_CONNECTIONS,
    RULE_METADATA,
    DetectionContexts,
)
from .detect_utils import (
    _basename,
    _is_microsoft_destination,
    _is_public_ip,
    _score_to_reason,
    is_allowlisted_image,
)


def _detect_lolbin_outbound(
    event: NetworkConnectEvent,
    process_create: ProcessCreateEvent | None,
) -> Alert | None:
    from .detect_types import LOLBIN_BASENAMES  # local to keep module imports acyclic

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

