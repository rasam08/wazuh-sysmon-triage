from __future__ import annotations

from collections import defaultdict

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import ProcessCreateEvent

from .detect_detectors_process import _base_alert
from .detect_types import (
    BURST_MIN_PROCESSES,
    BURST_SUSPICIOUS_BASENAMES,
    BURST_WINDOW_SECONDS,
    RULE_METADATA,
    AlertConfidence,
    DetectionContexts,
)
from .detect_utils import (
    _basename,
    _event_host_label,
    _host_key,
    _is_user_writable_path,
    _safe_tag_value,
    is_allowlisted_image,
)


def _is_burst_candidate(event: ProcessCreateEvent) -> bool:
    base = _basename(event.image)
    if base in BURST_SUSPICIOUS_BASENAMES:
        return True
    return _is_user_writable_path(event.image)


def _detect_burst_spread(
    contexts: DetectionContexts,
) -> list[Alert]:
    by_host: defaultdict[str, list[ProcessCreateEvent]] = defaultdict(list)
    host_labels: dict[str, str] = {}

    for rows in contexts.process_creates.values():
        for event in rows:
            if is_allowlisted_image(event.image):
                continue
            if not _is_burst_candidate(event):
                continue
            host_label = _event_host_label(event)
            key = _host_key(host_label)
            host_labels[key] = host_label
            by_host[key].append(event)

    alerts: list[Alert] = []
    for key, rows in by_host.items():
        if len(rows) < BURST_MIN_PROCESSES:
            continue

        rows = sorted(rows, key=lambda item: item.timestamp)
        best_window: tuple[int, int, int] | None = None
        start = 0

        for end in range(len(rows)):
            while (rows[end].timestamp - rows[start].timestamp).total_seconds() > BURST_WINDOW_SECONDS:
                start += 1
            window_rows = rows[start : end + 1]
            process_guids = {item.process_guid for item in window_rows}
            network_backed = sum(
                1 for guid in process_guids if contexts.network_by_guid.get(guid)
            )

            has_burst = len(process_guids) >= BURST_MIN_PROCESSES or (
                len(process_guids) >= 4 and network_backed >= 3
            )
            if not has_burst:
                continue

            if best_window is None:
                best_window = (start, end, network_backed)
                continue

            prev_start, prev_end, prev_network_backed = best_window
            prev_count = len({item.process_guid for item in rows[prev_start : prev_end + 1]})
            current_count = len(process_guids)
            if current_count > prev_count or (
                current_count == prev_count and network_backed > prev_network_backed
            ):
                best_window = (start, end, network_backed)

        if best_window is None:
            continue

        window_start, window_end, network_backed = best_window
        window_rows = rows[window_start : window_end + 1]
        process_guids = {item.process_guid for item in window_rows}
        family_count = len({_basename(item.image) for item in window_rows if _basename(item.image)})
        host_label = host_labels.get(key, "unknown-host")
        anchor = window_rows[-1]
        duration = max(1, int((anchor.timestamp - window_rows[0].timestamp).total_seconds()))

        score = min(100, 55 + len(process_guids) * 5 + min(network_backed, 5) * 4)
        confidence: AlertConfidence = "high" if len(process_guids) >= 8 or network_backed >= 4 else "medium"
        reason = (
            f"Burst suspicious process fan-out on host {host_label}: "
            f"{len(process_guids)} process launches in {duration}s "
            f"across {family_count} families ({network_backed} with outbound traffic)"
        )

        alerts.append(
            _base_alert(
                event=anchor,
                alert_type="burst_suspicious_processes",
                score=score,
                reason=reason,
                category="malware_execution",
                queue="soc_malware",
                confidence=confidence,
                tags=[
                    "batcave",
                    "burst",
                    "fanout",
                    f"host:{_safe_tag_value(host_label)}",
                ],
                command_line=anchor.command_line,
                parent_image=anchor.parent_image,
            )
        )

    return alerts


def _host_label_from_guid(
    process_guid: str,
    contexts: DetectionContexts,
) -> str:
    process_rows = contexts.process_creates.get(process_guid) or []
    if process_rows:
        return _event_host_label(process_rows[0])
    network_rows = contexts.network_by_guid.get(process_guid) or []
    if network_rows:
        return _event_host_label(network_rows[0])
    return "unknown-host"


def _detect_hot_host_meta_alerts(
    alerts: list[Alert],
    contexts: DetectionContexts,
) -> list[Alert]:
    grouped: defaultdict[str, list[Alert]] = defaultdict(list)
    host_labels: dict[str, str] = {}

    for alert in alerts:
        if alert.alert_type == "executive_hot_host":
            continue
        host_label = _host_label_from_guid(alert.process_guid, contexts)
        key = _host_key(host_label)
        host_labels[key] = host_label
        grouped[key].append(alert)

    hot_alerts: list[Alert] = []
    for key, rows in grouped.items():
        if len(rows) < 3:
            continue

        total_score = sum(alert.score for alert in rows)
        high_count = sum(1 for alert in rows if alert.score >= 85)
        unique_types = len({alert.alert_type for alert in rows})
        if total_score < 180 and high_count < 2:
            continue
        if unique_types < 2 and high_count < 2:
            continue

        anchor = max(rows, key=lambda alert: (alert.score, alert.utc_time))
        host_label = host_labels.get(key, "unknown-host")
        metadata = RULE_METADATA["executive_hot_host"]
        score = min(100, 70 + high_count * 10 + min(unique_types * 3, 15))

        hot_alerts.append(
            Alert(
                utc_time=anchor.utc_time,
                score=score,
                rule_id=metadata["rule_id"],
                rule_name=metadata["rule_name"],
                primary_event_id=metadata["primary_event_id"],
                alert_type="executive_hot_host",
                category="malware_execution",
                queue="soc_malware",
                confidence="high",
                reason=(
                    f"Hot host risk accumulation on {host_label}: "
                    f"{len(rows)} alerts, total score {total_score}, "
                    f"{high_count} high-severity, {unique_types} alert types"
                ),
                routing_why="Escalated to soc_malware: cumulative host risk exceeded threshold",
                image=anchor.image,
                command_line=anchor.command_line,
                parent_image=anchor.parent_image,
                destination_ip=anchor.destination_ip,
                destination_port=anchor.destination_port,
                process_guid=anchor.process_guid,
                tags=[
                    "batcave",
                    "meta",
                    "hot-host",
                    f"host:{_safe_tag_value(host_label)}",
                ],
            )
        )

    return hot_alerts

