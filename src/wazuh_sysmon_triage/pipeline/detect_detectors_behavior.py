from __future__ import annotations

from collections import defaultdict

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import ProcessCreateEvent

from .detect_detectors_process import _base_alert
from .detect_types import (
    BURST_MIN_PROCESSES,
    BURST_SUSPICIOUS_BASENAMES,
    BURST_WINDOW_SECONDS,
    DetectionContexts,
)
from .detect_utils import _basename, _is_user_writable_path, is_allowlisted_image


def _is_burst_candidate(event: ProcessCreateEvent) -> bool:
    return _basename(event.image) in BURST_SUSPICIOUS_BASENAMES or _is_user_writable_path(
        event.image
    )


def _detect_process_launch_burst(contexts: DetectionContexts) -> list[Alert]:
    by_host: defaultdict[str, list[ProcessCreateEvent]] = defaultdict(list)
    for rows in contexts.process_creates.values():
        for event in rows:
            if not is_allowlisted_image(event.image) and _is_burst_candidate(event):
                by_host[event.host_key or "unknown:constructed"].append(event)

    alerts: list[Alert] = []
    for host_key, rows in by_host.items():
        if len(rows) < BURST_MIN_PROCESSES:
            continue

        rows = sorted(rows, key=lambda item: item.timestamp)
        best_window: tuple[int, int, int] | None = None
        start = 0
        for end in range(len(rows)):
            while (
                rows[end].timestamp - rows[start].timestamp
            ).total_seconds() > BURST_WINDOW_SECONDS:
                start += 1
            window_rows = rows[start : end + 1]
            process_guids = {item.process_guid for item in window_rows}
            network_backed = sum(
                1 for guid in process_guids if contexts.network_by_process.get((host_key, guid))
            )
            has_burst = len(process_guids) >= BURST_MIN_PROCESSES or (
                len(process_guids) >= 4 and network_backed >= 3
            )
            if not has_burst:
                continue
            if best_window is None:
                best_window = (start, end, network_backed)
                continue
            previous = rows[best_window[0] : best_window[1] + 1]
            previous_count = len({item.process_guid for item in previous})
            if len(process_guids) > previous_count or (
                len(process_guids) == previous_count and network_backed > best_window[2]
            ):
                best_window = (start, end, network_backed)

        if best_window is None:
            continue

        window_rows = rows[best_window[0] : best_window[1] + 1]
        process_guids = {item.process_guid for item in window_rows}
        family_count = len({_basename(item.image) for item in window_rows if _basename(item.image)})
        anchor = window_rows[-1]
        duration = max(1, int((anchor.timestamp - window_rows[0].timestamp).total_seconds()))
        reason = (
            f"Process launch burst observed on {host_key}: "
            f"{len(process_guids)} process GUIDs in {duration}s across "
            f"{family_count} image names; {best_window[2]} had network activity. "
            "The count is an observation, not a maliciousness verdict."
        )
        alerts.append(
            _base_alert(
                event=anchor,
                alert_type="process_launch_burst",
                reason=reason,
                category="aggregate_behavior",
                finding_kind="aggregate_pattern",
                tags=["process-burst", "requires-context"],
                command_line=anchor.command_line,
                parent_image=anchor.parent_image,
                evidence_events=window_rows,
            )
        )

    return alerts
