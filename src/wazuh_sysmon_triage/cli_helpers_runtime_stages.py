from __future__ import annotations

import json
import logging
import os
from typing import Any

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.raw import RawHit
from wazuh_sysmon_triage.models.sysmon import SysmonEvent
from wazuh_sysmon_triage.pipeline.correlate import correlate_data
from wazuh_sysmon_triage.pipeline.detect import filter_alerts, run_detection
from wazuh_sysmon_triage.pipeline.normalize import normalize_data_with_report
from wazuh_sysmon_triage.pipeline.pivot import assign_alert_ids, build_pivot_bundles
from wazuh_sysmon_triage.pipeline.render import (
    render_alert_bundles,
    render_alerts_csv,
    render_process_tree,
    render_report,
    render_timeline,
)
from wazuh_sysmon_triage.runtime import RunContext, timed
from wazuh_sysmon_triage.sanitize import OutputSanitizer

from .cli_helpers_runtime_types import (
    CorrelateStageResult,
    DetectStageResult,
    NormalizeStageResult,
    TruncationInfo,
)
from .cli_helpers_runtime_utils import _filter_alerts_by_queue, _process_line


def _run_normalize_stage(
    *,
    logger: logging.Logger,
    run_ctx: RunContext,
    hits: list[RawHit],
    quarantine_drops: bool,
    out_dir: str,
    sanitizer: OutputSanitizer | None,
) -> NormalizeStageResult:
    logger.info(
        "Normalize start",
        extra={
            "event": "normalize_start",
            "stage": "normalize",
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
        },
    )
    _process_line("normalize", f"parsing {len(hits)} hits...")
    with timed("normalize", logger, run_ctx) as timer:
        normalized, normalize_report = normalize_data_with_report(
            hits,
            collect_dropped=quarantine_drops,
        )
        counts_by_eid: dict[str, int] = {}
        for event in normalized:
            counts_by_eid[str(event.event_id)] = counts_by_eid.get(str(event.event_id), 0) + 1
    duration_ms = timer["duration_ms"]

    if quarantine_drops and normalize_report.dropped_events:
        quarantine_path = os.path.join(out_dir, "quarantine.ndjson")
        with open(quarantine_path, "w", encoding="utf-8") as handle:
            for dropped in normalize_report.dropped_events:
                payload: dict[str, Any] = dropped
                if sanitizer:
                    payload = sanitizer.sanitize_obj(payload)
                handle.write(json.dumps(payload))
                handle.write("\n")
        _process_line("normalize", f"wrote quarantine entries to {quarantine_path}")

    logger.info(
        "Normalize complete",
        extra={
            "event": "normalize_complete",
            "stage": "normalize",
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
            "counts": {
                **counts_by_eid,
                "dropped": normalize_report.dropped_count,
                "invalid_timestamp": normalize_report.invalid_timestamp_count,
            },
        },
    )
    return NormalizeStageResult(
        events=normalized,
        report=normalize_report,
        counts_by_eid=counts_by_eid,
        duration_ms=duration_ms,
    )


def _run_correlate_stage(
    *,
    logger: logging.Logger,
    run_ctx: RunContext,
    events: list[SysmonEvent],
    destination_scoring_mode: str,
) -> CorrelateStageResult:
    _process_line("correlate", "building graph...")
    with timed("correlate", logger, run_ctx) as timer:
        correlation = correlate_data(
            events,
            destination_scoring_mode=destination_scoring_mode,
        )
    duration_ms = timer["duration_ms"]
    logger.info(
        "Correlate complete",
        extra={
            "event": "correlate_complete",
            "stage": "correlate",
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
            "counts": {
                "nodes": len(correlation.get("nodes", [])),
                "edges": len(correlation.get("edges", [])),
                "artifacts": len(correlation.get("artifacts", [])),
                "network": len(correlation.get("network_activity", [])),
            },
        },
    )
    return CorrelateStageResult(correlation=correlation, duration_ms=duration_ms)


def _run_detect_stage(
    *,
    logger: logging.Logger,
    run_ctx: RunContext,
    events: list[SysmonEvent],
    allowlist_basenames: list[str] | None,
    suppression_rules: list[dict[str, Any]],
    allowlist_override_rules: list[dict[str, Any]],
    context_roles: dict[str, dict[str, Any]],
    min_alert_score: int,
    configured_alert_queues: list[str] | None,
    include_dev_queue: bool,
) -> DetectStageResult:
    _process_line("detect", "scoring alerts...")
    with timed("detect", logger, run_ctx) as timer:
        detection_result = run_detection(
            events,
            allowlist_basenames=allowlist_basenames,
            suppression_rules=suppression_rules,
            allowlist_override_rules=allowlist_override_rules,
            context_roles=context_roles,
        )
        all_alerts = assign_alert_ids(detection_result.alerts)
        score_filtered_alerts = filter_alerts(all_alerts, min_score=min_alert_score)
        alerts = _filter_alerts_by_queue(
            score_filtered_alerts,
            alert_queues=configured_alert_queues,
            include_dev_queue=include_dev_queue,
        )
        pivot_bundles = build_pivot_bundles(
            alerts,
            events,
            suppression_rules=suppression_rules,
            allowlist_override=allowlist_override_rules,
            allowlist_basenames=allowlist_basenames,
        )
    duration_ms = timer["duration_ms"]
    logger.info(
        "Detect complete",
        extra={
            "event": "detect_complete",
            "stage": "detect",
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
            "counts": {
                "all_alerts": len(all_alerts),
                "alerts_emitted": len(alerts),
                "min_alert_score": min_alert_score,
                "suppressed_alerts": detection_result.suppressed_alerts,
                "suppressed_events": detection_result.suppressed_events,
            },
        },
    )
    return DetectStageResult(
        detection_result=detection_result,
        all_alerts=all_alerts,
        alerts=alerts,
        pivot_bundles=pivot_bundles,
        duration_ms=duration_ms,
    )


def _run_render_stage(
    *,
    logger: logging.Logger,
    run_ctx: RunContext,
    events: list[SysmonEvent],
    correlation: dict[str, Any],
    alerts: list[Alert],
    pivot_bundles: list[dict[str, Any]],
    query_body: dict[str, Any],
    case_value: str,
    truncation: TruncationInfo,
    out_dir: str,
    sanitizer: OutputSanitizer | None,
) -> int:
    _process_line("render", f"writing {4 + len(pivot_bundles)} outputs...")
    with timed("render", logger, run_ctx) as timer:
        render_timeline(events, out_dir, sanitizer=sanitizer)
        render_process_tree(correlation, out_dir, sanitizer=sanitizer)
        render_alerts_csv(alerts, out_dir, sanitizer=sanitizer)
        render_alert_bundles(pivot_bundles, out_dir, sanitizer=sanitizer)
        render_report(
            {
                **correlation,
                "events": events,
                "alerts": alerts,
                "query": query_body,
                "case_id": case_value,
                "truncation": truncation,
            },
            out_dir,
            sanitizer=sanitizer,
        )
    duration_ms = timer["duration_ms"]
    logger.info(
        "Render complete",
        extra={
            "event": "render_complete",
            "stage": "render",
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
            "counts": {"outputs": 4 + len(pivot_bundles), "out_dir": out_dir},
        },
    )
    return duration_ms

