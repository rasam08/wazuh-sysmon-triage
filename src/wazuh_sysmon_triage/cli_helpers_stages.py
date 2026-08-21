from __future__ import annotations

import json
import logging
import os
from typing import Any

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.raw import RawHit
from wazuh_sysmon_triage.models.sysmon import SysmonEvent
from wazuh_sysmon_triage.pipeline.correlate import correlate_data
from wazuh_sysmon_triage.pipeline.detect import run_detection
from wazuh_sysmon_triage.pipeline.ndjson import InputQualityReport
from wazuh_sysmon_triage.pipeline.normalize import normalize_data_with_report
from wazuh_sysmon_triage.pipeline.pivot import assign_alert_ids, build_pivot_bundles
from wazuh_sysmon_triage.pipeline.render import (
    render_alert_bundles,
    render_alerts_csv,
    render_investigation_anchor,
    render_process_tree,
    render_report,
    render_timeline,
)
from wazuh_sysmon_triage.runtime import RunContext, timed
from wazuh_sysmon_triage.sanitize import OutputSanitizer

from .cli_helpers_types import (
    CorrelateStageResult,
    DetectStageResult,
    NormalizeStageResult,
    TruncationInfo,
)
from .cli_helpers_utils import _process_line


def _run_normalize_stage(
    *,
    logger: logging.Logger,
    run_ctx: RunContext,
    hits: list[RawHit],
    quarantine_drops: bool,
    out_dir: str,
    sanitizer: OutputSanitizer | None,
    append_quarantine: bool = False,
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
        mode = "a" if append_quarantine else "w"
        with open(quarantine_path, mode, encoding="utf-8") as handle:
            for dropped in normalize_report.dropped_events:
                payload: dict[str, Any] = {"stage": "normalize", **dropped}
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
) -> CorrelateStageResult:
    _process_line("correlate", "building graph...")
    with timed("correlate", logger, run_ctx) as timer:
        correlation = correlate_data(events)
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
                "file_deletions": len(correlation.get("file_delete_activity", [])),
                "network": len(correlation.get("network_activity", [])),
                "registry": len(correlation.get("registry_activity", [])),
                "dns": len(correlation.get("dns_activity", [])),
                "process_access": len(correlation.get("process_access_activity", [])),
                "process_terminations": len(correlation.get("process_termination_activity", [])),
                "authentication": len(correlation.get("authentication_activity", [])),
                "service_installs": len(correlation.get("service_install_activity", [])),
                "scheduled_tasks": len(correlation.get("scheduled_task_activity", [])),
                "remote_activity_leads": len(correlation.get("remote_activity_leads", [])),
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
) -> DetectStageResult:
    _process_line("detect", "evaluating transparent behavior rules...")
    with timed("detect", logger, run_ctx) as timer:
        detection_result = run_detection(
            events,
            allowlist_basenames=allowlist_basenames,
            suppression_rules=suppression_rules,
            allowlist_override_rules=allowlist_override_rules,
            context_roles=context_roles,
        )
        all_alerts = assign_alert_ids(detection_result.alerts)
        alerts = all_alerts
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
    investigation_anchor: dict[str, Any] | None = None,
    input_quality: InputQualityReport | None = None,
) -> int:
    output_count = 4 + len(pivot_bundles) + (1 if investigation_anchor else 0)
    _process_line("render", f"writing {output_count} outputs...")
    with timed("render", logger, run_ctx) as timer:
        render_timeline(events, out_dir, sanitizer=sanitizer)
        render_process_tree(correlation, out_dir, sanitizer=sanitizer)
        render_alerts_csv(alerts, out_dir, sanitizer=sanitizer)
        render_alert_bundles(pivot_bundles, out_dir, sanitizer=sanitizer)
        if investigation_anchor:
            render_investigation_anchor(investigation_anchor, out_dir, sanitizer=sanitizer)
        render_report(
            {
                **correlation,
                "events": events,
                "alerts": alerts,
                "query": query_body,
                "case_id": case_value,
                "truncation": truncation,
                "investigation_anchor": investigation_anchor,
                "input_quality": input_quality.to_payload() if input_quality else None,
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
            "counts": {"outputs": output_count, "out_dir": out_dir},
        },
    )
    return duration_ms
