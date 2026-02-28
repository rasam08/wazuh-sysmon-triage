from __future__ import annotations

import logging
import os
from pathlib import Path
from time import perf_counter
from typing import Any

import typer

from wazuh_sysmon_triage.cli_helpers import (
    _build_run_metadata_payload,
    _emit_dry_run,
    _ensure_out_dir,
    _generate_case_id,
    _normalize_alert_queues,
    _print_alert_explanations,
    _print_alert_list,
    _print_stats_summary,
    _process_line,
    _resolve_config,
    _resolve_time_window,
    _run_correlate_stage,
    _run_detect_stage,
    _run_fetch_stage,
    _run_normalize_stage,
    _run_render_stage,
    _safe_case_id,
    _validate_opensearch,
    _validate_required,
    _write_query_json,
    _write_run_metadata,
    _write_stats_json,
)
from wazuh_sysmon_triage.logging import setup_logging
from wazuh_sysmon_triage.operations import apply_artifact_retention, record_run_telemetry
from wazuh_sysmon_triage.pipeline.fetch import build_sysmon_query
from wazuh_sysmon_triage.runtime import RunContext
from wazuh_sysmon_triage.sanitize import OutputSanitizer


def _execute_run(
    *,
    profile: str | None,
    start: str | None,
    end: str | None,
    last: str | None,
    today: bool,
    yesterday: bool,
    agent_id: str | None,
    agent_name: str | None,
    out_dir: str,
    host: str | None,
    user: str | None,
    password: str | None,
    verify_tls: bool | None,
    index_pattern: str,
    event_id: list[int] | None,
    agent_mode: str,
    raw_save: str | None,
    log_level: str,
    log_json: bool,
    log_file: str | None,
    max_events: int,
    max_pages: int,
    fail_on_truncation: bool,
    print_stats: bool | None,
    case_id: str | None,
    input_ndjson: str | None,
    min_alert_score: int | None,
    allowlist_image: list[str] | None,
    alert_queues: list[str] | None,
    include_dev_queue: bool | None,
    alerts_only: bool | None,
    explain: bool,
    explain_alert: str | None,
    quarantine_drops: bool,
    sanitize: bool,
    dry_run_query: bool,
    default_last_window: str | None,
    config: str | None,
) -> None:
    run_ctx = RunContext(case_id=case_id)
    setup_logging(log_level, json_format=log_json, out_path=None)
    resolved = _resolve_config(
        config,
        profile,
        start,
        end,
        agent_id,
        agent_name,
        out_dir,
        host,
        user,
        password,
        verify_tls,
        index_pattern,
        event_id,
        min_alert_score,
        allowlist_image,
        alert_queues,
        include_dev_queue,
        print_stats,
        alerts_only,
    )
    effective_last = last
    if (
        default_last_window
        and not resolved["start"]
        and not resolved["end"]
        and not last
        and not today
        and not yesterday
    ):
        effective_last = default_last_window

    start, end = _resolve_time_window(
        resolved["start"],
        resolved["end"],
        effective_last,
        today,
        yesterday,
    )
    agent_id = resolved["agent_id"]
    agent_name = resolved["agent_name"]
    out_dir = resolved["out_dir"] or "./out"
    host = resolved["host"]
    user = resolved["user"]
    password = resolved["password"]
    verify_tls = bool(resolved["verify_tls"]) if resolved["verify_tls"] is not None else True
    index_pattern = resolved["index_pattern"] or "wazuh-alerts-4.x-*"
    event_ids = resolved.get("event_ids")
    min_alert_score = (
        int(resolved["min_alert_score"]) if resolved.get("min_alert_score") is not None else 70
    )
    print_stats = bool(resolved.get("print_stats"))
    alerts_only = bool(resolved.get("alerts_only"))
    allowlist_basenames = resolved.get("alert_allowlist_basenames")
    destination_scoring_mode = resolved.get("destination_scoring_mode") or "balanced"
    suppressions = resolved.get("suppressions") or {}
    suppression_rules = suppressions.get("rules") or []
    allowlist_override_rules = suppressions.get("allowlist_override") or []
    context_roles = resolved.get("context_roles") or {}
    configured_alert_queues = _normalize_alert_queues(resolved.get("alert_queues"))
    include_dev_queue = bool(resolved.get("include_dev_queue"))
    if explain_alert:
        explain = True

    if not input_ndjson:
        _validate_required(start, end, agent_id, agent_name)
        if not dry_run_query:
            _validate_opensearch(host, user, password)

    case_value = _safe_case_id(case_id) if case_id else _generate_case_id()
    run_ctx.case_id = case_value
    sanitizer = OutputSanitizer() if sanitize else None
    out_root_dir = out_dir
    if os.path.basename(os.path.normpath(out_dir)) != case_value:
        out_dir = os.path.join(out_dir, case_value)
        out_root_dir = os.path.dirname(out_dir)
    else:
        out_root_dir = os.path.dirname(out_dir) or "."
    _ensure_out_dir(out_dir)
    if not log_file:
        log_file = os.path.join(out_dir, "run.log.ndjson")
    setup_logging(log_level, json_format=log_json, out_path=Path(log_file))
    logger = logging.getLogger("wazuh_sysmon_triage")

    retention_result: dict[str, Any] | None = None
    if not dry_run_query:
        retention_result = apply_artifact_retention(
            out_root=out_root_dir,
            current_case_id=case_value,
            policy=resolved.get("artifact_retention") or {},
        )
        removed_cases = retention_result.get("removed_cases") if retention_result else []
        if removed_cases:
            removed_bytes = int(retention_result.get("removed_bytes") or 0)
            removed_mb = round(removed_bytes / (1024 * 1024), 2)
            _process_line(
                "retention",
                f"pruned {len(removed_cases)} old case folder(s), reclaimed {removed_mb} MB",
            )
            logger.info(
                "Retention pruning complete",
                extra={
                    "event": "retention_pruned",
                    "stage": "retention",
                    "run_id": run_ctx.run_id,
                    "case_id": run_ctx.case_id,
                    "counts": {
                        "removed_cases": len(removed_cases),
                        "removed_bytes": removed_bytes,
                    },
                },
            )

    total_start = perf_counter()

    if input_ndjson:
        query_body = {"input_ndjson": input_ndjson}
    else:
        assert start is not None
        assert end is not None
        query_body = build_sysmon_query(
            start=start,
            end=end,
            agent_id=agent_id,
            agent_name=agent_name,
            agent_mode=agent_mode,
            event_ids=event_ids,
        )

    if dry_run_query:
        _emit_dry_run(
            mode="offline" if input_ndjson else "live",
            case_id=case_value,
            out_dir=out_dir,
            query=query_body,
            resolved={
                "profile": resolved.get("profile"),
                "start": start,
                "end": end,
                "host": host,
                "agent_id": agent_id,
                "agent_name": agent_name,
                "index_pattern": index_pattern,
                "event_ids": event_ids or [1, 3, 11],
                "min_alert_score": min_alert_score,
                "destination_scoring_mode": destination_scoring_mode,
                "alert_queues": configured_alert_queues,
                "include_dev_queue": include_dev_queue,
                "verify_tls": verify_tls,
            },
            sanitizer=sanitizer,
        )
        return

    stage_durations = {
        "fetch": 0,
        "normalize": 0,
        "correlate": 0,
        "detect": 0,
        "render": 0,
    }
    current_stage = "fetch"
    total_duration_ms = 0
    success = False
    failure_reason: str | None = None

    try:
        current_stage = "fetch"
        fetch_stage = _run_fetch_stage(
            logger=logger,
            run_ctx=run_ctx,
            input_ndjson=input_ndjson,
            raw_save=raw_save,
            host=host,
            user=user,
            password=password,
            verify_tls=verify_tls,
            index_pattern=index_pattern,
            start=start,
            end=end,
            agent_id=agent_id,
            agent_name=agent_name,
            event_ids=event_ids,
            agent_mode=agent_mode,
            max_events=max_events,
            max_pages=max_pages,
            fail_on_truncation=fail_on_truncation,
        )
        hits = fetch_stage.hits
        truncation = fetch_stage.truncation
        fetch_duration_ms = fetch_stage.duration_ms
        stage_durations["fetch"] = fetch_duration_ms

        current_stage = "normalize"
        normalize_stage = _run_normalize_stage(
            logger=logger,
            run_ctx=run_ctx,
            hits=hits,
            quarantine_drops=quarantine_drops,
            out_dir=out_dir,
            sanitizer=sanitizer,
        )
        normalized = normalize_stage.events
        normalize_report = normalize_stage.report
        counts_by_eid = normalize_stage.counts_by_eid
        normalize_duration_ms = normalize_stage.duration_ms
        stage_durations["normalize"] = normalize_duration_ms

        current_stage = "correlate"
        correlate_stage = _run_correlate_stage(
            logger=logger,
            run_ctx=run_ctx,
            events=normalized,
            destination_scoring_mode=destination_scoring_mode,
        )
        correlation = correlate_stage.correlation
        correlate_duration_ms = correlate_stage.duration_ms
        stage_durations["correlate"] = correlate_duration_ms

        current_stage = "detect"
        detect_stage = _run_detect_stage(
            logger=logger,
            run_ctx=run_ctx,
            events=normalized,
            allowlist_basenames=allowlist_basenames,
            suppression_rules=suppression_rules,
            allowlist_override_rules=allowlist_override_rules,
            context_roles=context_roles,
            min_alert_score=min_alert_score,
            configured_alert_queues=configured_alert_queues,
            include_dev_queue=include_dev_queue,
        )
        detection_result = detect_stage.detection_result
        alerts = detect_stage.alerts
        pivot_bundles = detect_stage.pivot_bundles
        detect_duration_ms = detect_stage.duration_ms
        stage_durations["detect"] = detect_duration_ms

        current_stage = "render"
        render_duration_ms = _run_render_stage(
            logger=logger,
            run_ctx=run_ctx,
            events=normalized,
            correlation=correlation,
            alerts=alerts,
            pivot_bundles=pivot_bundles,
            query_body=query_body,
            case_value=case_value,
            truncation=truncation,
            out_dir=out_dir,
            sanitizer=sanitizer,
        )
        stage_durations["render"] = render_duration_ms

        current_stage = "finalize"
        total_duration_ms = int((perf_counter() - total_start) * 1000)
        _write_query_json(
            out_dir=out_dir,
            query_body=query_body,
            sanitizer=sanitizer,
        )
        _write_stats_json(
            out_dir=out_dir,
            hits_count=len(hits),
            normalized=normalized,
            correlation=correlation,
            detection_result=detection_result,
            configured_alert_queues=configured_alert_queues,
            include_dev_queue=include_dev_queue,
            truncation=truncation,
            normalize_report=normalize_report,
            fetch_duration_ms=fetch_duration_ms,
            normalize_duration_ms=normalize_duration_ms,
            correlate_duration_ms=correlate_duration_ms,
            detect_duration_ms=detect_duration_ms,
            render_duration_ms=render_duration_ms,
            total_duration_ms=total_duration_ms,
            sanitizer=sanitizer,
        )

        _write_run_metadata(
            out_dir,
            _build_run_metadata_payload(
                run_id=run_ctx.run_id,
                resolved=resolved,
                start=start,
                end=end,
                agent_id=agent_id,
                agent_name=agent_name,
                case_value=case_value,
                index_pattern=index_pattern,
                hits_count=len(hits),
                normalized_count=len(normalized),
                correlation=correlation,
                alerts_count=len(alerts),
                pivot_bundle_count=len(pivot_bundles),
                detection_result=detection_result,
                destination_scoring_mode=destination_scoring_mode,
                suppression_rules=suppression_rules,
                allowlist_override_rules=allowlist_override_rules,
                configured_alert_queues=configured_alert_queues,
                include_dev_queue=include_dev_queue,
                verify_tls=verify_tls,
                retention_result=retention_result,
                normalize_report=normalize_report,
                truncation=truncation,
                fetch_duration_ms=fetch_duration_ms,
                normalize_duration_ms=normalize_duration_ms,
                correlate_duration_ms=correlate_duration_ms,
                detect_duration_ms=detect_duration_ms,
                render_duration_ms=render_duration_ms,
                total_duration_ms=total_duration_ms,
                query_body=query_body,
            ),
            sanitizer=sanitizer,
        )

        if print_stats:
            _print_stats_summary(
                hits_count=len(hits),
                counts_by_eid=counts_by_eid,
                normalize_report=normalize_report,
                correlation=correlation,
                alerts_count=len(alerts),
                configured_alert_queues=configured_alert_queues,
                include_dev_queue=include_dev_queue,
                suppressed_alerts=detection_result.suppressed_alerts,
                total_duration_ms=total_duration_ms,
            )

        if alerts_only:
            _print_alert_list(
                alerts=alerts,
                min_alert_score=min_alert_score,
                sanitizer=sanitizer,
            )

        if explain or explain_alert:
            _print_alert_explanations(
                alerts,
                explain_alert=explain_alert,
                sanitizer=sanitizer,
            )

        success = True
        typer.echo("Run complete")
    except typer.Exit as exc:
        failure_reason = f"{current_stage}:exit_{getattr(exc, 'exit_code', 1)}"
        raise
    except Exception as exc:
        failure_reason = f"{current_stage}:{type(exc).__name__}"
        raise
    finally:
        elapsed_ms = int((perf_counter() - total_start) * 1000)
        telemetry_total_ms = total_duration_ms if total_duration_ms > 0 else elapsed_ms
        run_mode = "offline" if input_ndjson else "live"
        try:
            telemetry_summary = record_run_telemetry(
                out_root=out_root_dir,
                run_id=run_ctx.run_id,
                case_id=run_ctx.case_id,
                mode=run_mode,
                profile=resolved.get("profile"),
                success=success,
                stage_durations=stage_durations,
                total_duration_ms=telemetry_total_ms,
                failure_reason=failure_reason,
            )
            logger.info(
                "Run telemetry updated",
                extra={
                    "event": "telemetry_updated",
                    "stage": "telemetry",
                    "run_id": run_ctx.run_id,
                    "case_id": run_ctx.case_id,
                    "counts": {
                        "total_runs": telemetry_summary.get("total_runs", 0),
                        "success_rate": telemetry_summary.get("success_rate", 0.0),
                    },
                },
            )
        except Exception as telemetry_exc:
            logger.warning(
                "Run telemetry update failed",
                extra={
                    "event": "telemetry_error",
                    "stage": "telemetry",
                    "run_id": run_ctx.run_id,
                    "case_id": run_ctx.case_id,
                    "error": str(telemetry_exc),
                },
            )



__all__ = ["_execute_run"]

