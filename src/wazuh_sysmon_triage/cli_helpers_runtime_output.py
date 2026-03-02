from __future__ import annotations

import json
import os
from typing import Any

import typer

from wazuh_sysmon_triage import __version__
from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import SysmonEvent
from wazuh_sysmon_triage.output_schema import OUTPUT_SCHEMA_VERSION
from wazuh_sysmon_triage.pipeline.detect import DetectionRunResult
from wazuh_sysmon_triage.pipeline.normalize import NormalizeReport
from wazuh_sysmon_triage.sanitize import OutputSanitizer

from .cli_helpers_runtime_types import TruncationInfo
from .cli_helpers_runtime_utils import _alert_contributors


def _write_run_metadata(
    out_dir: str,
    payload: dict[str, Any],
    *,
    sanitizer: OutputSanitizer | None = None,
) -> None:
    path = os.path.join(out_dir, "run_metadata.json")
    payload_with_schema = {"schema_version": OUTPUT_SCHEMA_VERSION, **payload}
    if sanitizer:
        payload_with_schema = sanitizer.sanitize_obj(payload_with_schema)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload_with_schema, handle, indent=2)


def _emit_dry_run(
    *,
    mode: str,
    case_id: str | None,
    out_dir: str,
    query: dict[str, Any],
    resolved: dict[str, Any] | None = None,
    sanitizer: OutputSanitizer | None = None,
) -> None:
    payload = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "mode": mode,
        "case_id": case_id,
        "out_dir": out_dir,
        "query": query,
        "resolved": resolved or {},
    }
    if sanitizer:
        payload = sanitizer.sanitize_obj(payload)
    typer.echo(json.dumps(payload, indent=2))


def _print_alert_explanations(
    alerts: list[Any],
    *,
    explain_alert: str | None,
    sanitizer: OutputSanitizer | None = None,
) -> None:
    selected = alerts
    if explain_alert:
        key = explain_alert.strip().upper()
        selected = [
            alert for alert in alerts if (getattr(alert, "alert_id", "") or "").upper() == key
        ]
        if not selected:
            raise typer.BadParameter(
                f"Alert '{explain_alert}' was not found in emitted alerts.",
                param_hint="--explain-alert",
            )
    elif not selected:
        typer.echo("No alerts available for explanation.")
        return

    for alert in selected:
        alert_id = getattr(alert, "alert_id", "") or "unassigned"
        image = getattr(alert, "image", "")
        command_line = getattr(alert, "command_line", "")
        destination_ip = getattr(alert, "destination_ip", "")
        destination_port = getattr(alert, "destination_port", "")
        reason = getattr(alert, "reason", "")
        routing_why = getattr(alert, "routing_why", "")
        if sanitizer:
            alert_id = sanitizer.sanitize_text(alert_id) or alert_id
            image = sanitizer.sanitize_text(image) or image
            command_line = sanitizer.sanitize_text(command_line) or command_line
            destination_ip = sanitizer.sanitize_ip(destination_ip) or destination_ip
            reason = sanitizer.sanitize_text(reason) or reason
            routing_why = sanitizer.sanitize_text(routing_why) or routing_why

        typer.echo(f"[explain] {alert_id} score={alert.score} type={alert.alert_type}")
        typer.echo(
            f"  rule={getattr(alert, 'rule_id', '') or 'n/a'} name={getattr(alert, 'rule_name', '') or 'n/a'} category={alert.category} queue={alert.queue} confidence={alert.confidence}"
        )
        typer.echo(f"  reason={reason}")
        if routing_why:
            typer.echo(f"  routing={routing_why}")
        typer.echo(f"  contributors={', '.join(_alert_contributors(alert))}")
        context = f"  image={image}"
        if command_line:
            context += f" command_line={command_line}"
        if destination_ip:
            context += f" destination={destination_ip}:{destination_port or ''}".rstrip(":")
        typer.echo(context)


def _write_query_json(
    *,
    out_dir: str,
    query_body: dict[str, Any],
    sanitizer: OutputSanitizer | None,
) -> None:
    query_payload: dict[str, Any] = query_body
    if sanitizer:
        query_payload = sanitizer.sanitize_obj(query_payload)
    with open(os.path.join(out_dir, "query.json"), "w", encoding="utf-8") as handle:
        json.dump(query_payload, handle, indent=2)


def _write_stats_json(
    *,
    out_dir: str,
    hits_count: int,
    normalized: list[SysmonEvent],
    correlation: dict[str, Any],
    detection_result: DetectionRunResult,
    configured_alert_queues: list[str] | None,
    include_dev_queue: bool,
    truncation: TruncationInfo,
    normalize_report: NormalizeReport,
    fetch_duration_ms: int,
    normalize_duration_ms: int,
    correlate_duration_ms: int,
    detect_duration_ms: int,
    render_duration_ms: int,
    total_duration_ms: int,
    sanitizer: OutputSanitizer | None,
) -> None:
    process_event_count = sum(1 for event in normalized if event.event_id == 1)
    file_event_count = sum(1 for event in normalized if event.event_id == 11)
    network_event_count = sum(1 for event in normalized if event.event_id == 3)
    events_per_second = (
        round(len(normalized) / (total_duration_ms / 1000), 2) if total_duration_ms > 0 else 0.0
    )

    stats_payload: dict[str, Any] = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "hits": hits_count,
        "total_events": len(normalized),
        "events_by_type": {
            "process_create": process_event_count,
            "network_connect": network_event_count,
            "file_create": file_event_count,
        },
        "artifacts": len(correlation.get("artifacts", [])),
        "nodes": len(correlation.get("nodes", [])),
        "edges": len(correlation.get("edges", [])),
        "suppressed_alerts": detection_result.suppressed_alerts,
        "suppressed_events": detection_result.suppressed_events,
        "suppression_hits": detection_result.suppression_hits,
        "queue_filter": {
            "alert_queues": configured_alert_queues,
            "include_dev_queue": include_dev_queue,
        },
        "truncation": truncation,
        "dropped_count": normalize_report.dropped_count,
        "dropped_by_reason": normalize_report.dropped_by_reason,
        "invalid_timestamp_count": normalize_report.invalid_timestamp_count,
        "invalid_timestamp_by_eid": normalize_report.invalid_timestamp_by_eid,
        "fetch_duration_ms": fetch_duration_ms,
        "normalize_duration_ms": normalize_duration_ms,
        "correlate_duration_ms": correlate_duration_ms,
        "detect_duration_ms": detect_duration_ms,
        "render_duration_ms": render_duration_ms,
        "total_duration_ms": total_duration_ms,
        "events_per_second": events_per_second,
    }
    if sanitizer:
        stats_payload = sanitizer.sanitize_obj(stats_payload)
    with open(os.path.join(out_dir, "stats.json"), "w", encoding="utf-8") as handle:
        json.dump(stats_payload, handle, indent=2)


def _build_run_metadata_payload(
    *,
    run_id: str,
    resolved: dict[str, Any],
    start: str | None,
    end: str | None,
    agent_id: str | None,
    agent_name: str | None,
    case_value: str,
    index_pattern: str,
    hits_count: int,
    normalized_count: int,
    correlation: dict[str, Any],
    alerts_count: int,
    pivot_bundle_count: int,
    detection_result: DetectionRunResult,
    destination_scoring_mode: str,
    suppression_rules: list[dict[str, Any]],
    allowlist_override_rules: list[dict[str, Any]],
    configured_alert_queues: list[str] | None,
    include_dev_queue: bool,
    verify_tls: bool,
    retention_result: dict[str, Any] | None,
    normalize_report: NormalizeReport,
    truncation: TruncationInfo,
    fetch_duration_ms: int,
    normalize_duration_ms: int,
    correlate_duration_ms: int,
    detect_duration_ms: int,
    render_duration_ms: int,
    total_duration_ms: int,
    query_body: dict[str, Any],
) -> dict[str, Any]:
    return {
        "version": __version__,
        "run_id": run_id,
        "start": start,
        "end": end,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "profile": resolved.get("profile"),
        "case_id": case_value,
        "index_pattern": index_pattern,
        "counts": {
            "raw_hits": hits_count,
            "normalized_events": normalized_count,
            "artifacts": len(correlation.get("artifacts", [])),
            "nodes": len(correlation.get("nodes", [])),
            "edges": len(correlation.get("edges", [])),
            "alerts": alerts_count,
            "suppressed_alerts": detection_result.suppressed_alerts,
            "suppressed_events": detection_result.suppressed_events,
            "pivot_bundles": pivot_bundle_count,
        },
        "destination_scoring_mode": destination_scoring_mode,
        "suppression": {
            "rules_count": len(suppression_rules),
            "allowlist_override_count": len(allowlist_override_rules),
            "suppression_hits": detection_result.suppression_hits,
        },
        "queue_filter": {
            "alert_queues": configured_alert_queues,
            "include_dev_queue": include_dev_queue,
        },
        "verify_tls": verify_tls,
        "retention": retention_result or {},
        "dropped_count": normalize_report.dropped_count,
        "dropped_by_reason": normalize_report.dropped_by_reason,
        "invalid_timestamp_count": normalize_report.invalid_timestamp_count,
        "invalid_timestamp_by_eid": normalize_report.invalid_timestamp_by_eid,
        "truncation": truncation,
        "fetch_duration_ms": fetch_duration_ms,
        "normalize_duration_ms": normalize_duration_ms,
        "correlate_duration_ms": correlate_duration_ms,
        "detect_duration_ms": detect_duration_ms,
        "render_duration_ms": render_duration_ms,
        "total_duration_ms": total_duration_ms,
        "query": query_body,
    }


def _print_stats_summary(
    *,
    hits_count: int,
    counts_by_eid: dict[str, int],
    normalize_report: NormalizeReport,
    correlation: dict[str, Any],
    alerts_count: int,
    configured_alert_queues: list[str] | None,
    include_dev_queue: bool,
    suppressed_alerts: int,
    total_duration_ms: int,
) -> None:
    normalized_summary = (
        ", ".join(f"{eid}: {count}" for eid, count in sorted(counts_by_eid.items())) or "none"
    )
    suspicious_destinations = sum(
        1 for entry in correlation.get("network_activity", []) if entry.get("suspicious")
    )
    summary_rows = [
        ("Fetched hits", str(hits_count)),
        ("Normalized by EID", normalized_summary),
        ("Dropped events", str(normalize_report.dropped_count)),
        ("Invalid timestamps", str(normalize_report.invalid_timestamp_count)),
        ("Artifacts", str(len(correlation.get("artifacts", [])))),
        ("Alerts", str(alerts_count)),
        (
            "Queue filter",
            ",".join(configured_alert_queues or ["all"]) + ("+dev" if include_dev_queue else ""),
        ),
        ("Suppressed alerts", str(suppressed_alerts)),
        ("Suspicious destinations", str(suspicious_destinations)),
        ("Total duration (ms)", str(total_duration_ms)),
    ]
    width = max(len(label) for label, _ in summary_rows)
    for label, value in summary_rows:
        typer.echo(f"{label.ljust(width)} : {value}")


def _print_alert_list(
    *,
    alerts: list[Alert],
    min_alert_score: int,
    sanitizer: OutputSanitizer | None,
) -> None:
    typer.echo(f"Alerts (score >= {min_alert_score}): {len(alerts)}")
    for alert in alerts:
        destination = ""
        if alert.destination_ip:
            destination = f" {alert.destination_ip}:{alert.destination_port or ''}".rstrip(":")
        iso_time = alert.utc_time.isoformat().replace("+00:00", "Z")
        alert_type = alert.alert_type
        image = alert.image
        reason = alert.reason
        if sanitizer:
            destination = sanitizer.sanitize_text(destination) or destination
            alert_type = sanitizer.sanitize_text(alert_type) or alert_type
            image = sanitizer.sanitize_text(image) or image
            reason = sanitizer.sanitize_text(reason) or reason
        typer.echo(f"[{alert.score}] {iso_time} {alert_type} {image}{destination} - {reason}")

