from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict

import typer

from wazuh_sysmon_triage import __version__
from wazuh_sysmon_triage.clients.opensearch_client import OpenSearchClient
from wazuh_sysmon_triage.config import config_has_inline_password, load_config
from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.raw import RawHit
from wazuh_sysmon_triage.models.sysmon import SysmonEvent
from wazuh_sysmon_triage.operations import (
    parse_optional_bool,
)
from wazuh_sysmon_triage.output_schema import OUTPUT_SCHEMA_VERSION
from wazuh_sysmon_triage.pipeline.correlate import correlate_data
from wazuh_sysmon_triage.pipeline.detect import DetectionRunResult, filter_alerts, run_detection
from wazuh_sysmon_triage.pipeline.fetch import fetch_sysmon_events
from wazuh_sysmon_triage.pipeline.normalize import NormalizeReport, normalize_data_with_report
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


class TruncationInfo(TypedDict):
    truncated: bool
    reason: str | None


@dataclass
class FetchStageResult:
    hits: list[RawHit]
    truncation: TruncationInfo
    duration_ms: int


@dataclass
class NormalizeStageResult:
    events: list[SysmonEvent]
    report: NormalizeReport
    counts_by_eid: dict[str, int]
    duration_ms: int


@dataclass
class CorrelateStageResult:
    correlation: dict[str, Any]
    duration_ms: int


@dataclass
class DetectStageResult:
    detection_result: DetectionRunResult
    all_alerts: list[Alert]
    alerts: list[Alert]
    pivot_bundles: list[dict[str, Any]]
    duration_ms: int


app = typer.Typer(help="SOC triage CLI for Wazuh Sysmon data.")


DEFAULT_PROFILE_PRESETS: dict[str, dict[str, Any]] = {
    "soc": {
        "event_ids": [1, 3, 11],
        "min_alert_score": 70,
        "alerts_only": True,
        "print_stats": True,
        "agent_name": "anon",
        "destination_scoring_mode": "balanced",
        "alert_queues": ["soc_malware", "soc_policy"],
        "include_dev_queue": False,
    },
    "lab": {
        "event_ids": [1, 3, 11],
        "min_alert_score": 60,
        "alerts_only": True,
        "print_stats": True,
        "destination_scoring_mode": "lab",
        "verify_tls": False,
    },
    "dev": {
        "event_ids": [1, 3, 11],
        "min_alert_score": 70,
        "alerts_only": False,
        "print_stats": True,
        "destination_scoring_mode": "balanced",
    },
}

VALID_ALERT_QUEUES = {"soc_malware", "soc_policy", "soc_dev", "soc_info"}


LAST_RE = re.compile(r"^(\d+)([mhd])$", flags=re.IGNORECASE)


def _ensure_out_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _process_line(stage: str, message: str) -> None:
    typer.echo(f"[process] {stage}: {message}")


def _resolve_default_config_path(config: str | None) -> str | None:
    if config:
        return config
    default_path = "config.local.yaml"
    if os.path.exists(default_path):
        _process_line("config", f"using {default_path} (override with --config)")
        return default_path
    return None


def _safe_case_id(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip())
    normalized = re.sub(r"-+", "-", normalized).strip("-._")
    return normalized or "incident"


def _generate_case_id(now: datetime | None = None) -> str:
    ts = (now or datetime.now(tz=UTC)).strftime("%Y%m%d-%H%M%S")
    return f"incident-{ts}"


def _parse_last_duration(value: str) -> timedelta:
    match = LAST_RE.match(value.strip())
    if not match:
        raise typer.BadParameter("--last must look like 15m, 2h, or 7d")
    amount = int(match.group(1))
    unit = match.group(2).lower()
    if amount <= 0:
        raise typer.BadParameter("--last value must be greater than zero")
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    return timedelta(days=amount)


def _iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_iso_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _shift_known_timestamp_fields(payload: Any, delta: timedelta) -> int:
    shifted = 0
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_lower = key.lower()
            if isinstance(value, str) and key_lower in {"@timestamp", "utctime", "creationutctime"}:
                parsed = _parse_iso_ts(value)
                if parsed is not None:
                    payload[key] = _iso_z(parsed + delta)
                    shifted += 1
                    continue
            shifted += _shift_known_timestamp_fields(value, delta)
    elif isinstance(payload, list):
        for item in payload:
            shifted += _shift_known_timestamp_fields(item, delta)
    return shifted


def _is_scenario_gym_path(input_ndjson: str) -> bool:
    normalized = input_ndjson.replace("\\", "/").lower()
    return "scenario_gym" in normalized and normalized.endswith(".ndjson")


def _rebase_scenario_gym_hits_to_now(hits: list[RawHit]) -> tuple[bool, int]:
    source_times: list[datetime] = []
    for hit in hits:
        source = hit.get("_source") or {}
        ts = _parse_iso_ts(source.get("@timestamp"))
        if ts is not None:
            source_times.append(ts)

    if not source_times:
        return False, 0

    anchor = min(source_times)
    delta = datetime.now(tz=UTC) - anchor
    shifted_fields = 0
    for hit in hits:
        shifted_fields += _shift_known_timestamp_fields(hit, delta)
    return True, shifted_fields


def _resolve_time_window(
    start: str | None,
    end: str | None,
    last: str | None,
    today: bool,
    yesterday: bool,
    now: datetime | None = None,
) -> tuple[str | None, str | None]:
    if start or end:
        if not start or not end:
            raise typer.BadParameter("--start and --end must be provided together")
        return start, end

    selected = int(bool(last)) + int(today) + int(yesterday)
    if selected > 1:
        raise typer.BadParameter("Use only one of --last, --today, or --yesterday")

    current = (now or datetime.now(tz=UTC)).astimezone(UTC)
    if last:
        delta = _parse_last_duration(last)
        return _iso_z(current - delta), _iso_z(current)

    if today:
        day_start = current.replace(hour=0, minute=0, second=0, microsecond=0)
        return _iso_z(day_start), _iso_z(current)

    if yesterday:
        today_start = current.replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday_start = today_start - timedelta(days=1)
        return _iso_z(yesterday_start), _iso_z(today_start)

    return start, end


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


def _alert_contributors(alert) -> list[str]:
    contributors: list[str] = []
    if getattr(alert, "rule_name", None):
        contributors.append(f"primary_rule:{alert.rule_name}")
    elif getattr(alert, "rule_id", None):
        contributors.append(f"primary_rule:{alert.rule_id}")
    else:
        contributors.append(f"primary_rule:{getattr(alert, 'alert_type', 'unknown')}")

    tags = set(getattr(alert, "tags", []) or [])
    for tag in sorted(tags):
        if str(tag).startswith("escalator:"):
            contributors.append(f"escalator:{tag.split(':', 1)[1]}")
    if "role:developer" in tags:
        contributors.append("context:developer")
    return contributors


def _print_alert_explanations(
    alerts: list,
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


def _run_fetch_stage(
    *,
    logger: logging.Logger,
    run_ctx: RunContext,
    input_ndjson: str | None,
    raw_save: str | None,
    host: str | None,
    user: str | None,
    password: str | None,
    verify_tls: bool,
    index_pattern: str,
    start: str | None,
    end: str | None,
    agent_id: str | None,
    agent_name: str | None,
    event_ids: list[int] | None,
    agent_mode: str,
    max_events: int,
    max_pages: int,
    fail_on_truncation: bool,
) -> FetchStageResult:
    hits: list[RawHit] = []
    truncation: TruncationInfo = {"truncated": False, "reason": None}
    raw_handle = None
    client = None
    duration_ms = 0

    try:
        with timed("fetch", logger, run_ctx) as timer:
            if input_ndjson:
                _process_line("fetch (offline)", f"reading ndjson from {input_ndjson}...")
                logger.info(
                    "Fetch started (offline)",
                    extra={
                        "event": "fetch_start",
                        "stage": "fetch",
                        "run_id": run_ctx.run_id,
                        "case_id": run_ctx.case_id,
                    },
                )
                with open(input_ndjson, encoding="utf-8") as handle:
                    for line in handle:
                        text = line.strip()
                        if not text:
                            continue
                        hits.append(json.loads(text))
                        if len(hits) >= max_events:
                            truncation = {"truncated": True, "reason": "max-events"}
                            break

                if _is_scenario_gym_path(input_ndjson):
                    rebased, shifted_fields = _rebase_scenario_gym_hits_to_now(hits)
                    if rebased:
                        _process_line(
                            "fetch (offline)", "rebased scenario_gym timestamps to current UTC"
                        )
                        logger.info(
                            "Scenario gym timestamps rebased",
                            extra={
                                "event": "scenario_gym_rebase",
                                "stage": "fetch",
                                "run_id": run_ctx.run_id,
                                "case_id": run_ctx.case_id,
                                "counts": {"timestamp_fields_shifted": shifted_fields},
                            },
                        )
                logger.info(
                    "Fetch completed (offline)",
                    extra={
                        "event": "fetch_complete",
                        "stage": "fetch",
                        "run_id": run_ctx.run_id,
                        "case_id": run_ctx.case_id,
                        "counts": {"hits": len(hits)},
                    },
                )
            else:
                _process_line("fetch (live)", "querying opensearch...")
                assert host is not None
                assert user is not None
                assert password is not None
                assert start is not None
                assert end is not None
                client = OpenSearchClient(
                    base_url=host,
                    user=user,
                    password=password,
                    verify_tls=verify_tls,
                )
                if raw_save:
                    raw_path = raw_save
                    os.makedirs(os.path.dirname(raw_path) or ".", exist_ok=True)
                    raw_handle = open(raw_path, "w", encoding="utf-8")

                logger.info(
                    "Fetch started",
                    extra={
                        "event": "fetch_start",
                        "stage": "fetch",
                        "run_id": run_ctx.run_id,
                        "case_id": run_ctx.case_id,
                    },
                )
                fetch_result = fetch_sysmon_events(
                    client=client,
                    index_pattern=index_pattern,
                    start_dt=start,
                    end_dt=end,
                    agent_id=agent_id,
                    agent_name=agent_name,
                    event_ids=tuple(event_ids) if event_ids else (1, 3, 11),
                    agent_mode=agent_mode,
                    run_id=run_ctx.run_id,
                    case_id=run_ctx.case_id,
                    max_events=max_events,
                    max_pages=max_pages,
                )
                hits = fetch_result.hits
                truncation = {"truncated": fetch_result.truncated, "reason": fetch_result.reason}
                if raw_handle:
                    for hit in hits:
                        raw_handle.write(json.dumps(hit))
                        raw_handle.write("\n")
        duration_ms = timer["duration_ms"]
    except Exception as exc:
        logger.error(
            "Fetch error",
            extra={
                "event": "fetch_error",
                "stage": "fetch",
                "run_id": run_ctx.run_id,
                "case_id": run_ctx.case_id,
                "error": str(exc),
            },
        )
        typer.echo(f"Fetch error: {exc}")
        raise typer.Exit(code=3) from exc
    finally:
        if raw_handle:
            raw_handle.close()
        if client:
            client.close()

    if truncation["truncated"]:
        logger.warning(
            "Fetch truncated",
            extra={
                "event": "fetch_truncated",
                "stage": "fetch",
                "run_id": run_ctx.run_id,
                "case_id": run_ctx.case_id,
                "counts": {"hits": len(hits)},
                "error": truncation["reason"],
            },
        )
        if fail_on_truncation:
            raise typer.Exit(code=4)

    return FetchStageResult(hits=hits, truncation=truncation, duration_ms=duration_ms)


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


def _validate_required(
    start: str | None, end: str | None, agent_id: str | None, agent_name: str | None
) -> None:
    if not start or not end:
        raise typer.BadParameter("--start and --end are required")
    if not agent_id and not agent_name:
        raise typer.BadParameter("--agent-id or --agent-name is required")


def _validate_opensearch(host: str | None, user: str | None, password: str | None) -> None:
    if not host or not user or not password:
        raise typer.BadParameter("--host, --user, and --password are required")


def _profile_default_verify_tls(profile: str | None) -> bool:
    # Lab defaults should be forgiving for common self-signed/local-indexer setups.
    return str(profile or "").strip().lower() != "lab"


def _resolve_verify_tls_setting(
    *,
    cli_value: bool | None,
    profile_value: Any,
    config_value: Any,
    env_value: str | None,
    active_profile: str | None,
) -> bool:
    if cli_value is not None:
        result = bool(cli_value)
    elif (env_parsed := parse_optional_bool(env_value)) is not None:
        result = env_parsed
    elif profile_value is not None:
        result = bool(profile_value)
    elif config_value is not None:
        result = bool(config_value)
    else:
        result = _profile_default_verify_tls(active_profile)

    if not result:
        typer.echo(
            "[warn] TLS certificate verification is DISABLED. "
            "Connections are vulnerable to MITM attacks. "
            "Set verify_tls=true or --verify-tls for production use."
        )
    return result


def _warn_inline_password_in_config(config_path: str | None) -> None:
    if not config_path:
        return
    if not config_has_inline_password(config_path):
        return
    typer.echo(
        "[warn] Inline password detected in config; use WAZUH_OS_PASSWORD instead. "
        "Config passwords are ignored."
    )


def _normalize_alert_queues(value: list[str] | None) -> list[str] | None:
    if not value:
        return None
    normalized: list[str] = []
    for queue in value:
        item = str(queue).strip().lower()
        if item not in VALID_ALERT_QUEUES:
            raise typer.BadParameter(
                f"Invalid queue '{queue}'. Use one of: {', '.join(sorted(VALID_ALERT_QUEUES))}"
            )
        if item not in normalized:
            normalized.append(item)
    return normalized


def _filter_alerts_by_queue(
    alerts: list,
    *,
    alert_queues: list[str] | None,
    include_dev_queue: bool,
) -> list:
    queues = _normalize_alert_queues(alert_queues)
    if queues is None:
        return alerts
    effective = set(queues)
    if include_dev_queue:
        effective.add("soc_dev")
    return [alert for alert in alerts if getattr(alert, "queue", "") in effective]


def _resolve_config(
    config_path: str | None,
    profile: str | None,
    start: str | None,
    end: str | None,
    agent_id: str | None,
    agent_name: str | None,
    out_dir: str | None,
    host: str | None,
    user: str | None,
    password: str | None,
    verify_tls: bool | None,
    index_pattern: str | None,
    event_ids: list[int] | None,
    min_alert_score: int | None,
    allowlist_image: list[str] | None,
    alert_queues: list[str] | None,
    include_dev_queue: bool | None,
    print_stats: bool | None = None,
    alerts_only: bool | None = None,
) -> dict:
    cfg: dict[str, Any] = {}
    if config_path:
        _warn_inline_password_in_config(config_path)
        loaded = load_config(config_path)
        cfg = loaded.model_dump()

    active_profile = profile or cfg.get("active_profile")
    merged_profile: dict[str, Any] = {}
    if active_profile:
        merged_profile = dict(DEFAULT_PROFILE_PRESETS.get(active_profile, {}))
        config_profiles = cfg.get("profiles") or {}
        if active_profile in config_profiles:
            profile_values = config_profiles.get(active_profile) or {}
            merged_profile.update(
                {key: value for key, value in profile_values.items() if value is not None}
            )

    resolved_verify_tls = _resolve_verify_tls_setting(
        cli_value=verify_tls,
        profile_value=merged_profile.get("verify_tls"),
        config_value=cfg.get("verify_tls"),
        env_value=os.getenv("WAZUH_OS_VERIFY_TLS"),
        active_profile=active_profile,
    )

    resolved = {
        "profile": active_profile,
        "start": start or merged_profile.get("start") or cfg.get("start"),
        "end": end or merged_profile.get("end") or cfg.get("end"),
        "agent_id": agent_id or merged_profile.get("agent_id") or cfg.get("agent_id"),
        "agent_name": agent_name or merged_profile.get("agent_name") or cfg.get("agent_name"),
        "out_dir": out_dir or merged_profile.get("out_dir") or cfg.get("out_dir"),
        "host": host or merged_profile.get("host") or cfg.get("host") or os.getenv("WAZUH_OS_HOST"),
        "user": user or merged_profile.get("user") or cfg.get("user") or os.getenv("WAZUH_OS_USER"),
        # Credentials are env-first by policy: avoid secrets in config files.
        "password": password or os.getenv("WAZUH_OS_PASSWORD"),
        "verify_tls": resolved_verify_tls,
        "index_pattern": index_pattern
        or merged_profile.get("index_pattern")
        or cfg.get("index_pattern"),
        "event_ids": event_ids or merged_profile.get("event_ids") or cfg.get("event_ids"),
        "min_alert_score": min_alert_score
        if min_alert_score is not None
        else merged_profile.get("min_alert_score", cfg.get("min_alert_score")),
        "alert_allowlist_basenames": allowlist_image
        or merged_profile.get("alert_allowlist_basenames")
        or cfg.get("alert_allowlist_basenames"),
        "destination_scoring_mode": merged_profile.get("destination_scoring_mode")
        or cfg.get("destination_scoring_mode")
        or "balanced",
        "suppressions": merged_profile.get("suppressions") or cfg.get("suppressions") or {},
        "context_roles": merged_profile.get("context_roles") or cfg.get("context_roles") or {},
        "alert_queues": alert_queues
        or merged_profile.get("alert_queues")
        or cfg.get("alert_queues"),
        "include_dev_queue": include_dev_queue
        if include_dev_queue is not None
        else bool(merged_profile.get("include_dev_queue", cfg.get("include_dev_queue", False))),
        "print_stats": print_stats
        if print_stats is not None
        else merged_profile.get("print_stats", cfg.get("print_stats")),
        "alerts_only": alerts_only
        if alerts_only is not None
        else merged_profile.get("alerts_only", cfg.get("alerts_only")),
        "artifact_retention": merged_profile.get("artifact_retention")
        or cfg.get("artifact_retention")
        or {},
    }
    return resolved
