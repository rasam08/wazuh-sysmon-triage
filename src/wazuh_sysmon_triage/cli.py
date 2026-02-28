from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import typer

from wazuh_sysmon_triage import __version__
from wazuh_sysmon_triage import cli_helpers as _cli_helpers
from wazuh_sysmon_triage.cli_helpers import (
    TruncationInfo,
    _emit_dry_run,
    _ensure_out_dir,
    _resolve_config,
    _resolve_default_config_path,
    _validate_opensearch,
    _validate_required,
    _write_run_metadata,
)
from wazuh_sysmon_triage.clients.opensearch_client import OpenSearchClient
from wazuh_sysmon_triage.logging import setup_logging
from wazuh_sysmon_triage.pipeline.fetch import build_sysmon_query, fetch_sysmon_events
from wazuh_sysmon_triage.pipeline.orchestrator import _execute_run
from wazuh_sysmon_triage.runtime import RunContext

app = typer.Typer(help="SOC triage CLI for Wazuh Sysmon data.")

# Backwards-compatible helper exports used by tests and scripts.
_parse_iso_ts = _cli_helpers._parse_iso_ts
_parse_last_duration = _cli_helpers._parse_last_duration
_rebase_scenario_gym_hits_to_now = _cli_helpers._rebase_scenario_gym_hits_to_now
_resolve_time_window = _cli_helpers._resolve_time_window


def _sync_runtime_dependencies() -> None:
    # Keep test monkeypatch behavior stable after extraction.
    _cli_helpers.OpenSearchClient = OpenSearchClient  # type: ignore[misc]
    _cli_helpers.fetch_sysmon_events = fetch_sysmon_events


@app.command("fetch")
def fetch_command(
    start: str | None = typer.Option(None, help="Start time in ISO8601 format."),
    end: str | None = typer.Option(None, help="End time in ISO8601 format."),
    agent_id: str | None = typer.Option(None, help="Agent ID."),
    agent_name: str | None = typer.Option(None, help="Agent Name."),
    out_dir: str = typer.Option("./out", help="Output directory."),
    host: str | None = typer.Option(None, help="Host for OpenSearch."),
    user: str | None = typer.Option(None, help="Username for OpenSearch."),
    password: str | None = typer.Option(
        None,
        help="Password for OpenSearch (prefer WAZUH_OS_PASSWORD environment variable).",
    ),
    verify_tls: bool | None = typer.Option(
        None,
        "--verify-tls/--no-verify-tls",
        help="Verify TLS certificate.",
    ),
    index_pattern: str = typer.Option("wazuh-alerts-4.x-*", help="Index pattern for OpenSearch."),
    event_id: list[int] | None = typer.Option(
        None,
        "--event-id",
        help="Sysmon event ID(s) to include. Repeatable (e.g. --event-id 1 --event-id 3 --event-id 11).",
    ),
    agent_mode: str = typer.Option("any", help="Agent filter mode: any|all."),
    raw_save: str | None = typer.Option(None, help="Optional NDJSON output path for raw hits."),
    log_level: str = typer.Option("INFO", help="Logging level."),
    log_json: bool = typer.Option(True, help="Emit JSON logs."),
    log_file: str | None = typer.Option(None, help="Optional log file path."),
    max_events: int = typer.Option(20000, help="Maximum events to fetch."),
    max_pages: int = typer.Option(200, help="Maximum PIT pages to fetch."),
    fail_on_truncation: bool = typer.Option(False, help="Fail if results are truncated."),
    dry_run_query: bool = typer.Option(
        False,
        "--dry-run-query",
        help="Print resolved query/config and exit before network calls.",
    ),
    config: str | None = typer.Option(None, help="Path to YAML config file."),
):
    _sync_runtime_dependencies()
    run_ctx = RunContext()
    log_path = Path(log_file).resolve() if log_file else None
    setup_logging(log_level, json_format=log_json, out_path=log_path)

    resolved = _resolve_config(
        config,
        None,
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
        None,
        None,
        None,
        None,
    )
    start = resolved["start"]
    end = resolved["end"]
    agent_id = resolved["agent_id"]
    agent_name = resolved["agent_name"]
    out_dir = resolved["out_dir"] or "./out"
    host = resolved["host"]
    user = resolved["user"]
    password = resolved["password"]
    verify_tls = bool(resolved["verify_tls"]) if resolved["verify_tls"] is not None else True
    index_pattern = resolved["index_pattern"] or "wazuh-alerts-4.x-*"
    event_ids = resolved.get("event_ids")

    _validate_required(start, end, agent_id, agent_name)
    if not dry_run_query:
        _validate_opensearch(host, user, password)

    _ensure_out_dir(out_dir)
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
            mode="fetch",
            case_id=run_ctx.case_id,
            out_dir=out_dir,
            query=query_body,
            resolved=resolved,
        )
        return

    logger = logging.getLogger("wazuh_sysmon_triage")
    logger.info(
        "Fetch started",
        extra={
            "event": "fetch_start",
            "stage": "fetch",
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
            "counts": {"agent": 1},
        },
    )

    client = OpenSearchClient(
        base_url=host,
        user=user,
        password=password,
        verify_tls=verify_tls,
    )

    hits = []
    truncation: TruncationInfo = {"truncated": False, "reason": None}
    raw_handle = None
    try:
        if raw_save:
            raw_path = raw_save
            os.makedirs(os.path.dirname(raw_path) or ".", exist_ok=True)
            raw_handle = open(raw_path, "w", encoding="utf-8")

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

    logger.info(
        "Fetch completed",
        extra={
            "event": "fetch_complete",
            "stage": "fetch",
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
            "counts": {"hits": len(hits)},
        },
    )
    typer.echo(f"Fetched {len(hits)} hits")
    _write_run_metadata(
        out_dir,
        {
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
            "version": __version__,
            "start": start,
            "end": end,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "index_pattern": index_pattern,
            "verify_tls": verify_tls,
            "counts": {"raw_hits": len(hits)},
            "truncation": truncation,
            "query": query_body,
        },
    )


@app.command("run")
def run_command(
    profile: str | None = typer.Option(None, help="Optional profile name from config presets."),
    start: str | None = typer.Option(None, help="Start time in ISO8601 format."),
    end: str | None = typer.Option(None, help="End time in ISO8601 format."),
    last: str | None = typer.Option(None, help="Relative lookback window (e.g. 15m, 2h, 7d)."),
    today: bool = typer.Option(False, help="Use UTC today window (00:00 to now)."),
    yesterday: bool = typer.Option(False, help="Use UTC yesterday window (00:00 to 00:00)."),
    agent_id: str | None = typer.Option(None, help="Agent ID."),
    agent_name: str | None = typer.Option(None, help="Agent Name."),
    out_dir: str = typer.Option("./out", help="Output directory."),
    host: str | None = typer.Option(None, help="Host for OpenSearch."),
    user: str | None = typer.Option(None, help="Username for OpenSearch."),
    password: str | None = typer.Option(
        None,
        help="Password for OpenSearch (prefer WAZUH_OS_PASSWORD environment variable).",
    ),
    verify_tls: bool | None = typer.Option(
        None,
        "--verify-tls/--no-verify-tls",
        help="Verify TLS certificate.",
    ),
    index_pattern: str = typer.Option("wazuh-alerts-4.x-*", help="Index pattern for OpenSearch."),
    event_id: list[int] | None = typer.Option(
        None,
        "--event-id",
        help="Sysmon event ID(s) to include. Repeatable (e.g. --event-id 1 --event-id 3 --event-id 11).",
    ),
    agent_mode: str = typer.Option("any", help="Agent filter mode: any|all."),
    raw_save: str | None = typer.Option(None, help="Optional NDJSON output path for raw hits."),
    log_level: str = typer.Option("INFO", help="Logging level."),
    log_json: bool = typer.Option(True, help="Emit JSON logs."),
    log_file: str | None = typer.Option(None, help="Optional log file path."),
    max_events: int = typer.Option(20000, help="Maximum events to fetch."),
    max_pages: int = typer.Option(200, help="Maximum PIT pages to fetch."),
    fail_on_truncation: bool = typer.Option(False, help="Fail if results are truncated."),
    print_stats: bool | None = typer.Option(
        None,
        "--print-stats/--no-print-stats",
        help="Print a summary table after the run.",
    ),
    case_id: str | None = typer.Option(None, help="Optional case ID for case bundle output."),
    input_ndjson: str | None = typer.Option(None, help="Run offline from NDJSON hits."),
    min_alert_score: int | None = typer.Option(
        None,
        help="Minimum score for emitted alerts (0-100). Overrides config if set.",
    ),
    allowlist_image: list[str] | None = typer.Option(
        None,
        "--allowlist-image",
        help="Image basename to hard-suppress alerts. Repeatable; overrides config if provided.",
    ),
    queue: list[str] | None = typer.Option(
        None,
        "--queue",
        help="Queue(s) to include (repeatable): soc_malware|soc_policy|soc_dev|soc_info.",
    ),
    include_dev_queue: bool | None = typer.Option(
        None,
        "--include-dev-queue/--no-include-dev-queue",
        help="Include soc_dev queue in emitted alerts.",
    ),
    alerts_only: bool | None = typer.Option(
        None,
        "--alerts-only/--no-alerts-only",
        help="Print alerts to console after run.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Print per-alert scoring/routing explanations after run.",
    ),
    explain_alert: str | None = typer.Option(
        None,
        "--explain-alert",
        help="Explain a single emitted alert ID (e.g. A003).",
    ),
    quarantine_drops: bool = typer.Option(
        False,
        "--quarantine-drops",
        help="Write dropped events with reasons to quarantine.ndjson.",
    ),
    sanitize: bool = typer.Option(
        False,
        "--sanitize",
        help="Sanitize outputs for publish-safe sharing (users/home paths/internal IPs).",
    ),
    dry_run_query: bool = typer.Option(
        False,
        "--dry-run-query",
        help="Print resolved query/config and exit before fetching.",
    ),
    config: str | None = typer.Option(None, help="Path to YAML config file."),
):
    _sync_runtime_dependencies()
    typer.echo(
        "[hint] `triage run` remains supported; prefer `triage live` or `triage offline` for shorter commands."
    )
    _execute_run(
        profile=profile,
        start=start,
        end=end,
        last=last,
        today=today,
        yesterday=yesterday,
        agent_id=agent_id,
        agent_name=agent_name,
        out_dir=out_dir,
        host=host,
        user=user,
        password=password,
        verify_tls=verify_tls,
        index_pattern=index_pattern,
        event_id=event_id,
        agent_mode=agent_mode,
        raw_save=raw_save,
        log_level=log_level,
        log_json=log_json,
        log_file=log_file,
        max_events=max_events,
        max_pages=max_pages,
        fail_on_truncation=fail_on_truncation,
        print_stats=print_stats,
        case_id=case_id,
        input_ndjson=input_ndjson,
        min_alert_score=min_alert_score,
        allowlist_image=allowlist_image,
        alert_queues=queue,
        include_dev_queue=include_dev_queue,
        alerts_only=alerts_only,
        explain=explain,
        explain_alert=explain_alert,
        quarantine_drops=quarantine_drops,
        sanitize=sanitize,
        dry_run_query=dry_run_query,
        default_last_window=None,
        config=config,
    )


@app.command("live")
def live_command(
    profile: str | None = typer.Option("soc", help="Optional profile name from config presets."),
    start: str | None = typer.Option(None, help="Start time in ISO8601 format."),
    end: str | None = typer.Option(None, help="End time in ISO8601 format."),
    last: str | None = typer.Option(
        None,
        help="Relative lookback window (e.g. 15m, 2h, 7d). Defaults to 2h when no window flags are provided.",
    ),
    today: bool = typer.Option(False, help="Use UTC today window (00:00 to now)."),
    yesterday: bool = typer.Option(False, help="Use UTC yesterday window (00:00 to 00:00)."),
    agent_id: str | None = typer.Option(None, help="Agent ID."),
    agent_name: str | None = typer.Option(None, help="Agent Name."),
    out_dir: str = typer.Option("./out", help="Output directory."),
    host: str | None = typer.Option(None, help="Host for OpenSearch."),
    user: str | None = typer.Option(None, help="Username for OpenSearch."),
    password: str | None = typer.Option(
        None,
        help="Password for OpenSearch (prefer WAZUH_OS_PASSWORD environment variable).",
    ),
    verify_tls: bool | None = typer.Option(
        None,
        "--verify-tls/--no-verify-tls",
        help="Verify TLS certificate.",
    ),
    index_pattern: str = typer.Option("wazuh-alerts-4.x-*", help="Index pattern for OpenSearch."),
    event_id: list[int] | None = typer.Option(
        None, "--event-id", help="Repeatable Sysmon event IDs."
    ),
    agent_mode: str = typer.Option("any", help="Agent filter mode: any|all."),
    raw_save: str | None = typer.Option(None, help="Optional NDJSON output path for raw hits."),
    log_level: str = typer.Option("INFO", help="Logging level."),
    log_json: bool = typer.Option(True, help="Emit JSON logs."),
    log_file: str | None = typer.Option(None, help="Optional log file path."),
    max_events: int = typer.Option(20000, help="Maximum events to fetch."),
    max_pages: int = typer.Option(200, help="Maximum PIT pages to fetch."),
    fail_on_truncation: bool = typer.Option(False, help="Fail if results are truncated."),
    print_stats: bool | None = typer.Option(
        None,
        "--print-stats/--no-print-stats",
        help="Print a summary table after the run.",
    ),
    case_id: str | None = typer.Option(None, help="Optional case ID for case bundle output."),
    min_alert_score: int | None = typer.Option(
        None, help="Minimum score for emitted alerts (0-100)."
    ),
    allowlist_image: list[str] | None = typer.Option(
        None, "--allowlist-image", help="Repeatable image allowlist."
    ),
    queue: list[str] | None = typer.Option(
        None,
        "--queue",
        help="Queue(s) to include (repeatable): soc_malware|soc_policy|soc_dev|soc_info.",
    ),
    include_dev_queue: bool | None = typer.Option(
        None,
        "--include-dev-queue/--no-include-dev-queue",
        help="Include soc_dev queue in emitted alerts.",
    ),
    alerts_only: bool | None = typer.Option(
        None,
        "--alerts-only/--no-alerts-only",
        help="Print alerts to console after run.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Print per-alert scoring/routing explanations after run.",
    ),
    explain_alert: str | None = typer.Option(
        None,
        "--explain-alert",
        help="Explain a single emitted alert ID (e.g. A003).",
    ),
    quarantine_drops: bool = typer.Option(
        False,
        "--quarantine-drops",
        help="Write dropped events with reasons to quarantine.ndjson.",
    ),
    sanitize: bool = typer.Option(
        False,
        "--sanitize",
        help="Sanitize outputs for publish-safe sharing (users/home paths/internal IPs).",
    ),
    dry_run_query: bool = typer.Option(
        False,
        "--dry-run-query",
        help="Print resolved query/config and exit before fetching.",
    ),
    config: str | None = typer.Option(None, help="Path to YAML config file."),
):
    _sync_runtime_dependencies()
    resolved_config = _resolve_default_config_path(config)

    _execute_run(
        profile=profile,
        start=start,
        end=end,
        last=last,
        today=today,
        yesterday=yesterday,
        agent_id=agent_id,
        agent_name=agent_name,
        out_dir=out_dir,
        host=host,
        user=user,
        password=password,
        verify_tls=verify_tls,
        index_pattern=index_pattern,
        event_id=event_id,
        agent_mode=agent_mode,
        raw_save=raw_save,
        log_level=log_level,
        log_json=log_json,
        log_file=log_file,
        max_events=max_events,
        max_pages=max_pages,
        fail_on_truncation=fail_on_truncation,
        print_stats=print_stats,
        case_id=case_id,
        input_ndjson=None,
        min_alert_score=min_alert_score,
        allowlist_image=allowlist_image,
        alert_queues=queue,
        include_dev_queue=include_dev_queue,
        alerts_only=alerts_only,
        explain=explain,
        explain_alert=explain_alert,
        quarantine_drops=quarantine_drops,
        sanitize=sanitize,
        dry_run_query=dry_run_query,
        default_last_window="2h",
        config=resolved_config,
    )


@app.command("offline")
def offline_command(
    profile: str | None = typer.Option("soc", help="Optional profile name from config presets."),
    input_ndjson: str = typer.Option(..., help="Run offline from NDJSON hits."),
    out_dir: str = typer.Option("./out", help="Output directory."),
    log_level: str = typer.Option("INFO", help="Logging level."),
    log_json: bool = typer.Option(True, help="Emit JSON logs."),
    log_file: str | None = typer.Option(None, help="Optional log file path."),
    max_events: int = typer.Option(20000, help="Maximum events to fetch."),
    fail_on_truncation: bool = typer.Option(False, help="Fail if results are truncated."),
    print_stats: bool | None = typer.Option(
        None,
        "--print-stats/--no-print-stats",
        help="Print a summary table after the run.",
    ),
    case_id: str | None = typer.Option(None, help="Optional case ID for case bundle output."),
    min_alert_score: int | None = typer.Option(
        None, help="Minimum score for emitted alerts (0-100)."
    ),
    allowlist_image: list[str] | None = typer.Option(
        None, "--allowlist-image", help="Repeatable image allowlist."
    ),
    queue: list[str] | None = typer.Option(
        None,
        "--queue",
        help="Queue(s) to include (repeatable): soc_malware|soc_policy|soc_dev|soc_info.",
    ),
    include_dev_queue: bool | None = typer.Option(
        None,
        "--include-dev-queue/--no-include-dev-queue",
        help="Include soc_dev queue in emitted alerts.",
    ),
    alerts_only: bool | None = typer.Option(
        None,
        "--alerts-only/--no-alerts-only",
        help="Print alerts to console after run.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Print per-alert scoring/routing explanations after run.",
    ),
    explain_alert: str | None = typer.Option(
        None,
        "--explain-alert",
        help="Explain a single emitted alert ID (e.g. A003).",
    ),
    quarantine_drops: bool = typer.Option(
        False,
        "--quarantine-drops",
        help="Write dropped events with reasons to quarantine.ndjson.",
    ),
    sanitize: bool = typer.Option(
        False,
        "--sanitize",
        help="Sanitize outputs for publish-safe sharing (users/home paths/internal IPs).",
    ),
    dry_run_query: bool = typer.Option(
        False,
        "--dry-run-query",
        help="Print resolved query/config and exit before reading NDJSON.",
    ),
    config: str | None = typer.Option(None, help="Path to YAML config file."),
):
    _sync_runtime_dependencies()
    resolved_config = _resolve_default_config_path(config)

    _execute_run(
        profile=profile,
        start=None,
        end=None,
        last=None,
        today=False,
        yesterday=False,
        agent_id=None,
        agent_name=None,
        out_dir=out_dir,
        host=None,
        user=None,
        password=None,
        verify_tls=None,
        index_pattern="wazuh-alerts-4.x-*",
        event_id=None,
        agent_mode="any",
        raw_save=None,
        log_level=log_level,
        log_json=log_json,
        log_file=log_file,
        max_events=max_events,
        max_pages=200,
        fail_on_truncation=fail_on_truncation,
        print_stats=print_stats,
        case_id=case_id,
        input_ndjson=input_ndjson,
        min_alert_score=min_alert_score,
        allowlist_image=allowlist_image,
        alert_queues=queue,
        include_dev_queue=include_dev_queue,
        alerts_only=alerts_only,
        explain=explain,
        explain_alert=explain_alert,
        quarantine_drops=quarantine_drops,
        sanitize=sanitize,
        dry_run_query=dry_run_query,
        default_last_window=None,
        config=resolved_config,
    )


if __name__ == "__main__":
    app()
