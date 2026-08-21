from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer

from wazuh_sysmon_triage import __version__
from wazuh_sysmon_triage import cli_helpers as _cli_helpers
from wazuh_sysmon_triage.cli_helpers import (
    TruncationInfo,
    _emit_dry_run,
    _ensure_out_dir,
    _resolve_config,
    _resolve_default_config_path,
    _safe_case_id,
    _validate_opensearch,
    _validate_required,
    _write_run_metadata,
)
from wazuh_sysmon_triage.clients.opensearch_client import OpenSearchClient
from wazuh_sysmon_triage.logging import setup_logging
from wazuh_sysmon_triage.pipeline.case_view import (
    CaseViewError,
    build_case_overview,
    build_process_view,
    load_case_artifacts,
    render_case_overview_text,
    render_process_view_text,
)
from wazuh_sysmon_triage.pipeline.fetch import (
    DEFAULT_EVENT_IDS,
    build_sysmon_query,
    fetch_sysmon_events,
)
from wazuh_sysmon_triage.pipeline.investigate import fetch_investigation_anchor
from wazuh_sysmon_triage.pipeline.ndjson import DEFAULT_MAX_RECORD_BYTES
from wazuh_sysmon_triage.pipeline.orchestrator import _execute_run
from wazuh_sysmon_triage.runtime import RunContext

app = typer.Typer(help="SOC triage CLI for Wazuh Sysmon data.")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"wazuh-sysmon-triage {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed package version and exit.",
    ),
) -> None:
    """Investigate Windows endpoint telemetry collected by Wazuh."""
    del version

# Backwards-compatible helper exports used by tests and scripts.
_parse_iso_ts = _cli_helpers._parse_iso_ts
_parse_last_duration = _cli_helpers._parse_last_duration
_rebase_scenario_gym_hits_to_now = _cli_helpers._rebase_scenario_gym_hits_to_now
_resolve_time_window = _cli_helpers._resolve_time_window


def _emit_saved_view(
    payload: dict[str, Any],
    *,
    output_format: str,
    output: str | None,
    text_renderer: Callable[[dict[str, Any]], str],
) -> None:
    normalized_format = output_format.strip().lower()
    if normalized_format not in {"text", "json"}:
        raise typer.BadParameter("--format must be text or json", param_hint="--format")
    rendered = (
        json.dumps(payload, indent=2, sort_keys=True)
        if normalized_format == "json"
        else text_renderer(payload)
    )
    if output:
        output_path = Path(output)
        if not output_path.parent.is_dir():
            raise typer.BadParameter(
                f"Output parent directory does not exist: {output_path.parent}",
                param_hint="--output",
            )
        output_path.write_text(rendered + "\n", encoding="utf-8")
        return
    typer.echo(rendered)


def _sync_runtime_dependencies() -> None:
    # _run_fetch_stage resolves these as module globals, so tests that patch them on this
    # module take effect there too. setattr keeps mypy from rejecting the class rebind.
    for attr_name, dependency in (
        ("OpenSearchClient", OpenSearchClient),
        ("fetch_sysmon_events", fetch_sysmon_events),
    ):
        setattr(_cli_helpers, attr_name, dependency)


@app.command("fetch")
def fetch_command(
    start: str | None = typer.Option(None, help="Start time in ISO8601 format."),
    end: str | None = typer.Option(None, help="End time in ISO8601 format."),
    agent_id: str | None = typer.Option(None, help="Agent ID."),
    agent_name: str | None = typer.Option(None, help="Agent Name."),
    out_dir: str | None = typer.Option(None, help="Output directory (default: ./out)."),
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
    index_pattern: str | None = typer.Option(
        None,
        help="Index pattern for OpenSearch (default: wazuh-alerts-4.x-*).",
    ),
    event_id: list[int] | None = typer.Option(
        None,
        "--event-id",
        help="Windows event ID(s) to include. Repeatable; defaults to the supported evidence set.",
    ),
    agent_mode: str = typer.Option("all", help="Agent filter mode: all|any."),
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
            event_ids=tuple(event_ids) if event_ids else DEFAULT_EVENT_IDS,
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


@app.command("alert")
def alert_command(
    document_id: str = typer.Argument(..., help="OpenSearch _id of the triggering Wazuh alert."),
    before: str = typer.Option("5m", help="Context to collect before the alert (e.g. 5m, 1h)."),
    after: str = typer.Option("10m", help="Context to collect after the alert (e.g. 10m, 1h)."),
    profile: str | None = typer.Option("soc", help="Optional profile name from config presets."),
    out_dir: str | None = typer.Option(None, help="Output directory (default: ./out)."),
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
    index_pattern: str | None = typer.Option(None, help="Index pattern for OpenSearch."),
    context_index_pattern: str | None = typer.Option(
        None,
        help=(
            "Optional separate index pattern for surrounding context, such as indexed "
            "wazuh-archives-* data. The triggering alert is still resolved from --index-pattern."
        ),
    ),
    raw_save: str | None = typer.Option(None, help="Optional NDJSON output path for context hits."),
    max_events: int = typer.Option(20000, help="Maximum contextual events to fetch."),
    max_pages: int = typer.Option(200, help="Maximum contextual pages to fetch."),
    fail_on_truncation: bool = typer.Option(
        True,
        "--fail-on-truncation/--allow-truncation",
        help="Fail by default when contextual evidence is incomplete.",
    ),
    case_id: str | None = typer.Option(None, help="Optional case ID."),
    explain: bool = typer.Option(True, "--explain/--no-explain", help="Explain findings."),
    quarantine_drops: bool = typer.Option(
        True,
        "--quarantine-drops/--no-quarantine-drops",
        help="Preserve malformed or unsupported contextual events.",
    ),
    sanitize: bool = typer.Option(False, help="Sanitize publishable output."),
    log_level: str = typer.Option("INFO", help="Logging level."),
    log_json: bool = typer.Option(True, help="Emit JSON logs."),
    config: str | None = typer.Option(None, help="Path to YAML config file."),
) -> None:
    """Reconstruct endpoint context around one triggering Wazuh alert."""
    _sync_runtime_dependencies()
    before_delta = _parse_last_duration(before, option_name="--before")
    after_delta = _parse_last_duration(after, option_name="--after")
    resolved_config = _resolve_default_config_path(config)
    resolved = _resolve_config(
        resolved_config,
        profile,
        None,
        None,
        None,
        None,
        out_dir,
        host,
        user,
        password,
        verify_tls,
        index_pattern,
        None,
        None,
        True,
        True,
    )
    host = resolved.get("host")
    user = resolved.get("user")
    password = resolved.get("password")
    verify_tls = bool(resolved.get("verify_tls"))
    index_pattern = resolved.get("index_pattern") or "wazuh-alerts-4.x-*"
    alert_index_pattern = index_pattern
    resolved_context_pattern = context_index_pattern or alert_index_pattern
    _validate_opensearch(host, user, password)
    assert isinstance(host, str)
    assert isinstance(user, str)
    assert isinstance(password, str)

    selected_case_id = _safe_case_id(case_id or f"alert-{document_id}")
    lookup_context = RunContext(case_id=selected_case_id)
    setup_logging(log_level, json_format=log_json, out_path=None)
    client = OpenSearchClient(
        base_url=host,
        user=user,
        password=password,
        verify_tls=verify_tls,
    )
    try:
        anchor = fetch_investigation_anchor(
            client,
            index_pattern=alert_index_pattern,
            document_id=document_id,
            run_id=lookup_context.run_id,
            case_id=selected_case_id,
        )
    except Exception as exc:
        typer.echo(f"Alert lookup failed: {exc}")
        raise typer.Exit(code=3) from exc
    finally:
        client.close()

    start_dt, end_dt = anchor.context_window(before=before_delta, after=after_delta)
    anchor_payload = anchor.to_payload()
    anchor_payload["alert_index_pattern"] = alert_index_pattern
    anchor_payload["context_index_pattern"] = resolved_context_pattern
    anchor_payload["context_source"] = (
        "wazuh_archives"
        if "wazuh-archives" in resolved_context_pattern.lower()
        else "wazuh_alerts"
        if "wazuh-alerts" in resolved_context_pattern.lower()
        else "custom"
    )
    anchor_payload["context_window"] = {
        "start": start_dt.isoformat().replace("+00:00", "Z"),
        "end": end_dt.isoformat().replace("+00:00", "Z"),
        "before": before,
        "after": after,
    }
    typer.echo(
        f"Investigating alert {anchor.document_id} on "
        f"{anchor.agent_name or anchor.agent_id} from {anchor_payload['context_window']['start']} "
        f"to {anchor_payload['context_window']['end']}"
    )
    if context_index_pattern is None and "wazuh-alerts" in resolved_context_pattern.lower():
        typer.echo(
            "Evidence caveat: context is being collected from Wazuh alert indices; events that "
            "did not trigger a rule may be absent. Use --context-index-pattern for indexed archives."
        )

    _execute_run(
        profile=profile,
        start=anchor_payload["context_window"]["start"],
        end=anchor_payload["context_window"]["end"],
        last=None,
        today=False,
        yesterday=False,
        agent_id=anchor.agent_id,
        agent_name=anchor.agent_name,
        out_dir=resolved.get("out_dir") or "./out",
        host=host,
        user=user,
        password=password,
        verify_tls=verify_tls,
        index_pattern=resolved_context_pattern,
        event_id=list(DEFAULT_EVENT_IDS),
        agent_mode="all",
        raw_save=raw_save,
        log_level=log_level,
        log_json=log_json,
        log_file=None,
        max_events=max_events,
        max_pages=max_pages,
        fail_on_truncation=fail_on_truncation,
        fail_on_input_errors=False,
        max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
        print_stats=True,
        case_id=selected_case_id,
        input_ndjson=None,
        allowlist_image=None,
        alerts_only=True,
        explain=explain,
        explain_alert=None,
        quarantine_drops=quarantine_drops,
        sanitize=sanitize,
        dry_run_query=False,
        default_last_window=None,
        config=resolved_config,
        investigation_anchor=anchor_payload,
    )


@app.command("case")
def case_command(
    case_dir: str = typer.Argument(..., help="Saved case directory containing case artifacts."),
    output_format: str = typer.Option("text", "--format", help="Output format: text or json."),
    output: str | None = typer.Option(None, help="Optional output file; stdout is the default."),
) -> None:
    """Summarize a saved case and identify evidence-backed process pivots."""
    try:
        payload = build_case_overview(load_case_artifacts(case_dir))
    except CaseViewError as exc:
        typer.echo(f"Case inspection failed: {exc}", err=True)
        raise typer.Exit(code=4) from exc
    _emit_saved_view(
        payload,
        output_format=output_format,
        output=output,
        text_renderer=render_case_overview_text,
    )


@app.command("process")
def process_command(
    process_guid: str = typer.Argument(..., help="ProcessGuid to investigate."),
    case_dir: str = typer.Option(..., help="Saved case directory containing case artifacts."),
    host_key: str | None = typer.Option(
        None,
        help="Required when the same ProcessGuid appears on more than one host.",
    ),
    include_descendants: bool = typer.Option(
        True,
        "--include-descendants/--no-descendants",
        help="Include activity from descendant processes in the focused scope.",
    ),
    max_depth: int = typer.Option(5, min=0, help="Maximum ancestry and descendant depth."),
    max_events: int = typer.Option(
        200,
        min=1,
        help="Maximum focused timeline events to return; omissions are reported.",
    ),
    output_format: str = typer.Option("text", "--format", help="Output format: text or json."),
    output: str | None = typer.Option(None, help="Optional output file; stdout is the default."),
) -> None:
    """Investigate one process from a saved case without querying Wazuh again."""
    try:
        payload = build_process_view(
            load_case_artifacts(case_dir),
            process_guid,
            host_key=host_key,
            include_descendants=include_descendants,
            max_depth=max_depth,
            max_events=max_events,
        )
    except CaseViewError as exc:
        typer.echo(f"Process inspection failed: {exc}", err=True)
        raise typer.Exit(code=4) from exc
    _emit_saved_view(
        payload,
        output_format=output_format,
        output=output,
        text_renderer=render_process_view_text,
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
    out_dir: str | None = typer.Option(None, help="Output directory (default: ./out)."),
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
    index_pattern: str | None = typer.Option(
        None,
        help="Index pattern for OpenSearch (default: wazuh-alerts-4.x-*).",
    ),
    event_id: list[int] | None = typer.Option(
        None,
        "--event-id",
        help="Sysmon event ID(s) to include. Repeatable; defaults to the supported evidence set.",
    ),
    agent_mode: str = typer.Option("all", help="Agent filter mode: all|any."),
    raw_save: str | None = typer.Option(None, help="Optional NDJSON output path for raw hits."),
    log_level: str = typer.Option("INFO", help="Logging level."),
    log_json: bool = typer.Option(True, help="Emit JSON logs."),
    log_file: str | None = typer.Option(None, help="Optional log file path."),
    max_events: int = typer.Option(20000, help="Maximum events to fetch."),
    max_pages: int = typer.Option(200, help="Maximum PIT pages to fetch."),
    fail_on_truncation: bool = typer.Option(False, help="Fail if results are truncated."),
    fail_on_input_errors: bool = typer.Option(
        False,
        "--fail-on-input-errors",
        help="Write artifacts, then exit 5 if any offline input record is rejected.",
    ),
    max_record_bytes: int = typer.Option(
        DEFAULT_MAX_RECORD_BYTES,
        min=1,
        help="Maximum bytes permitted in one offline NDJSON record.",
    ),
    print_stats: bool | None = typer.Option(
        None,
        "--print-stats/--no-print-stats",
        help="Print a summary table after the run.",
    ),
    case_id: str | None = typer.Option(None, help="Optional case ID for case bundle output."),
    input_ndjson: str | None = typer.Option(None, help="Run offline from NDJSON hits."),
    allowlist_image: list[str] | None = typer.Option(
        None,
        "--allowlist-image",
        help="Image basename to hard-suppress alerts. Repeatable; overrides config if provided.",
    ),
    alerts_only: bool | None = typer.Option(
        None,
        "--alerts-only/--no-alerts-only",
        help="Print alerts to console after run.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Print each finding's rule, evidence strength, and contributing evidence.",
    ),
    explain_alert: str | None = typer.Option(
        None,
        "--explain-alert",
        help="Explain a single emitted alert ID (e.g. A003).",
    ),
    quarantine_drops: bool = typer.Option(
        False,
        "--quarantine-drops",
        help="Include rejected offline raw lines and write normalization drops.",
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
        fail_on_input_errors=fail_on_input_errors,
        max_record_bytes=max_record_bytes,
        print_stats=print_stats,
        case_id=case_id,
        input_ndjson=input_ndjson,
        allowlist_image=allowlist_image,
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
    out_dir: str | None = typer.Option(None, help="Output directory (default: ./out)."),
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
    index_pattern: str | None = typer.Option(
        None,
        help="Index pattern for OpenSearch (default: wazuh-alerts-4.x-*).",
    ),
    event_id: list[int] | None = typer.Option(
        None, "--event-id", help="Repeatable Windows event IDs."
    ),
    agent_mode: str = typer.Option("all", help="Agent filter mode: all|any."),
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
    allowlist_image: list[str] | None = typer.Option(
        None, "--allowlist-image", help="Repeatable image allowlist."
    ),
    alerts_only: bool | None = typer.Option(
        None,
        "--alerts-only/--no-alerts-only",
        help="Print alerts to console after run.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Print each finding's rule, evidence strength, and contributing evidence.",
    ),
    explain_alert: str | None = typer.Option(
        None,
        "--explain-alert",
        help="Explain a single emitted alert ID (e.g. A003).",
    ),
    quarantine_drops: bool = typer.Option(
        False,
        "--quarantine-drops",
        help="Write normalization drops with reasons to quarantine.ndjson.",
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
        fail_on_input_errors=False,
        max_record_bytes=DEFAULT_MAX_RECORD_BYTES,
        print_stats=print_stats,
        case_id=case_id,
        input_ndjson=None,
        allowlist_image=allowlist_image,
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
    out_dir: str | None = typer.Option(None, help="Output directory (default: ./out)."),
    log_level: str = typer.Option("INFO", help="Logging level."),
    log_json: bool = typer.Option(True, help="Emit JSON logs."),
    log_file: str | None = typer.Option(None, help="Optional log file path."),
    max_events: int = typer.Option(20000, help="Maximum events to fetch."),
    fail_on_truncation: bool = typer.Option(False, help="Fail if results are truncated."),
    fail_on_input_errors: bool = typer.Option(
        False,
        "--fail-on-input-errors",
        help="Write artifacts, then exit 5 if any input record is rejected.",
    ),
    max_record_bytes: int = typer.Option(
        DEFAULT_MAX_RECORD_BYTES,
        min=1,
        help="Maximum bytes permitted in one NDJSON record.",
    ),
    print_stats: bool | None = typer.Option(
        None,
        "--print-stats/--no-print-stats",
        help="Print a summary table after the run.",
    ),
    case_id: str | None = typer.Option(None, help="Optional case ID for case bundle output."),
    allowlist_image: list[str] | None = typer.Option(
        None, "--allowlist-image", help="Repeatable image allowlist."
    ),
    alerts_only: bool | None = typer.Option(
        None,
        "--alerts-only/--no-alerts-only",
        help="Print alerts to console after run.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Print each finding's rule, evidence strength, and contributing evidence.",
    ),
    explain_alert: str | None = typer.Option(
        None,
        "--explain-alert",
        help="Explain a single emitted alert ID (e.g. A003).",
    ),
    quarantine_drops: bool = typer.Option(
        False,
        "--quarantine-drops",
        help="Include rejected raw lines and write normalization drops.",
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
        fail_on_input_errors=fail_on_input_errors,
        max_record_bytes=max_record_bytes,
        print_stats=print_stats,
        case_id=case_id,
        input_ndjson=input_ndjson,
        allowlist_image=allowlist_image,
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
