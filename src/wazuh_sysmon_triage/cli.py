from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from time import perf_counter
from typing import TypedDict

import typer

from wazuh_sysmon_triage import __version__
from wazuh_sysmon_triage.clients.opensearch_client import OpenSearchClient
from wazuh_sysmon_triage.config import load_config
from wazuh_sysmon_triage.logging import setup_logging
from wazuh_sysmon_triage.pipeline.correlate import correlate_data
from wazuh_sysmon_triage.pipeline.fetch import build_sysmon_query, fetch_sysmon_events
from wazuh_sysmon_triage.pipeline.normalize import normalize_data
from wazuh_sysmon_triage.pipeline.render import (
    render_process_tree,
    render_report,
    render_timeline,
)
from wazuh_sysmon_triage.runtime import RunContext, timed


class TruncationInfo(TypedDict):
    truncated: bool
    reason: str | None


app = typer.Typer(help="SOC triage CLI for Wazuh Sysmon data.")


def _ensure_out_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _write_run_metadata(out_dir: str, payload: dict) -> None:
    path = os.path.join(out_dir, "run_metadata.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


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


def _resolve_config(
    config_path: str | None,
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
) -> dict:
    cfg = {}
    if config_path:
        loaded = load_config(config_path)
        cfg = loaded.model_dump()

    resolved = {
        "start": start or cfg.get("start"),
        "end": end or cfg.get("end"),
        "agent_id": agent_id or cfg.get("agent_id"),
        "agent_name": agent_name or cfg.get("agent_name"),
        "out_dir": out_dir or cfg.get("out_dir"),
        "host": host or os.getenv("WAZUH_OS_HOST") or cfg.get("host"),
        "user": user or os.getenv("WAZUH_OS_USER") or cfg.get("user"),
        "password": password or os.getenv("WAZUH_OS_PASSWORD") or cfg.get("password"),
        "verify_tls": verify_tls if verify_tls is not None else cfg.get("verify_tls"),
        "index_pattern": index_pattern or cfg.get("index_pattern"),
        "event_ids": event_ids or cfg.get("event_ids"),
    }
    return resolved


@app.command("fetch")
def fetch_command(
    start: str | None = typer.Option(None, help="Start time in ISO8601 format."),
    end: str | None = typer.Option(None, help="End time in ISO8601 format."),
    agent_id: str | None = typer.Option(None, help="Agent ID."),
    agent_name: str | None = typer.Option(None, help="Agent Name."),
    out_dir: str = typer.Option("./out", help="Output directory."),
    host: str | None = typer.Option(None, help="Host for OpenSearch."),
    user: str | None = typer.Option(None, help="Username for OpenSearch."),
    password: str | None = typer.Option(None, help="Password for OpenSearch."),
    verify_tls: bool = typer.Option(True, help="Verify TLS certificate."),
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
    config: str | None = typer.Option(None, help="Path to YAML config file."),
):
    run_ctx = RunContext()
    log_path = Path(log_file).resolve() if log_file else None
    setup_logging(log_level, json=log_json, out_path=log_path)

    resolved = _resolve_config(
        config,
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
            event_ids=tuple(event_ids) if event_ids else (1, 11),
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
            "version": __version__,
            "start": start,
            "end": end,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "index_pattern": index_pattern,
            "counts": {"raw_hits": len(hits)},
            "truncation": truncation,
            "query": query_body,
        },
    )


@app.command("run")
def run_command(
    start: str | None = typer.Option(None, help="Start time in ISO8601 format."),
    end: str | None = typer.Option(None, help="End time in ISO8601 format."),
    agent_id: str | None = typer.Option(None, help="Agent ID."),
    agent_name: str | None = typer.Option(None, help="Agent Name."),
    out_dir: str = typer.Option("./out", help="Output directory."),
    host: str | None = typer.Option(None, help="Host for OpenSearch."),
    user: str | None = typer.Option(None, help="Username for OpenSearch."),
    password: str | None = typer.Option(None, help="Password for OpenSearch."),
    verify_tls: bool = typer.Option(True, help="Verify TLS certificate."),
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
    print_stats: bool = typer.Option(False, help="Print a summary table after the run."),
    case_id: str | None = typer.Option(None, help="Optional case ID for case bundle output."),
    input_ndjson: str | None = typer.Option(None, help="Run offline from NDJSON hits."),
    config: str | None = typer.Option(None, help="Path to YAML config file."),
):
    run_ctx = RunContext(case_id=case_id)
    setup_logging(log_level, json=log_json, out_path=None)
    resolved = _resolve_config(
        config,
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

    if not input_ndjson:
        _validate_required(start, end, agent_id, agent_name)
        _validate_opensearch(host, user, password)

    if case_id:
        out_dir = os.path.join(out_dir, case_id)
    _ensure_out_dir(out_dir)
    if not log_file:
        log_file = os.path.join(out_dir, "run.log.ndjson")
    setup_logging(log_level, json=log_json, out_path=Path(log_file))

    total_start = perf_counter()

    if input_ndjson:
        query_body = {"input_ndjson": input_ndjson}
    else:
        query_body = build_sysmon_query(
            start=start,
            end=end,
            agent_id=agent_id,
            agent_name=agent_name,
            agent_mode=agent_mode,
            event_ids=event_ids,
        )

    logger = logging.getLogger("wazuh_sysmon_triage")
    hits = []
    truncation: TruncationInfo = {"truncated": False, "reason": None}
    raw_handle = None
    fetch_duration_ms = 0
    try:
        with timed("fetch", logger, run_ctx) as timer:
            if input_ndjson:
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
                    event_ids=tuple(event_ids) if event_ids else (1, 11),
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
        if not input_ndjson:
            client.close()
    fetch_duration_ms = timer["duration_ms"]

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

    normalize_duration_ms = 0
    correlate_duration_ms = 0
    render_duration_ms = 0

    logger.info(
        "Normalize start",
        extra={
            "event": "normalize_start",
            "stage": "normalize",
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
        },
    )
    with timed("normalize", logger, run_ctx) as timer:
        normalized = normalize_data(hits)
        counts_by_eid: dict[str, int] = {}
        for event in normalized:
            counts_by_eid[str(event.event_id)] = counts_by_eid.get(str(event.event_id), 0) + 1
    normalize_duration_ms = timer["duration_ms"]
    logger.info(
        "Normalize complete",
        extra={
            "event": "normalize_complete",
            "stage": "normalize",
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
            "counts": counts_by_eid,
        },
    )
    with timed("correlate", logger, run_ctx) as timer:
        correlation = correlate_data(normalized)
    correlate_duration_ms = timer["duration_ms"]
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
    with timed("render", logger, run_ctx) as timer:
        render_timeline(normalized, out_dir)
        render_process_tree(correlation, out_dir)
        render_report(
            {
                **correlation,
                "events": normalized,
                "query": query_body,
                "case_id": case_id,
                "truncation": truncation,
            },
            out_dir,
        )
    render_duration_ms = timer["duration_ms"]
    logger.info(
        "Render complete",
        extra={
            "event": "render_complete",
            "stage": "render",
            "run_id": run_ctx.run_id,
            "case_id": run_ctx.case_id,
            "counts": {"outputs": 3, "out_dir": out_dir},
        },
    )

    total_duration_ms = int((perf_counter() - total_start) * 1000)

    if case_id:
        with open(os.path.join(out_dir, "query.json"), "w", encoding="utf-8") as handle:
            json.dump(query_body, handle, indent=2)
        with open(os.path.join(out_dir, "stats.json"), "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "hits": len(hits),
                    "events_by_type": {
                        "process_create": len([e for e in normalized if e.event_id == 1]),
                        "file_create": len([e for e in normalized if e.event_id == 11]),
                    },
                    "artifacts": len(correlation.get("artifacts", [])),
                    "nodes": len(correlation.get("nodes", [])),
                    "edges": len(correlation.get("edges", [])),
                    "truncation": truncation,
                    "fetch_duration_ms": fetch_duration_ms,
                    "normalize_duration_ms": normalize_duration_ms,
                    "correlate_duration_ms": correlate_duration_ms,
                    "render_duration_ms": render_duration_ms,
                    "total_duration_ms": total_duration_ms,
                },
                handle,
                indent=2,
            )

    _write_run_metadata(
        out_dir,
        {
            "version": __version__,
            "start": start,
            "end": end,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "index_pattern": index_pattern,
            "counts": {
                "raw_hits": len(hits),
                "normalized_events": len(normalized),
                "artifacts": len(correlation.get("artifacts", [])),
                "nodes": len(correlation.get("nodes", [])),
                "edges": len(correlation.get("edges", [])),
            },
            "truncation": truncation,
            "fetch_duration_ms": fetch_duration_ms,
            "normalize_duration_ms": normalize_duration_ms,
            "correlate_duration_ms": correlate_duration_ms,
            "render_duration_ms": render_duration_ms,
            "total_duration_ms": total_duration_ms,
            "query": query_body,
        },
    )

    if print_stats:
        normalized_summary = (
            ", ".join(f"{eid}: {count}" for eid, count in sorted(counts_by_eid.items())) or "none"
        )
        suspicious_destinations = sum(
            1 for entry in correlation.get("network_activity", []) if entry.get("suspicious")
        )
        summary_rows = [
            ("Fetched hits", str(len(hits))),
            ("Normalized by EID", normalized_summary),
            ("Artifacts", str(len(correlation.get("artifacts", [])))),
            ("Suspicious destinations", str(suspicious_destinations)),
            ("Total duration (ms)", str(total_duration_ms)),
        ]
        width = max(len(label) for label, _ in summary_rows)
        for label, value in summary_rows:
            typer.echo(f"{label.ljust(width)} : {value}")

    typer.echo("Run complete")


if __name__ == "__main__":
    app()
