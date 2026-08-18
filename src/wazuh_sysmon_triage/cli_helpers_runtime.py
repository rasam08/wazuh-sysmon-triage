from __future__ import annotations

import json
import logging
import os

import typer

from wazuh_sysmon_triage.clients.opensearch_client import OpenSearchClient
from wazuh_sysmon_triage.models.raw import RawHit
from wazuh_sysmon_triage.pipeline.fetch import DEFAULT_EVENT_IDS, fetch_sysmon_events
from wazuh_sysmon_triage.pipeline.ndjson import (
    DEFAULT_MAX_RECORD_BYTES,
    InputQualityReport,
    read_ndjson,
)
from wazuh_sysmon_triage.runtime import RunContext, timed
from wazuh_sysmon_triage.sanitize import OutputSanitizer

from . import cli_helpers_runtime_config as _config
from . import cli_helpers_runtime_output as _output
from . import cli_helpers_runtime_stages as _stages
from . import cli_helpers_runtime_utils as _utils
from .cli_helpers_runtime_types import *  # noqa: F401,F403
from .cli_helpers_runtime_types import FetchStageResult, TruncationInfo
from .cli_helpers_runtime_utils import *  # noqa: F401,F403

app = typer.Typer(help="SOC triage CLI for Wazuh Sysmon data.")

_build_run_metadata_payload = _output._build_run_metadata_payload
_emit_dry_run = _output._emit_dry_run
_ensure_out_dir = _utils._ensure_out_dir
_generate_case_id = _utils._generate_case_id
_parse_iso_ts = _utils._parse_iso_ts
_parse_last_duration = _utils._parse_last_duration
_print_alert_explanations = _output._print_alert_explanations
_print_alert_list = _output._print_alert_list
_print_stats_summary = _output._print_stats_summary
_process_line = _utils._process_line
_rebase_scenario_gym_hits_to_now = _utils._rebase_scenario_gym_hits_to_now
_resolve_config = _config._resolve_config
_resolve_default_config_path = _utils._resolve_default_config_path
_resolve_time_window = _utils._resolve_time_window
_run_correlate_stage = _stages._run_correlate_stage
_run_detect_stage = _stages._run_detect_stage
_run_normalize_stage = _stages._run_normalize_stage
_run_render_stage = _stages._run_render_stage
_safe_case_id = _utils._safe_case_id
_validate_opensearch = _config._validate_opensearch
_validate_required = _config._validate_required
_write_query_json = _output._write_query_json
_write_run_metadata = _output._write_run_metadata
_write_stats_json = _output._write_stats_json


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
    out_dir: str,
    quarantine_drops: bool,
    sanitizer: OutputSanitizer | None,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
) -> FetchStageResult:
    hits: list[RawHit] = []
    truncation: TruncationInfo = {"truncated": False, "reason": None}
    raw_handle = None
    client = None
    duration_ms = 0
    input_quality: InputQualityReport | None = None

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
                quarantine_handle = None
                quarantine_path = os.path.join(out_dir, "quarantine.ndjson")
                with open(quarantine_path, "w", encoding="utf-8"):
                    pass

                def write_rejection(payload: dict[str, object]) -> None:
                    nonlocal quarantine_handle
                    if quarantine_handle is None:
                        quarantine_handle = open(quarantine_path, "w", encoding="utf-8")
                    output_payload: object = payload
                    if sanitizer:
                        output_payload = sanitizer.sanitize_obj(payload)
                    quarantine_handle.write(json.dumps(output_payload))
                    quarantine_handle.write("\n")

                try:
                    read_result = read_ndjson(
                        input_ndjson,
                        max_events=max_events,
                        max_record_bytes=max_record_bytes,
                        on_rejection=write_rejection,
                        include_raw_line=quarantine_drops,
                    )
                finally:
                    if quarantine_handle is not None:
                        quarantine_handle.close()
                hits = read_result.hits
                input_quality = read_result.report
                truncation = {
                    "truncated": input_quality.truncated,
                    "reason": input_quality.truncation_reason,
                }

                if _utils._is_scenario_gym_path(input_ndjson):
                    rebased, shifted_fields = _utils._rebase_scenario_gym_hits_to_now(hits)
                    if rebased:
                        _utils._process_line(
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
                        "counts": {
                            "hits": len(hits),
                            "input_rejected": input_quality.rejected_records,
                            "input_blank": input_quality.blank_lines,
                        },
                    },
                )
            else:
                _utils._process_line("fetch (live)", "querying opensearch...")
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

    return FetchStageResult(
        hits=hits,
        truncation=truncation,
        duration_ms=duration_ms,
        input_quality=input_quality,
    )
