from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from wazuh_sysmon_triage.operations import (
    _percentile,
    _read_json_lines,
    apply_artifact_retention,
    build_telemetry_summary,
    parse_optional_bool,
    record_run_telemetry,
)


def _create_case_dir(root: Path, case_id: str, *, size_bytes: int, age_days: int) -> Path:
    case_dir = root / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "run_metadata.json").write_text(json.dumps({"case_id": case_id}), encoding="utf-8")
    payload = "X" * size_bytes
    (case_dir / "blob.bin").write_text(payload, encoding="utf-8")
    old_ts = (datetime.now(tz=UTC) - timedelta(days=age_days)).timestamp()
    os.utime(case_dir, (old_ts, old_ts))
    os.utime(case_dir / "run_metadata.json", (old_ts, old_ts))
    os.utime(case_dir / "blob.bin", (old_ts, old_ts))
    return case_dir


def test_parse_optional_bool() -> None:
    assert parse_optional_bool("true") is True
    assert parse_optional_bool("False") is False
    assert parse_optional_bool("1") is True
    assert parse_optional_bool("0") is False
    assert parse_optional_bool("unknown") is None
    assert parse_optional_bool(None) is None


def test_record_run_telemetry_creates_history_and_summary(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    summary = record_run_telemetry(
        out_root=out_root,
        run_id="run-success-1",
        case_id="case-success-1",
        mode="live",
        profile="soc",
        success=True,
        stage_durations={"fetch": 10, "normalize": 5, "correlate": 4, "detect": 3, "render": 2},
        total_duration_ms=30,
    )
    record_run_telemetry(
        out_root=out_root,
        run_id="run-fail-1",
        case_id="case-fail-1",
        mode="live",
        profile="soc",
        success=False,
        stage_durations={"fetch": 1, "normalize": 0, "correlate": 0, "detect": 0, "render": 0},
        total_duration_ms=5,
        failure_reason="fetch:exit_3",
    )

    history_path = out_root / "telemetry_history.ndjson"
    summary_path = out_root / "telemetry_summary.json"
    assert history_path.exists()
    assert summary_path.exists()

    saved_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["total_runs"] >= 1
    assert saved_summary["total_runs"] == 2
    assert saved_summary["successful_runs"] == 1
    assert saved_summary["failed_runs"] == 1
    assert saved_summary["success_rate"] == 0.5
    assert saved_summary["top_failure_reasons"][0]["reason"] == "fetch:exit_3"
    assert saved_summary["last_successful_live_fetch_at"]


def test_artifact_retention_prunes_old_case_dirs(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    out_root.mkdir(parents=True, exist_ok=True)
    _create_case_dir(out_root, "case-recent", size_bytes=512, age_days=1)
    _create_case_dir(out_root, "case-old", size_bytes=1024, age_days=45)

    result = apply_artifact_retention(
        out_root=out_root,
        current_case_id=None,
        policy={
            "enabled": True,
            "max_age_days": 30,
            "max_total_size_mb": 100,
            "min_keep_runs": 0,
        },
    )

    assert result["enabled"] is True
    assert "case-old" in result["removed_cases"]
    assert (out_root / "case-recent").exists()
    assert not (out_root / "case-old").exists()


def test_size_based_retention(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    out_root.mkdir(parents=True, exist_ok=True)
    _create_case_dir(out_root, "case-1-oldest", size_bytes=700_000, age_days=40)
    _create_case_dir(out_root, "case-2-old", size_bytes=700_000, age_days=30)
    _create_case_dir(out_root, "case-3-new", size_bytes=700_000, age_days=20)
    _create_case_dir(out_root, "case-4-newest", size_bytes=700_000, age_days=10)

    result = apply_artifact_retention(
        out_root=out_root,
        current_case_id=None,
        policy={
            "enabled": True,
            "max_age_days": 0,
            "max_total_size_mb": 2,
            "min_keep_runs": 0,
        },
    )

    assert set(result["removed_cases"]) == {"case-1-oldest", "case-2-old"}
    assert not (out_root / "case-1-oldest").exists()
    assert not (out_root / "case-2-old").exists()
    assert (out_root / "case-3-new").exists()
    assert (out_root / "case-4-newest").exists()


def test_min_keep_runs_protection(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    out_root.mkdir(parents=True, exist_ok=True)
    _create_case_dir(out_root, "case-a", size_bytes=1024, age_days=120)
    _create_case_dir(out_root, "case-b", size_bytes=1024, age_days=110)
    _create_case_dir(out_root, "case-c", size_bytes=1024, age_days=100)

    result = apply_artifact_retention(
        out_root=out_root,
        current_case_id=None,
        policy={
            "enabled": True,
            "max_age_days": 1,
            "max_total_size_mb": 0,
            "min_keep_runs": 3,
        },
    )

    assert result["removed_cases"] == []
    assert (out_root / "case-a").exists()
    assert (out_root / "case-b").exists()
    assert (out_root / "case-c").exists()


def test_retention_disabled(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    out_root.mkdir(parents=True, exist_ok=True)
    _create_case_dir(out_root, "case-a", size_bytes=1024, age_days=45)
    _create_case_dir(out_root, "case-b", size_bytes=1024, age_days=30)

    result = apply_artifact_retention(
        out_root=out_root,
        current_case_id=None,
        policy={"enabled": False, "max_age_days": 1, "max_total_size_mb": 1, "min_keep_runs": 0},
    )

    assert result["enabled"] is False
    assert result["removed_cases"] == []
    assert (out_root / "case-a").exists()
    assert (out_root / "case-b").exists()


def test_percentile_edge_cases() -> None:
    assert _percentile([], 0.5) == 0
    assert _percentile([42], 0.95) == 42
    assert _percentile([50, 10, 40, 20, 30], 0.5) == 30


def test_read_json_lines_truncation(tmp_path: Path) -> None:
    history_path = tmp_path / "telemetry_history.ndjson"
    history_path.write_text(
        "\n".join(json.dumps({"index": i}, separators=(",", ":")) for i in range(6000)) + "\n",
        encoding="utf-8",
    )

    rows = _read_json_lines(history_path, max_entries=5000)

    assert len(rows) == 5000
    assert rows[0]["index"] == 1000
    assert rows[-1]["index"] == 5999

    rewritten = history_path.read_text(encoding="utf-8").splitlines()
    assert len(rewritten) == 5000
    assert json.loads(rewritten[0])["index"] == 1000
    assert json.loads(rewritten[-1])["index"] == 5999


def test_build_telemetry_summary_empty() -> None:
    summary = build_telemetry_summary([])

    assert summary["total_runs"] == 0
    assert summary["successful_runs"] == 0
    assert summary["failed_runs"] == 0
    assert summary["success_rate"] == 0.0
    assert summary["top_failure_reasons"] == []
    assert summary["last_successful_live_fetch_at"] is None
    assert summary["generated_at"]
    for stage in ("fetch", "normalize", "correlate", "detect", "render"):
        assert summary["stage_latency_percentiles"][stage] == {"p50_ms": 0, "p95_ms": 0}


def test_concurrent_telemetry_writes(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    barrier = threading.Barrier(2)

    def _worker(index: int) -> None:
        barrier.wait()
        record_run_telemetry(
            out_root=out_root,
            run_id=f"run-{index}",
            case_id=f"case-{index}",
            mode="live",
            profile="soc",
            success=index % 2 == 0,
            stage_durations={"fetch": 1, "normalize": 1, "correlate": 1, "detect": 1, "render": 1},
            total_duration_ms=5,
            failure_reason=None if index % 2 == 0 else "fetch:exit_1",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(_worker, idx) for idx in range(2)]
        for future in futures:
            future.result()

    history_path = out_root / "telemetry_history.ndjson"
    summary_path = out_root / "telemetry_summary.json"
    assert history_path.exists()
    assert summary_path.exists()

    lines = [line for line in history_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 2
    records = [json.loads(line) for line in lines]
    assert {row["run_id"] for row in records} == {"run-0", "run-1"}
    saved_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert saved_summary["total_runs"] == 2
