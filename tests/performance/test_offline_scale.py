from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = REPO_ROOT / "scripts" / "benchmark_offline.py"


def _run_gate(
    tmp_path: Path,
    *,
    source_events: int,
    selected_events: int,
    max_seconds: int,
    max_rss_mib: int,
    repeat: int,
) -> dict:
    report_path = tmp_path / "report.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(BENCHMARK),
            "--source-events",
            str(source_events),
            "--selected-events",
            str(selected_events),
            "--repeat",
            str(repeat),
            "--max-seconds",
            str(max_seconds),
            "--max-rss-mib",
            str(max_rss_mib),
            "--work-dir",
            str(tmp_path / "work"),
            "--report",
            str(report_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert completed.returncode == 0, completed.stdout + completed.stderr + json.dumps(report)
    return report


@pytest.mark.performance
@pytest.mark.skipif(
    os.getenv("RUN_PERFORMANCE") != "1",
    reason="set RUN_PERFORMANCE=1 to run the 10k qualification",
)
def test_offline_10k_pull_request_gate(tmp_path: Path) -> None:
    report = _run_gate(
        tmp_path,
        source_events=10_000,
        selected_events=10_000,
        max_seconds=30,
        max_rss_mib=512,
        repeat=2,
    )
    assert report["passed"] is True
    assert report["checks"]["stable_digest"] is True


@pytest.mark.performance
@pytest.mark.skipif(
    os.getenv("RUN_RELEASE_PERFORMANCE") != "1",
    reason="set RUN_RELEASE_PERFORMANCE=1 to run the 100k qualification",
)
def test_offline_100k_release_gate(tmp_path: Path) -> None:
    report = _run_gate(
        tmp_path,
        source_events=100_000,
        selected_events=100_000,
        max_seconds=180,
        max_rss_mib=1536,
        repeat=2,
    )
    assert report["passed"] is True


@pytest.mark.performance
@pytest.mark.skipif(
    os.getenv("RUN_RELEASE_PERFORMANCE") != "1",
    reason="set RUN_RELEASE_PERFORMANCE=1 to run the million-line source safety gate",
)
def test_million_line_source_stays_bounded(tmp_path: Path) -> None:
    report = _run_gate(
        tmp_path,
        source_events=1_000_000,
        selected_events=10_000,
        max_seconds=30,
        max_rss_mib=512,
        repeat=1,
    )
    assert report["passed"] is True
    run = report["runs"][0]
    assert run["input_quality"]["accepted_records"] == 10_000
    assert run["input_quality"]["total_lines"] == 10_001
    assert run["truncation"] == {"truncated": True, "reason": "max-events"}
