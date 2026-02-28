from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter

from typer.testing import CliRunner

from wazuh_sysmon_triage import cli

runner = CliRunner()


def _write_fixed_ndjson(path: Path, count: int) -> None:
    rows = []
    for idx in range(count):
        rows.append(
            json.dumps(
                {
                    "_source": {
                        "@timestamp": f"2024-01-01T00:00:{idx % 60:02d}Z",
                        "agent": {"id": "999", "name": "perf-agent"},
                        "rule": {"id": "92203", "description": "Sysmon Process Create"},
                        "data": {
                            "win": {
                                "system": {"eventID": "1"},
                                "eventdata": {
                                    "ProcessGuid": f"{{PERF-{idx}}}",
                                    "ProcessId": 1000 + idx,
                                    "Image": "C:\\Windows\\System32\\schtasks.exe",
                                    "CommandLine": "schtasks.exe /create /tn nightly",
                                    "ParentImage": "C:\\Windows\\explorer.exe",
                                    "User": "HOST\\perfuser",
                                },
                            }
                        },
                    }
                }
            )
        )
    path.write_text("\n".join(rows), encoding="utf-8")


def _load_stats(case_dir: Path) -> dict:
    return json.loads((case_dir / "stats.json").read_text(encoding="utf-8"))


def test_offline_perf_and_truncation_determinism_smoke(tmp_path: Path) -> None:
    sample = tmp_path / "perf.ndjson"
    _write_fixed_ndjson(sample, 200)
    out_dir = tmp_path / "out"

    started = perf_counter()
    first = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(sample),
            "--out-dir",
            str(out_dir),
            "--case-id",
            "perf-smoke-1",
            "--max-events",
            "25",
        ],
    )
    elapsed = perf_counter() - started
    assert first.exit_code == 0
    assert elapsed < 45

    second = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(sample),
            "--out-dir",
            str(out_dir),
            "--case-id",
            "perf-smoke-2",
            "--max-events",
            "25",
        ],
    )
    assert second.exit_code == 0

    first_case = out_dir / "perf-smoke-1"
    second_case = out_dir / "perf-smoke-2"
    first_stats = _load_stats(first_case)
    second_stats = _load_stats(second_case)

    assert first_stats["truncation"]["truncated"] is True
    assert first_stats["truncation"]["reason"] == "max-events"
    assert first_stats["hits"] == 25
    assert first_stats["total_events"] == 25

    assert second_stats["truncation"] == first_stats["truncation"]
    assert second_stats["hits"] == first_stats["hits"]
    assert second_stats["total_events"] == first_stats["total_events"]

    first_timeline_lines = (first_case / "timeline.csv").read_text(encoding="utf-8").splitlines()
    second_timeline_lines = (second_case / "timeline.csv").read_text(encoding="utf-8").splitlines()
    assert len(first_timeline_lines) == 26
    assert first_timeline_lines == second_timeline_lines
