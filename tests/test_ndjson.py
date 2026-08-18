from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from wazuh_sysmon_triage import cli
from wazuh_sysmon_triage.pipeline.ndjson import read_ndjson


def _hit(index: int, *, event_id: int = 1) -> dict:
    eventdata: dict[str, object]
    if event_id == 1:
        eventdata = {
            "ProcessGuid": f"{{INPUT-{index}}}",
            "ProcessId": 1000 + index,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ParentProcessGuid": "{PARENT}",
            "ParentProcessId": 500,
            "ParentImage": "C:\\Windows\\explorer.exe",
            "User": "LAB\\analyst",
        }
    else:
        eventdata = {
            "ProcessGuid": "{INPUT-1}",
            "ProcessId": 1001,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "DestinationIp": "203.0.113.10",
            "DestinationPort": 443,
            "Protocol": "tcp",
        }
    return {
        "_id": f"input-{index}",
        "_index": "acceptance-input",
        "_source": {
            "@timestamp": f"2024-01-01T00:00:0{index}Z",
            "agent": {"id": "001", "name": "input-host"},
            "data": {
                "win": {
                    "system": {"eventID": str(event_id), "computer": "input-host"},
                    "eventdata": eventdata,
                }
            },
        },
    }


def test_reader_isolates_each_rejection_type(tmp_path: Path) -> None:
    source = tmp_path / "mixed.ndjson"
    source.write_bytes(
        json.dumps(_hit(1)).encode()
        + b"\n"
        + b'{"broken":\n'
        + b'\xff\xfe\n'
        + b'[1, 2, 3]\n'
        + b'"scalar"\n'
        + (b"x" * 1025)
        + b"\n"
        + json.dumps(_hit(2, event_id=3)).encode()
        + b"\n"
    )
    rejected: list[dict] = []

    result = read_ndjson(
        source,
        max_events=10,
        max_record_bytes=1024,
        on_rejection=rejected.append,
        include_raw_line=True,
    )

    assert len(result.hits) == 2
    assert result.report.total_lines == 7
    assert result.report.accepted_records == 2
    assert result.report.rejected_records == 5
    assert result.report.rejected_by_reason == {
        "invalid_utf8": 1,
        "malformed_json": 1,
        "non_object_json": 2,
        "record_too_large": 1,
    }
    assert [entry["line_number"] for entry in rejected] == [2, 3, 4, 5, 6]
    assert all(entry["stage"] == "input" for entry in rejected)
    assert all(len(entry["raw_sha256"]) == 64 for entry in rejected)
    assert rejected[-1]["raw_truncated"] is True


def test_reader_continues_around_bad_records_and_counts_limit_by_accepted_object(
    tmp_path: Path,
) -> None:
    source = tmp_path / "bounded.ndjson"
    source.write_text(
        "\n".join(
            [
                json.dumps(_hit(1)),
                "{bad-json",
                json.dumps(_hit(2)),
                json.dumps(_hit(3)),
                json.dumps(_hit(4)),
            ]
        ),
        encoding="utf-8",
    )
    first_rejections: list[dict] = []
    second_rejections: list[dict] = []

    first = read_ndjson(source, max_events=2, on_rejection=first_rejections.append)
    second = read_ndjson(source, max_events=2, on_rejection=second_rejections.append)

    assert len(first.hits) == 2
    assert first.report.total_lines == 4
    assert first.report.accepted_records == 2
    assert first.report.rejected_records == 1
    assert first.report.truncated is True
    assert first.report.truncation_reason == "max-events"
    assert first.report.integrity == "degraded"
    assert "raw_line" not in first_rejections[0]
    assert first.report.to_payload() == second.report.to_payload()
    assert first_rejections == second_rejections


def test_reader_bounds_rejection_count_and_raw_preview(tmp_path: Path) -> None:
    source = tmp_path / "rejections.ndjson"
    source.write_bytes((b'{"unterminated":"' + (b"x" * 5000) + b"\n") * 5)
    rejected: list[dict] = []

    result = read_ndjson(
        source,
        max_events=10,
        max_record_bytes=6000,
        max_rejected_records=2,
        on_rejection=rejected.append,
        include_raw_line=True,
    )

    assert result.report.total_lines == 2
    assert result.report.rejected_records == 2
    assert result.report.truncated is True
    assert result.report.truncation_reason == "max-input-rejections"
    assert len(rejected) == 2
    assert all(entry["raw_truncated"] is True for entry in rejected)
    assert all(len(entry["raw_line"].encode("utf-8")) <= 4096 for entry in rejected)


def test_offline_cli_writes_quality_artifacts_and_strict_mode_fails_after_render(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.ndjson"
    source.write_text(
        json.dumps(_hit(1))
        + "\n"
        + '{"user":"CORP\\\\alice","ip":"10.20.30.40","path":"C:\\\\Users\\\\alice"\n'
        + json.dumps(_hit(2, event_id=3))
        + "\n",
        encoding="utf-8",
    )
    out_root = tmp_path / "out"
    runner = CliRunner()

    result = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(source),
            "--out-dir",
            str(out_root),
            "--case-id",
            "input-isolation",
            "--quarantine-drops",
            "--sanitize",
            "--fail-on-input-errors",
        ],
    )

    assert result.exit_code == 5
    case_dir = out_root / "input-isolation"
    stats = json.loads((case_dir / "stats.json").read_text(encoding="utf-8"))
    metadata = json.loads((case_dir / "run_metadata.json").read_text(encoding="utf-8"))
    quarantine = (case_dir / "quarantine.ndjson").read_text(encoding="utf-8")
    timeline = (case_dir / "timeline.csv").read_text(encoding="utf-8").splitlines()

    assert stats["schema_version"] == "2.4.0"
    assert stats["total_events"] == 2
    assert stats["input_quality"]["accepted_records"] == 2
    assert stats["input_quality"]["rejected_records"] == 1
    assert stats["input_quality"]["integrity"] == "degraded"
    assert metadata["fail_on_input_errors"] is True
    assert metadata["slowest_stage"] in metadata["stage_durations_ms"]
    assert len(timeline) == 3
    assert "alice" not in quarantine
    assert "10.20.30.40" not in quarantine
    assert "internal-ip-" in quarantine
    assert "Input integrity is degraded" in (case_dir / "report.md").read_text(
        encoding="utf-8"
    )
