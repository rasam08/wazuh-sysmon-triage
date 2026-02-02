import json
from pathlib import Path

from typer.testing import CliRunner

import wazuh_sysmon_triage.cli as cli
from wazuh_sysmon_triage.pipeline.fetch import FetchResult

runner = CliRunner()


def test_fetch_requires_start_end() -> None:
    result = runner.invoke(cli.app, ["fetch"])
    assert result.exit_code == 2


def test_fetch_requires_agent() -> None:
    result = runner.invoke(
        cli.app,
        [
            "fetch",
            "--start",
            "2024-01-01T00:00:00Z",
            "--end",
            "2024-01-01T01:00:00Z",
            "--host",
            "https://example:9200",
            "--user",
            "admin",
            "--password",
            "secret",
        ],
    )
    assert result.exit_code == 2


def test_run_requires_agent() -> None:
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--start",
            "2024-01-01T00:00:00Z",
            "--end",
            "2024-01-01T01:00:00Z",
            "--host",
            "https://example:9200",
            "--user",
            "admin",
            "--password",
            "secret",
        ],
    )
    assert result.exit_code == 2


def test_run_requires_opensearch_creds() -> None:
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--start",
            "2024-01-01T00:00:00Z",
            "--end",
            "2024-01-01T01:00:00Z",
            "--agent-id",
            "010",
        ],
    )
    assert result.exit_code == 2


def test_run_case_id_outputs(tmp_path, monkeypatch) -> None:
    class DummyClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def close(self) -> None:
            return None

    def dummy_fetch(*args, **kwargs):
        return FetchResult(hits=[], truncated=False, reason=None, fetched_count=0)

    monkeypatch.setattr(cli, "OpenSearchClient", DummyClient)
    monkeypatch.setattr(cli, "fetch_sysmon_events", dummy_fetch)

    out_dir = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--start",
            "2024-01-01T00:00:00Z",
            "--end",
            "2024-01-01T01:00:00Z",
            "--agent-id",
            "010",
            "--host",
            "https://example:9200",
            "--user",
            "admin",
            "--password",
            "secret",
            "--out-dir",
            str(out_dir),
            "--case-id",
            "INCIDENT-001",
        ],
    )

    assert result.exit_code == 0

    case_dir = out_dir / "INCIDENT-001"
    assert (case_dir / "timeline.csv").exists()
    assert (case_dir / "process_tree.json").exists()
    assert (case_dir / "report.md").exists()
    assert (case_dir / "query.json").exists()
    assert (case_dir / "stats.json").exists()

    report_text = (case_dir / "report.md").read_text(encoding="utf-8")
    assert "Case ID" in report_text


def test_run_offline_ndjson(tmp_path) -> None:
    sample_path = (
        Path(__file__).resolve().parents[1] / "samples" / "incident_001" / "raw_hits.ndjson"
    )

    out_dir = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--log-file",
            str(out_dir / "run.log.ndjson"),
        ],
    )

    assert result.exit_code == 0

    process_tree = (out_dir / "process_tree.json").read_text(encoding="utf-8")
    assert "schtasks.exe" in process_tree
    assert "powershell.exe" in process_tree

    report_text = (out_dir / "report.md").read_text(encoding="utf-8")
    assert "Artifacts & IOCs" in report_text

    artifacts_text = (out_dir / "process_tree.json").read_text(encoding="utf-8")
    assert "lab_demo.ps1" in artifacts_text
    assert "HIGH" in artifacts_text

    log_path = out_dir / "run.log.ndjson"
    assert log_path.exists()
    lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line]
    assert lines
    import json

    parsed = [json.loads(line) for line in lines]
    stages = {entry.get("stage") for entry in parsed}
    assert "fetch" in stages
    assert "normalize" in stages
    assert "correlate" in stages
    assert "render" in stages

    metadata = json.loads((out_dir / "run_metadata.json").read_text(encoding="utf-8"))
    for key in [
        "fetch_duration_ms",
        "normalize_duration_ms",
        "correlate_duration_ms",
        "render_duration_ms",
        "total_duration_ms",
    ]:
        assert key in metadata
        assert metadata[key] >= 0


def test_run_offline_truncation(tmp_path) -> None:
    sample_path = tmp_path / "many.ndjson"
    lines = []
    for idx in range(5):
        lines.append(
            json.dumps(
                {
                    "_source": {
                        "@timestamp": "2024-01-01T00:00:00Z",
                        "agent": {"id": "010", "name": "anon"},
                        "rule": {"id": "92203", "description": "Sysmon Process Create"},
                        "data": {
                            "win": {
                                "system": {"eventID": "1"},
                                "eventdata": {
                                    "ProcessGuid": f"{{GUID-{idx}}}",
                                    "ProcessId": 100 + idx,
                                    "Image": "C:\\Windows\\System32\\schtasks.exe",
                                    "CommandLine": "schtasks.exe /create",
                                    "User": "HOST-A\\user",
                                },
                            }
                        },
                    }
                }
            )
        )
    sample_path.write_text("\n".join(lines), encoding="utf-8")

    out_dir = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--max-events",
            "2",
        ],
    )
    assert result.exit_code == 0

    report_text = (out_dir / "report.md").read_text(encoding="utf-8")
    assert "WARNING: Results truncated due to max-events guardrail" in report_text


def test_run_offline_truncation_fails(tmp_path) -> None:
    sample_path = tmp_path / "many.ndjson"
    lines = []
    for idx in range(3):
        lines.append(
            json.dumps(
                {
                    "_source": {
                        "@timestamp": "2024-01-01T00:00:00Z",
                        "agent": {"id": "010", "name": "anon"},
                        "rule": {"id": "92203", "description": "Sysmon Process Create"},
                        "data": {
                            "win": {
                                "system": {"eventID": "1"},
                                "eventdata": {
                                    "ProcessGuid": f"{{GUID-{idx}}}",
                                    "ProcessId": 100 + idx,
                                    "Image": "C:\\Windows\\System32\\schtasks.exe",
                                    "CommandLine": "schtasks.exe /create",
                                    "User": "HOST-A\\user",
                                },
                            }
                        },
                    }
                }
            )
        )
    sample_path.write_text("\n".join(lines), encoding="utf-8")

    out_dir = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        [
            "run",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_dir),
            "--max-events",
            "1",
            "--fail-on-truncation",
        ],
    )
    assert result.exit_code == 4
