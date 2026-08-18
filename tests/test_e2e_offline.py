from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from typer.testing import CliRunner

from wazuh_sysmon_triage import cli
from wazuh_sysmon_triage.output_schema import OUTPUT_SCHEMA_VERSION

runner = CliRunner()


def _sample_path(*parts: str) -> Path:
    return Path(__file__).resolve().parents[1] / "samples" / Path(*parts)


def _run_offline(
    *,
    tmp_path: Path,
    input_ndjson: Path,
    case_id: str,
) -> tuple[object, Path]:
    out_root = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(input_ndjson),
            "--out-dir",
            str(out_root),
            "--case-id",
            case_id,
        ],
    )
    return result, out_root / case_id


def test_offline_scenario_creates_valid_case_folder(tmp_path: Path) -> None:
    sample_path = _sample_path("scenario_gym", "encoded_powershell.ndjson")
    case_id = "e2e-offline-case"

    result, case_dir = _run_offline(
        tmp_path=tmp_path,
        input_ndjson=sample_path,
        case_id=case_id,
    )
    assert result.exit_code == 0, result.stdout

    required_files = [
        "run_metadata.json",
        "query.json",
        "stats.json",
        "process_tree.json",
        "timeline.csv",
        "alerts.csv",
        "report.md",
    ]
    for file_name in required_files:
        assert (case_dir / file_name).exists(), f"missing {file_name}"

    run_metadata = json.loads((case_dir / "run_metadata.json").read_text(encoding="utf-8"))
    stats = json.loads((case_dir / "stats.json").read_text(encoding="utf-8"))
    process_tree = json.loads((case_dir / "process_tree.json").read_text(encoding="utf-8"))

    assert run_metadata["schema_version"] == OUTPUT_SCHEMA_VERSION
    assert stats["schema_version"] == OUTPUT_SCHEMA_VERSION
    assert process_tree["schema_version"] == OUTPUT_SCHEMA_VERSION

    assert run_metadata["case_id"] == case_id
    assert run_metadata["run_id"]
    assert int(stats.get("total_events", 0)) > 0

    assert isinstance(process_tree.get("nodes"), list)
    assert isinstance(process_tree.get("edges"), list)
    assert isinstance(process_tree.get("artifacts"), list)

    alert_rows = list(
        csv.DictReader((case_dir / "alerts.csv").read_text(encoding="utf-8").splitlines())
    )
    assert alert_rows
    expected_columns = {
        "utc_time",
        "alert_type",
        "category",
        "finding_kind",
        "evidence_strength",
        "reason",
        "host_key",
        "process_guid",
        "evidence_refs",
        "source_host_key",
        "source_ip",
        "source_port",
    }
    assert expected_columns.issubset(set(alert_rows[0].keys()))


def test_offline_suppression_proof_produces_no_alerts(tmp_path: Path) -> None:
    sample_path = _sample_path("scenario_gym", "suppression_proof.ndjson")
    result, case_dir = _run_offline(
        tmp_path=tmp_path,
        input_ndjson=sample_path,
        case_id="e2e-suppression-proof",
    )
    assert result.exit_code == 0, result.stdout

    alert_rows = list(
        csv.DictReader((case_dir / "alerts.csv").read_text(encoding="utf-8").splitlines())
    )
    assert alert_rows == []
    assert list(case_dir.glob("alert_A*_bundle.json")) == []


def test_offline_schtasks_produces_persistence_alert(tmp_path: Path) -> None:
    sample_path = _sample_path("scenario_gym", "schtasks_persistence.ndjson")
    result, case_dir = _run_offline(
        tmp_path=tmp_path,
        input_ndjson=sample_path,
        case_id="e2e-schtasks-persistence",
    )
    assert result.exit_code == 0, result.stdout

    alert_rows = list(
        csv.DictReader((case_dir / "alerts.csv").read_text(encoding="utf-8").splitlines())
    )
    assert alert_rows
    assert any(
        row.get("alert_type") == "scheduled_task_create"
        and row.get("category") == "persistence_behavior"
        and row.get("evidence_strength") == "deterministic"
        for row in alert_rows
    )


def test_offline_invalid_ndjson_path_fails_gracefully(tmp_path: Path) -> None:
    missing_path = tmp_path / "does_not_exist.ndjson"
    result, _ = _run_offline(
        tmp_path=tmp_path,
        input_ndjson=missing_path,
        case_id="e2e-missing-ndjson",
    )
    assert result.exit_code != 0
    stderr_bytes = getattr(result, "stderr_bytes", None)
    if stderr_bytes:
        assert b"Traceback (most recent call last)" not in stderr_bytes
    assert "Traceback (most recent call last)" not in result.output


def test_offline_empty_ndjson_produces_empty_outputs(tmp_path: Path) -> None:
    empty_ndjson = tmp_path / "empty.ndjson"
    empty_ndjson.write_text("", encoding="utf-8")
    result, case_dir = _run_offline(
        tmp_path=tmp_path,
        input_ndjson=empty_ndjson,
        case_id="e2e-empty-ndjson",
    )
    assert result.exit_code == 0, result.stdout

    stats_path = case_dir / "stats.json"
    if stats_path.exists():
        stats = json.loads(stats_path.read_text(encoding="utf-8"))
        assert int(stats.get("total_events", 0)) == 0


def test_offline_alert_bundles_match_alerts_csv(tmp_path: Path) -> None:
    sample_path = _sample_path("scenario_gym", "encoded_powershell.ndjson")
    result, case_dir = _run_offline(
        tmp_path=tmp_path,
        input_ndjson=sample_path,
        case_id="e2e-bundle-match",
    )
    assert result.exit_code == 0, result.stdout

    alert_rows = list(
        csv.DictReader((case_dir / "alerts.csv").read_text(encoding="utf-8").splitlines())
    )
    bundle_files = sorted(case_dir.glob("alert_A*_bundle.json"))
    assert len(bundle_files) == len(alert_rows)

    for bundle_file in bundle_files:
        match = re.match(r"^alert_(A\d+)_bundle\.json$", bundle_file.name)
        assert match is not None
        payload = json.loads(bundle_file.read_text(encoding="utf-8"))
        assert payload.get("alert", {}).get("alert_id") == match.group(1)


def test_p1_endpoint_chain_reconstructs_registry_dns_and_process_access(tmp_path: Path) -> None:
    sample_path = _sample_path("incident_002_endpoint_chain", "raw_hits.ndjson")
    result, case_dir = _run_offline(
        tmp_path=tmp_path,
        input_ndjson=sample_path,
        case_id="e2e-p1-endpoint-chain",
    )
    assert result.exit_code == 0, result.stdout

    alerts = list(
        csv.DictReader((case_dir / "alerts.csv").read_text(encoding="utf-8").splitlines())
    )
    alert_types = {row["alert_type"] for row in alerts}
    assert {
        "powershell_encoded_or_download_pattern",
        "registry_persistence_location_modified",
        "lsass_process_access",
    }.issubset(alert_types)

    graph = json.loads((case_dir / "process_tree.json").read_text(encoding="utf-8"))
    assert len(graph["registry_activity"]) == 1
    assert len(graph["dns_activity"]) == 1
    assert len(graph["process_access_activity"]) == 1
    assert graph["process_access_activity"][0]["target_image"].endswith("lsass.exe")
    assert any(node["guid"] == "{CHAIN-LSASS}" and node["synthetic"] for node in graph["nodes"])

    report = (case_dir / "report.md").read_text(encoding="utf-8")
    assert "payload.example" in report
    assert "CurrentVersion\\Run\\Updater" in report
    assert "0x1010" in report

    bundle = json.loads(next(case_dir.glob("alert_A*_bundle.json")).read_text(encoding="utf-8"))
    assert bundle["counts"]["registry_events"] == 1
    assert bundle["counts"]["dns_queries"] == 1
    assert bundle["counts"]["process_access_events"] == 1


def test_p2_file_cleanup_preserves_deletion_and_process_lifecycle(tmp_path: Path) -> None:
    sample_path = _sample_path("incident_003_file_cleanup", "raw_hits.ndjson")
    result, case_dir = _run_offline(
        tmp_path=tmp_path,
        input_ndjson=sample_path,
        case_id="e2e-p2-file-cleanup",
    )
    assert result.exit_code == 0, result.stdout

    graph = json.loads((case_dir / "process_tree.json").read_text(encoding="utf-8"))
    assert len(graph["file_delete_activity"]) == 1
    assert len(graph["process_termination_activity"]) == 1
    node = next(row for row in graph["nodes"] if row["guid"] == "{CLEANUP-CMD}")
    assert node["terminated_at"] == "2024-01-02T08:00:05Z"
    assert node["synthetic"] is False

    stats = json.loads((case_dir / "stats.json").read_text(encoding="utf-8"))
    assert stats["events_by_type"]["file_delete"] == 1
    assert stats["events_by_type"]["process_terminate"] == 1

    report = (case_dir / "report.md").read_text(encoding="utf-8")
    assert "## File deletion activity" in report
    assert "stage.tmp" in report
    assert "## Process termination activity" in report

    alerts_text = (case_dir / "alerts.csv").read_text(encoding="utf-8")
    assert "cleanup" not in alerts_text.lower()


def test_p3_remote_service_and_task_sequence_is_explicitly_a_lead(tmp_path: Path) -> None:
    sample_path = _sample_path("incident_004_remote_service_task", "raw_hits.ndjson")
    result, case_dir = _run_offline(
        tmp_path=tmp_path,
        input_ndjson=sample_path,
        case_id="e2e-p3-remote-activity",
    )
    assert result.exit_code == 0, result.stdout

    graph = json.loads((case_dir / "process_tree.json").read_text(encoding="utf-8"))
    assert len(graph["authentication_activity"]) == 1
    assert len(graph["service_install_activity"]) == 1
    assert len(graph["scheduled_task_activity"]) == 1
    assert len(graph["remote_activity_leads"]) == 2
    assert all(
        lead["source_host_resolution"] == "exact_agent_ip"
        and lead["evidence_strength"] == "strong"
        for lead in graph["remote_activity_leads"]
    )

    alert_rows = list(
        csv.DictReader((case_dir / "alerts.csv").read_text(encoding="utf-8").splitlines())
    )
    assert {row["alert_type"] for row in alert_rows} == {
        "remote_logon_followed_by_service_install",
        "remote_logon_followed_by_scheduled_task",
    }
    assert all(row["finding_kind"] == "hypothesis" for row in alert_rows)
    assert len(list(case_dir.glob("alert_A*_bundle.json"))) == 2

    report = (case_dir / "report.md").read_text(encoding="utf-8")
    assert "## Remote authentication activity" in report
    assert "## Service installation activity" in report
    assert "## Scheduled-task creation activity" in report
    assert "not proof of malicious lateral movement" in report
