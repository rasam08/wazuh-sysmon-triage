from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from wazuh_sysmon_triage import cli
from wazuh_sysmon_triage.pipeline.case_view import (
    CaseViewError,
    build_case_overview,
    build_process_view,
    load_case_artifacts,
)

runner = CliRunner()


@pytest.fixture
def endpoint_case(tmp_path: Path) -> Path:
    sample = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "incident_002_endpoint_chain"
        / "raw_hits.ndjson"
    )
    out_root = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(sample),
            "--out-dir",
            str(out_root),
            "--case-id",
            "p2-case",
            "--no-log-json",
        ],
    )
    assert result.exit_code == 0, result.output
    return out_root / "p2-case"


def test_case_overview_surfaces_scope_findings_and_process_pivots(endpoint_case: Path) -> None:
    overview = build_case_overview(load_case_artifacts(endpoint_case))

    assert overview["collection"]["integrity"] == "complete_within_query"
    assert overview["collection"]["source_scope"] == "wazuh_alerts"
    assert overview["collection"]["coverage_caveats"][0]["code"] == "alert_index_scope"
    assert overview["counts"]["timeline_events"] == 6
    assert overview["counts"]["unresolved_relationships"] == 1
    assert [row["alert_id"] for row in overview["findings"]] == ["A001", "A002", "A003"]
    assert overview["process_pivots"][0]["process_guid"] == "{CHAIN-PS}"
    assert overview["process_pivots"][0]["finding_ids"] == ["A001", "A002", "A003"]
    assert overview["process_pivots"][0]["pivot_basis"] == "finding_linked_process"


def test_case_overview_offers_collected_process_when_no_finding_exists(
    endpoint_case: Path,
) -> None:
    alerts_path = endpoint_case / "alerts.csv"
    header = alerts_path.read_text(encoding="utf-8").splitlines()[0]
    alerts_path.write_text(header + "\n", encoding="utf-8")

    overview = build_case_overview(load_case_artifacts(endpoint_case))

    assert overview["findings"] == []
    assert overview["process_pivots"]
    assert overview["process_pivots"][0]["process_guid"] == "{CHAIN-PS}"
    assert overview["process_pivots"][0]["finding_ids"] == []
    assert overview["process_pivots"][0]["pivot_basis"] == "collected_process_no_local_finding"


def test_process_view_selects_linked_evidence_and_reports_unknowns(endpoint_case: Path) -> None:
    view = build_process_view(load_case_artifacts(endpoint_case), "{chain-ps}")

    assert view["process"]["guid"] == "{CHAIN-PS}"
    assert view["selection"] == {
        "total_case_events": 6,
        "matched_process_scope": 6,
        "returned": 6,
        "omitted_by_limit": 0,
        "excluded_as_unrelated": 0,
    }
    assert len(view["activity"]["files"]) == 1
    assert len(view["activity"]["network"]) == 1
    assert len(view["activity"]["registry"]) == 1
    assert len(view["activity"]["dns"]) == 1
    assert len(view["activity"]["process_access"]) == 1
    unknown_codes = {row["code"] for row in view["unknowns"]}
    assert "alert_index_scope" in unknown_codes
    assert "unresolved_process_relationship" in unknown_codes
    assert any("{CHAIN-WORD}" in row["query"] for row in view["recommended_pivots"])


def test_process_view_accounts_for_unrelated_noise_and_event_limit(endpoint_case: Path) -> None:
    timeline_path = endpoint_case / "timeline.csv"
    with timeline_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fieldnames = reader.fieldnames
    assert fieldnames is not None
    unrelated = {key: "" for key in fieldnames}
    unrelated.update(
        {
            "ts": "2024-01-01T12:00:01Z",
            "event_id": "3",
            "host_key": "agent:001|computer:host-a",
            "process_guid": "{UNRELATED}",
            "image": "C:\\Program Files\\Browser\\browser.exe",
            "destination_ip": "198.51.100.20",
            "destination_port": "443",
            "source_document_id": "noise-1",
        }
    )
    with timeline_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows([*rows, unrelated])

    view = build_process_view(
        load_case_artifacts(endpoint_case),
        "{CHAIN-PS}",
        max_events=2,
    )

    assert view["selection"]["total_case_events"] == 7
    assert view["selection"]["matched_process_scope"] == 6
    assert view["selection"]["returned"] == 2
    assert view["selection"]["omitted_by_limit"] == 4
    assert view["selection"]["excluded_as_unrelated"] == 1
    assert any(row["code"] == "focused_timeline_limited" for row in view["unknowns"])


def test_process_view_requires_host_for_duplicate_guid(endpoint_case: Path) -> None:
    tree_path = endpoint_case / "process_tree.json"
    tree = json.loads(tree_path.read_text(encoding="utf-8"))
    duplicate = dict(tree["nodes"][0])
    duplicate["host_key"] = "agent:002|computer:host-b"
    tree["nodes"].append(duplicate)
    tree["host_keys"].append(duplicate["host_key"])
    tree_path.write_text(json.dumps(tree), encoding="utf-8")

    artifacts = load_case_artifacts(endpoint_case)
    with pytest.raises(CaseViewError, match="exists on multiple hosts"):
        build_process_view(artifacts, "{CHAIN-PS}")

    selected = build_process_view(
        artifacts,
        "{CHAIN-PS}",
        host_key="agent:002|computer:host-b",
    )
    assert selected["process"]["host_key"] == "agent:002|computer:host-b"


def test_case_overview_labels_cross_host_observable_as_scoping_lead(endpoint_case: Path) -> None:
    tree_path = endpoint_case / "process_tree.json"
    tree = json.loads(tree_path.read_text(encoding="utf-8"))
    second_host = dict(tree["network_activity"][0])
    second_host["host_key"] = "agent:002|computer:host-b"
    second_host["process_guid"] = "{HOST-B-PROCESS}"
    second_host["source_ref"] = {
        **second_host["source_ref"],
        "document_id": "host-b-network",
    }
    tree["network_activity"].append(second_host)
    tree["host_keys"].append(second_host["host_key"])
    tree_path.write_text(json.dumps(tree), encoding="utf-8")

    overview = build_case_overview(load_case_artifacts(endpoint_case))

    leads = overview["cross_host_observables"]
    assert len(leads) == 1
    assert leads[0]["observable_type"] == "destination_ip"
    assert leads[0]["value"] == "203.0.113.10"
    assert len(leads[0]["hosts"]) == 2
    assert "not proof of lateral movement" in leads[0]["interpretation"]


def test_case_and_process_cli_emit_pipeable_json(endpoint_case: Path) -> None:
    case_result = runner.invoke(cli.app, ["case", str(endpoint_case), "--format", "json"])
    assert case_result.exit_code == 0
    case_payload = json.loads(case_result.output)
    assert case_payload["view_type"] == "case_overview"

    process_result = runner.invoke(
        cli.app,
        [
            "process",
            "{CHAIN-PS}",
            "--case-dir",
            str(endpoint_case),
            "--format",
            "json",
            "--max-events",
            "2",
        ],
    )
    assert process_result.exit_code == 0
    process_payload = json.loads(process_result.output)
    assert process_payload["view_type"] == "process_investigation"
    assert process_payload["selection"]["omitted_by_limit"] == 4


def test_case_cli_fails_transparently_for_missing_artifacts(tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["case", str(tmp_path)])

    assert result.exit_code == 4
    assert "Required case artifact is missing: process_tree.json" in result.output
