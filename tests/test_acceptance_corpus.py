from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from wazuh_sysmon_triage.corpus import (
    ACCEPTANCE_SCENARIOS,
    iter_mixed_hits,
    iter_scenario_lines,
)
from wazuh_sysmon_triage.pipeline.correlate import correlate_data
from wazuh_sysmon_triage.pipeline.detect import run_detection
from wazuh_sysmon_triage.pipeline.ndjson import InputQualityReport, read_ndjson
from wazuh_sysmon_triage.pipeline.normalize import NormalizeReport, normalize_data_with_report

CORPUS_ROOT = Path(__file__).resolve().parents[1] / "samples" / "acceptance"
REQUIRED_MANIFEST_KEYS = {
    "schema_version",
    "scenario",
    "provenance",
    "required_findings",
    "forbidden_findings",
    "expected_unknowns",
    "minimum_process_edges",
    "minimum_unresolved_relationships",
    "expected_counts",
}
REQUIRED_COUNT_KEYS = {
    "input_records",
    "selected_records",
    "omitted_records",
    "input_rejected",
    "normalize_dropped",
    "unsupported",
}


def _manifest(name: str) -> dict[str, Any]:
    payload = yaml.safe_load((CORPUS_ROOT / name / "expected.yaml").read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _validate_manifest(name: str, manifest: dict[str, Any]) -> None:
    assert REQUIRED_MANIFEST_KEYS <= manifest.keys()
    assert manifest["schema_version"] == 1
    assert manifest["scenario"] == name
    assert manifest["provenance"] in {"synthetic", "sanitized_capture"}
    assert isinstance(manifest["required_findings"], list)
    assert isinstance(manifest["forbidden_findings"], list)
    assert manifest["expected_unknowns"]
    assert REQUIRED_COUNT_KEYS == set(manifest["expected_counts"])
    assert all(isinstance(value, int) and value >= 0 for value in manifest["expected_counts"].values())
    for finding in manifest["required_findings"]:
        assert set(finding) == {"type", "finding_kind", "evidence_strength"}
        assert finding["finding_kind"] in {
            "observed_pattern",
            "correlated_pattern",
            "aggregate_pattern",
            "hypothesis",
        }
        assert finding["evidence_strength"] in {
            "deterministic",
            "strong",
            "circumstantial",
            "unresolved",
        }


def _run_scenario(
    name: str,
    manifest: dict[str, Any],
) -> tuple[list, NormalizeReport, InputQualityReport, dict[str, Any]]:
    if name == "noisy_workstation":
        event_count = manifest["generator"]["event_count"]
        hits = list(iter_mixed_hits(event_count, seed=manifest["generator"]["seed"]))
        input_report = InputQualityReport(
            total_lines=event_count,
            accepted_records=event_count,
        )
    else:
        result = read_ndjson(CORPUS_ROOT / name / "raw_hits.ndjson", max_events=100_000)
        hits = result.hits
        input_report = result.report
    events, normalize_report = normalize_data_with_report(hits, collect_dropped=True)
    detection = run_detection(events)
    correlation = correlate_data(events)
    return detection.alerts, normalize_report, input_report, correlation


@pytest.mark.parametrize("name", ACCEPTANCE_SCENARIOS)
def test_acceptance_scenario_conclusions_and_accounting(name: str) -> None:
    manifest = _manifest(name)
    _validate_manifest(name, manifest)
    alerts, normalize_report, input_report, correlation = _run_scenario(name, manifest)

    by_type = {alert.alert_type: alert for alert in alerts}
    for required in manifest["required_findings"]:
        alert = by_type.get(required["type"])
        assert alert is not None, f"missing {required['type']} in {name}"
        assert alert.finding_kind == required["finding_kind"]
        assert alert.evidence_strength.value == required["evidence_strength"]
    assert not set(manifest["forbidden_findings"]) & set(by_type)
    assert all(alert.evidence_refs for alert in alerts)

    expected = manifest["expected_counts"]
    assert input_report.total_lines == expected["input_records"]
    assert input_report.accepted_records == expected["selected_records"]
    assert input_report.rejected_records == expected["input_rejected"]
    assert (1 if input_report.truncated else 0) == expected["omitted_records"]
    assert normalize_report.dropped_count == expected["normalize_dropped"]
    assert normalize_report.unsupported_count == expected["unsupported"]
    assert len(correlation["edges"]) >= manifest["minimum_process_edges"]
    assert (
        len(correlation["unresolved_relationships"])
        >= manifest["minimum_unresolved_relationships"]
    )


def test_checked_in_fixtures_match_the_deterministic_generator() -> None:
    for name in ACCEPTANCE_SCENARIOS:
        if name == "noisy_workstation":
            assert not (CORPUS_ROOT / name / "raw_hits.ndjson").exists()
            continue
        expected = b"".join(iter_scenario_lines(name))
        assert (CORPUS_ROOT / name / "raw_hits.ndjson").read_bytes() == expected


def test_degraded_fixture_is_order_invariant_for_conclusions() -> None:
    result = read_ndjson(
        CORPUS_ROOT / "degraded_telemetry" / "raw_hits.ndjson",
        max_events=100,
    )
    forward_events, _ = normalize_data_with_report(result.hits)
    reverse_events, _ = normalize_data_with_report(reversed(result.hits))

    forward_alerts = [
        (alert.alert_type, alert.finding_kind, alert.evidence_strength.value)
        for alert in run_detection(forward_events).alerts
    ]
    reverse_alerts = [
        (alert.alert_type, alert.finding_kind, alert.evidence_strength.value)
        for alert in run_detection(reverse_events).alerts
    ]
    assert forward_alerts == reverse_alerts

    def edge_payloads(events: list) -> list[dict[str, Any]]:
        return [
            edge.model_dump(mode="json")
            for edge in correlate_data(events)["edges"]
        ]

    assert edge_payloads(forward_events) == edge_payloads(reverse_events)


def test_noisy_manifest_seed_and_mix_are_auditable() -> None:
    manifest = _manifest("noisy_workstation")
    generator = manifest["generator"]
    assert generator["seed"] == 20260817
    assert generator["event_count"] >= 1000
    assert generator["event_mix"] == ["process", "network", "dns", "file"]
    assert generator["injected_chain"] == "powershell_download_execute"

    first = [
        json.dumps(hit, sort_keys=True)
        for hit in iter_mixed_hits(25, seed=generator["seed"])
    ]
    second = [
        json.dumps(hit, sort_keys=True)
        for hit in iter_mixed_hits(25, seed=generator["seed"])
    ]
    assert first == second
