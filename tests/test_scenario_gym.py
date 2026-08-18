import json
from pathlib import Path

from wazuh_sysmon_triage.pipeline.detect import detect_alerts, filter_alerts
from wazuh_sysmon_triage.pipeline.normalize import normalize_data

SCENARIO_EXPECTATIONS = {
    "encoded_powershell.ndjson": "powershell_encoded_or_download_pattern",
    "schtasks_persistence.ndjson": "scheduled_task_create",
    "lolbin_outbound.ndjson": "lolbin_outbound",
    "advanced_injection_escalated.ndjson": "powershell_reflection_or_native_api_pattern",
    "obfuscated_powershell_critical_combo.ndjson": "powershell_encoded_or_download_pattern",
    "suspicious_path_outbound.ndjson": "user_writable_path_outbound",
    "rundll32_outbound_public.ndjson": "lolbin_outbound",
    "schtasks_persistence_cmd_dropper.ndjson": "scheduled_task_create",
}

SUPPRESSION_PROOF_SCENARIO = "suppression_proof.ndjson"


def _load_hits(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text:
            rows.append(json.loads(text))
    return rows


def test_scenario_gym_expected_behavior_findings() -> None:
    base = Path(__file__).resolve().parents[1] / "samples" / "scenario_gym"

    for scenario, expected_alert_type in SCENARIO_EXPECTATIONS.items():
        hits = _load_hits(base / scenario)
        events = normalize_data(hits)
        alerts = filter_alerts(detect_alerts(events))
        assert alerts, f"Expected at least one behavior finding for {scenario}"
        assert any(alert.alert_type == expected_alert_type for alert in alerts), (
            f"Expected alert type {expected_alert_type} in {scenario}"
        )


def test_scenario_gym_suppression_proof_emits_no_alerts() -> None:
    base = Path(__file__).resolve().parents[1] / "samples" / "scenario_gym"
    hits = _load_hits(base / SUPPRESSION_PROOF_SCENARIO)
    events = normalize_data(hits)
    alerts = filter_alerts(detect_alerts(events))
    assert alerts == []
