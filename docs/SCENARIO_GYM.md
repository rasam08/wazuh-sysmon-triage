# Scenario Gym

This repository currently ships **9** deterministic synthetic scenarios under `samples/scenario_gym/`.

## Included scenarios

1. `encoded_powershell.ndjson`
2. `schtasks_persistence.ndjson`
3. `lolbin_outbound.ndjson`
4. `advanced_injection_escalated.ndjson`
5. `obfuscated_powershell_critical_combo.ndjson`
6. `suspicious_path_outbound.ndjson`
7. `rundll32_outbound_public.ndjson`
8. `schtasks_persistence_cmd_dropper.ndjson`
9. `suppression_proof.ndjson`

## Expected outcome

- Scenarios 1-8: emit at least one alert with score `>= 70`.
- `suppression_proof.ndjson`: emits **zero** alerts by design (allowlist/suppression proof case).

## Quick run

```powershell
$py = ".\.venv\Scripts\python.exe"
$base = "samples/scenario_gym"

& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/encoded_powershell.ndjson" --out-dir "out/scenario-encoded" --case-id "scenario-encoded" --min-alert-score 70
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/schtasks_persistence.ndjson" --out-dir "out/scenario-schtasks" --case-id "scenario-schtasks" --min-alert-score 70
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/lolbin_outbound.ndjson" --out-dir "out/scenario-lolbin" --case-id "scenario-lolbin" --min-alert-score 70
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/advanced_injection_escalated.ndjson" --out-dir "out/scenario-advanced-injection" --case-id "scenario-advanced-injection" --min-alert-score 70
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/obfuscated_powershell_critical_combo.ndjson" --out-dir "out/scenario-obf-critical" --case-id "scenario-obf-critical" --min-alert-score 70
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/suspicious_path_outbound.ndjson" --out-dir "out/scenario-suspicious-path" --case-id "scenario-suspicious-path" --min-alert-score 70
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/rundll32_outbound_public.ndjson" --out-dir "out/scenario-rundll32" --case-id "scenario-rundll32" --min-alert-score 70
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/schtasks_persistence_cmd_dropper.ndjson" --out-dir "out/scenario-schtasks-cmd-dropper" --case-id "scenario-schtasks-cmd-dropper" --min-alert-score 70
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/suppression_proof.ndjson" --out-dir "out/scenario-suppression-proof" --case-id "scenario-suppression-proof" --min-alert-score 70
```

## QA hooks

- `tests/test_scenario_gym.py::test_scenario_gym_minimum_signal_threshold`
- `tests/test_scenario_gym.py::test_scenario_gym_suppression_proof_emits_no_alerts`
