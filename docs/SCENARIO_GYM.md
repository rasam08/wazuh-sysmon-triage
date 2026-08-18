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

- Scenarios 1-8: emit the expected evidence-backed behavior finding.
- `suppression_proof.ndjson`: emits **zero** alerts by design (allowlist/suppression proof case).

## Quick run

```powershell
$py = ".\.venv\Scripts\python.exe"
$base = "samples/scenario_gym"

& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/encoded_powershell.ndjson" --out-dir "out/scenario-encoded" --case-id "scenario-encoded"
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/schtasks_persistence.ndjson" --out-dir "out/scenario-schtasks" --case-id "scenario-schtasks"
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/lolbin_outbound.ndjson" --out-dir "out/scenario-lolbin" --case-id "scenario-lolbin"
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/advanced_injection_escalated.ndjson" --out-dir "out/scenario-advanced-injection" --case-id "scenario-advanced-injection"
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/obfuscated_powershell_critical_combo.ndjson" --out-dir "out/scenario-obf-critical" --case-id "scenario-obf-critical"
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/suspicious_path_outbound.ndjson" --out-dir "out/scenario-suspicious-path" --case-id "scenario-suspicious-path"
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/rundll32_outbound_public.ndjson" --out-dir "out/scenario-rundll32" --case-id "scenario-rundll32"
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/schtasks_persistence_cmd_dropper.ndjson" --out-dir "out/scenario-schtasks-cmd-dropper" --case-id "scenario-schtasks-cmd-dropper"
& $py -m wazuh_sysmon_triage offline --input-ndjson "$base/suppression_proof.ndjson" --out-dir "out/scenario-suppression-proof" --case-id "scenario-suppression-proof"
```

## QA hooks

- `tests/test_scenario_gym.py::test_scenario_gym_minimum_signal_threshold`
- `tests/test_scenario_gym.py::test_scenario_gym_suppression_proof_emits_no_alerts`

## Professional acceptance corpus

`samples/acceptance/` is the conclusion-oriented corpus. Unlike the compact scenario gym,
each scenario has an `expected.yaml` manifest that asserts required and forbidden findings,
finding kind and evidence strength, unknowns, relationship minima, exact input/drop counts,
and provenance.

The corpus covers:

1. benign administrative PowerShell;
2. benign software installation;
3. benign RMM maintenance;
4. PowerShell download and execution context;
5. LSASS process access with source context;
6. Run-key persistence evidence;
7. remote service and scheduled-task creation;
8. duplicate, malformed, unsupported, missing-parent, invalid-time, and out-of-order data; and
9. a deterministic noisy workstation with one injected chain.

Regenerate the checked-in fixtures and manifests with:

```powershell
python scripts/generate_acceptance_corpus.py
```

The noisy raw file is intentionally not committed. Generate it when needed:

```powershell
python scripts/generate_acceptance_corpus.py --include-noisy-raw --noisy-events 5000
```

Re-running the generator without `--include-noisy-raw` removes that generated large file.
The fixed seed, event mix, injected chain, and expected conclusions remain in its manifest.
`tests/test_acceptance_corpus.py` validates every manifest before comparing conclusions,
source references, ordering, noise accounting, and forbidden findings.
