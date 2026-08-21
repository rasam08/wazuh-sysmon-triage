# Synthetic scenarios

The repository has two fixture collections. They answer different questions:

- `samples/scenario_gym/` contains nine small signal examples for quick rule smoke tests.
- `samples/acceptance/` contains nine manifest-driven cases that check conclusions, non-conclusions, missing evidence, ordering, and noise.

None of these files came from a production environment.

## Small scenario gym

| File | Intended check |
| --- | --- |
| `encoded_powershell.ndjson` | Encoded/download-oriented PowerShell behavior |
| `schtasks_persistence.ndjson` | Scheduled-task creation pattern |
| `lolbin_outbound.ndjson` | A configured LOLBin with public network activity |
| `advanced_injection_escalated.ndjson` | Process-access/reflection context |
| `obfuscated_powershell_critical_combo.ndjson` | Multiple PowerShell contributors in one small case |
| `suspicious_path_outbound.ndjson` | Network activity from a user-writable path |
| `rundll32_outbound_public.ndjson` | `rundll32.exe` with a public destination |
| `schtasks_persistence_cmd_dropper.ndjson` | Scheduled task with interpreter/dropper context |
| `suppression_proof.ndjson` | Zero findings by design, proving suppression behavior |

Run one:

```powershell
triage offline --input-ndjson samples/scenario_gym/encoded_powershell.ndjson --case-id scenario-encoded --explain
```

Scenario-gym timestamps are automatically shifted near the current UTC time during replay. The relative spacing stays intact, which keeps time-sensitive examples useful without hand-editing their source files. This rebasing applies only to paths recognized as `scenario_gym` inputs.

The focused checks live in `tests/test_scenario_gym.py`.

## Acceptance corpus

Each directory under `samples/acceptance/` has:

- `README.md` with the human reason the scenario exists;
- `expected.yaml` with required and forbidden findings, evidence strength, unknowns, relationship minimums, exact counts, and provenance; and
- `raw_hits.ndjson`, except for the large noisy-workstation input generated on demand.

The corpus covers benign administrative PowerShell, benign installation, legitimate remote maintenance, PowerShell download/execution, LSASS access, a Run-key change, remote service/task activity, degraded telemetry, and a noisy workstation.

Regenerate the checked-in corpus:

```powershell
python scripts/generate_acceptance_corpus.py
```

Generate the large noisy raw file when needed:

```powershell
python scripts/generate_acceptance_corpus.py --include-noisy-raw --noisy-events 5000
```

That large NDJSON file is ignored by Git. Running the generator later without `--include-noisy-raw` removes it and restores the normal lightweight checkout.

`tests/test_acceptance_corpus.py` validates every manifest before comparing findings, source references, ordering, unknowns, input quality, and forbidden conclusions.
