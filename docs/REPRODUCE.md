# Reproducing the project results

There are two different reproduction paths:

- **Offline replay** exercises the local pipeline with checked-in synthetic NDJSON and needs no Wazuh infrastructure.
- **Live collection** queries Wazuh Indexer/OpenSearch and is still awaiting the declared real-lab qualification.

Use the offline path when reviewing the release.

## Install from the checkout

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\triage.exe --version
```

macOS/Linux:

```bash
python3.12 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install .
./.venv/bin/triage --version
```

The examples below use `triage`. Activate the virtual environment or substitute its full executable path.

## Smallest offline replay

```powershell
triage offline --input-ndjson samples/incident_001/raw_hits.ndjson --case-id INCIDENT-001 --print-stats
```

The case is written below the output root:

- `out/INCIDENT-001/timeline.csv`
- `out/INCIDENT-001/process_tree.json`
- `out/INCIDENT-001/alerts.csv`
- `out/INCIDENT-001/report.md`
- `out/INCIDENT-001/run_metadata.json`
- one `alert_A###_bundle.json` per emitted finding

Review it without rerunning the pipeline:

```powershell
triage case out\INCIDENT-001
```

## Broader checked-in examples

Endpoint chain and process pivot:

```powershell
triage offline --input-ndjson samples/incident_002_endpoint_chain/raw_hits.ndjson --case-id P1-ENDPOINT-CHAIN
triage case out\P1-ENDPOINT-CHAIN
triage process "{PROCESS-GUID}" --case-dir out\P1-ENDPOINT-CHAIN --format json
```

Process lifecycle and file cleanup:

```powershell
triage offline --input-ndjson samples/incident_003_file_cleanup/raw_hits.ndjson --case-id P2-FILE-CLEANUP
triage process "{CLEANUP-CMD}" --case-dir out\P2-FILE-CLEANUP
```

Remote logon, service, and scheduled-task evidence:

```powershell
triage offline --input-ndjson samples/incident_004_remote_service_task/raw_hits.ndjson --case-id P3-REMOTE-ACTIVITY
triage case out\P3-REMOTE-ACTIVITY
```

The P3 output is supposed to remain a lead. The fixture proves that exact logon-session and account relationships can be retained; it does not prove malicious lateral movement.

The nine manifest-driven scenarios under `samples/acceptance/` cover benign behavior, suspicious chains, degraded input, remote administration, and endpoint noise. See [SCENARIO_GYM.md](SCENARIO_GYM.md) for the fixture map and regeneration commands.

## Check malformed-input handling

```powershell
triage offline --input-ndjson samples/acceptance/degraded_telemetry/raw_hits.ndjson --case-id DEGRADED --quarantine-drops
```

The run should keep usable records, report input/normalization drops, and write `quarantine.ndjson`. To make any rejected input produce a non-zero automation result after artifacts are written:

```powershell
triage offline --input-ndjson samples/acceptance/degraded_telemetry/raw_hits.ndjson --case-id DEGRADED-STRICT --fail-on-input-errors
```

Strict input failure exits with code `5`.

## Save a live result for later offline review

Keep real captures under an ignored evidence/output directory, not under `samples/`.

```powershell
New-Item -ItemType Directory -Force out\captures | Out-Null
triage fetch --agent-name "windows-lab-01" `
  --start "2026-08-18T00:00:00Z" --end "2026-08-18T02:00:00Z" `
  --raw-save out\captures\raw_hits.ndjson --out-dir out\fetch-metadata
```

Replay the capture:

```powershell
triage offline --input-ndjson out\captures\raw_hits.ndjson --case-id CAPTURE-REPLAY --print-stats
```

A real capture may contain sensitive information even if no finding is emitted.

## Prepare a live query

Copy the example and replace its placeholder host, user, and agent values:

```powershell
Copy-Item config.example.yaml config.local.yaml
$env:WAZUH_OS_PASSWORD = "<password>"
triage live --config config.local.yaml --agent-name "windows-lab-01" --last 2h --dry-run-query
```

The dry run is safe and performs no network request. When the live trial is explicitly authorized, the first real probe should stay small:

```powershell
triage live --config config.local.yaml --agent-name "windows-lab-01" `
  --last 15m --max-events 100 --max-pages 2 --fail-on-truncation `
  --case-id LAB-SMOKE --print-stats
```

Do not read the presence of output artifacts as proof of generic Wazuh compatibility. Record the exact Wazuh, Sysmon, configuration, index, and TLS details described in [LAB_SETUP.md](LAB_SETUP.md).

For alert-centered collection:

```powershell
triage alert <opensearch-_id> --before 5m --after 10m --case-id LAB-ALERT
triage alert <opensearch-_id> --context-index-pattern "wazuh-archives-4.x-*" --case-id LAB-ALERT-ARCHIVES
```

The second command still resolves the trigger from the alert index; only the surrounding context changes to the archive pattern.

## Validation before a release

Run the normal suite:

```powershell
python -m pytest -q
python scripts/check_markdown_links.py
```

Run the convenience gate:

```powershell
.\scripts\release_gate.ps1
```

Run the pull-request performance profile:

```powershell
python scripts/benchmark_offline.py --source-events 10000 --selected-events 10000 --repeat 2 --max-seconds 30 --max-rss-mib 512 --report benchmark-report-10k.json
```

The scheduled performance workflow adds 50k, 100k, scaling-growth, and one-million-source checks. [PERFORMANCE.md](PERFORMANCE.md) records the thresholds and current local evidence.

The release gate's live step is only `--dry-run-query`. A real live query remains a separate, explicitly authorized trial.
