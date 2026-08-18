# Reproduce results

This project supports two reproducible paths:

- Offline (NDJSON replay): no lab required; ideal for reviewers.
- Online (OpenSearch): query Wazuh Indexer directly.

## 0) Set up Python environment (Windows)

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install .
```

Notes:

- If you are on macOS/Linux, the venv interpreter is typically `./.venv/bin/python`.
- The commands below assume you use the venv interpreter (so deleting/recreating `.venv/` is safe).

## 1) Offline reproduction (recommended)

From the repository root:

```powershell
triage offline --input-ndjson samples/incident_001/raw_hits.ndjson --case-id INCIDENT-001 --print-stats
```

Expected artifacts:

- `out/INCIDENT-001/timeline.csv`
- `out/INCIDENT-001/process_tree.json`
- `out/INCIDENT-001/alerts.csv`
- `out/INCIDENT-001/report.md`
- `out/INCIDENT-001/alert_A001_bundle.json` (plus one bundle per emitted alert)

## 2) Online reproduction (OpenSearch / Wazuh Indexer)

### Environment variables (preferred)

Set credentials through the process environment rather than a committed configuration file.
Use your secret manager's shell integration when available:

```powershell
$env:WAZUH_OS_HOST = "https://indexer:9200"
$env:WAZUH_OS_USER = "triage-readonly"
$env:WAZUH_OS_PASSWORD = "<password>"
$env:WAZUH_OS_VERIFY_TLS = "true"
```

Run:

```powershell
triage live --last 2h --case-id INCIDENT-ONLINE-001 --agent-name "anon" --print-stats
```

Recommended alert-centered workflow:

```powershell
triage alert <opensearch-_id> --before 5m --after 10m --case-id INCIDENT-ALERT-001
```

This resolves the exact Wazuh alert, derives its agent and time, and collects the
supported Sysmon evidence around it. Context truncation fails by default.

The default context source is the Wazuh alert index. When indexed archives are
available, preserve the exact alert lookup while collecting fuller context:

```powershell
triage alert <opensearch-_id> --context-index-pattern "wazuh-archives-4.x-*" --case-id INCIDENT-ALERT-ARCHIVE-001
```

Review a completed case without querying OpenSearch again:

```powershell
triage case out\INCIDENT-ALERT-001
triage process "{PROCESS-GUID}" --case-dir out\INCIDENT-ALERT-001 --format json
```

Reproduce the P2 lifecycle fixture:

```powershell
triage offline --input-ndjson samples/incident_003_file_cleanup/raw_hits.ndjson --case-id P2-FILE-CLEANUP --print-stats
triage process "{CLEANUP-CMD}" --case-dir out\P2-FILE-CLEANUP
```

### Config-driven run (example)

You can place non-secret defaults in a YAML file and keep secrets in environment variables.

```powershell
$env:WAZUH_OS_PASSWORD = "<password>"

triage live --config config.example.yaml --last 2h --case-id INCIDENT-CONFIG-001
```

### TLS note

If you are using a lab indexer with a self-signed certificate:

```powershell
triage live --no-verify-tls --last 2h ...
```

### SSH tunnel note

If the indexer API is only reachable from the server itself:

Terminal 1 (keep running):

```powershell
ssh -N -L 9920:localhost:9200 <user>@<wazuh-indexer>
```

Terminal 2:

```powershell
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"
triage live --no-verify-tls --last 2h --case-id INCIDENT-TUNNEL-001 --agent-name "anon"
```

Recommended short command:

```powershell
triage live --config .\config.local.yaml --last 2h --case-id incident-002-endpoint --no-verify-tls
```

## 3) Reproducibility notes

- The tool is designed to produce deterministic bundle structure and stable ordering.
- Bundles include captured inputs and metadata (e.g., `query.json`, `run_metadata.json`, `stats.json`) to support review and reruns.
- Detection-stage tuning is reproducible through explicit suppression and allowlist rules.

## 4) Create your own offline dataset (online → NDJSON → offline)

If you want a fully portable artifact for review, first fetch raw hits from OpenSearch into NDJSON, then rerun offline.

Fetch to NDJSON:

```powershell
.\.venv\Scripts\python.exe -m wazuh_sysmon_triage fetch --agent-name "anon" --start "2026-02-10T00:00:00Z" --end "2026-02-10T02:00:00Z" --raw-save ./samples/my_capture/raw_hits.ndjson --out-dir ./out
```

Replay offline:

```powershell
triage offline --input-ndjson ./samples/my_capture/raw_hits.ndjson --case-id INCIDENT-OFFLINE-REPLAY-001 --print-stats
```

## 5) Release regression checklist (quick gate)

Run these from repository root before tagging or deploying.

### A. Python full suite

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Pass criteria: all tests pass.

### B. Focused hardening suite (input/schema/sanitize/scenario)

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_ndjson.py tests/test_acceptance_corpus.py tests/test_investigate.py tests/test_e2e_offline.py tests/test_perf_smoke.py tests/test_sanitize.py
```

Pass criteria: all focused tests pass.

### C. Bounded performance qualification

```powershell
python scripts/benchmark_offline.py --source-events 10000 --selected-events 10000 --repeat 2 --max-seconds 30 --max-rss-mib 512 --report benchmark-report-10k.json
```

Pass criteria: the report records `passed: true`, both stable digests match, the injected
chain remains present, and wall-time/RSS thresholds pass. The scheduled performance
workflow adds 50k, 100k, scaling-growth, and one-million-source gates. See
`docs/PERFORMANCE.md`.

### D. Live connectivity + bounded pipeline probe

Prerequisite:

```powershell
$env:WAZUH_OS_PASSWORD = "<password>"
```

Dry-run query validation:

```powershell
triage live --config .\config.local.yaml --profile soc --last 2h --dry-run-query
```

Bounded end-to-end probe:

```powershell
triage live --config .\config.local.yaml --profile soc --last 2h --max-events 10 --max-pages 1 --print-stats --alerts-only
```

Pass criteria:

- Dry-run prints resolved query payload successfully.
- Probe reaches `Run complete` and all stages (`fetch`, `normalize`, `correlate`, `detect`, `render`) finish.

### E. Scenario timestamp recency check

```powershell
triage offline --config .\config.local.yaml --input-ndjson samples/scenario_gym/obfuscated_powershell_critical_combo.ndjson --case-id rebase-check --print-stats --alerts-only
```

Pass criteria:

- Logs include `Scenario gym timestamps rebased`.
- Output timeline timestamps are near current UTC time.
