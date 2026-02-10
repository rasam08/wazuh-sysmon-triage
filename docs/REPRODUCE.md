# Reproduce results

This project supports two reproducible paths:

- Offline (NDJSON replay): no lab required; ideal for reviewers.
- Online (OpenSearch): query Wazuh Indexer directly.

## 0) Set up Python environment (Windows)

From the repository root:

```powershell
python -m venv .venv
\.\.venv\Scripts\python.exe -m pip install -U pip
\.\.venv\Scripts\python.exe -m pip install .
```

Notes:

- If you are on macOS/Linux, the venv interpreter is typically `./.venv/bin/python`.
- The commands below assume you use the venv interpreter (so deleting/recreating `.venv/` is safe).

## 1) Offline reproduction (recommended)

From the repository root:

```powershell
\.\.venv\Scripts\python.exe -m wazuh_sysmon_triage run --case-id INCIDENT-001 --input-ndjson samples/incident_001/raw_hits.ndjson --out-dir ./out --print-stats
```

Expected artifacts:

- `out/INCIDENT-001/timeline.csv`
- `out/INCIDENT-001/process_tree.json`
- `out/INCIDENT-001/report.md`

## 2) Online reproduction (OpenSearch / Wazuh Indexer)

### Environment variables (preferred)

Set credentials via environment variables to avoid shell history:

```powershell
$env:WAZUH_OS_HOST = "https://indexer:9920"
$env:WAZUH_OS_USER = "admin"
$env:WAZUH_OS_PASSWORD = "<password>"
```

Run:

```powershell
\.\.venv\Scripts\python.exe -m wazuh_sysmon_triage run --case-id INCIDENT-ONLINE-001 --index-pattern "wazuh-alerts-4.x-*" --agent-name "anon" --start "2026-02-10T00:00:00Z" --end "2026-02-10T02:00:00Z" --event-id 1 --event-id 3 --event-id 11 --out-dir ./out --print-stats
```

### Config-driven run (example)

You can place non-secret defaults in a YAML file and keep secrets in environment variables.

```powershell
$env:WAZUH_OS_PASSWORD = "<password>"

\.\.venv\Scripts\python.exe -m wazuh_sysmon_triage run --config config.example.yaml --case-id INCIDENT-CONFIG-001 --print-stats
```

### TLS note

If you are using a lab indexer with a self-signed certificate:

```powershell
\.\.venv\Scripts\python.exe -m wazuh_sysmon_triage run --no-verify-tls ...
```

### SSH tunnel note

If the indexer API is only reachable from the server itself:

Terminal 1 (keep running):

```powershell
ssh -N -L 9920:localhost:9920 <user>@<wazuh-server>
```

Terminal 2:

```powershell
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"
\.\.venv\Scripts\python.exe -m wazuh_sysmon_triage run --no-verify-tls --case-id INCIDENT-TUNNEL-001 --agent-name "anon" --start "2026-02-10T00:00:00Z" --end "2026-02-10T02:00:00Z" --event-id 1 --event-id 3 --event-id 11 --out-dir ./out
```

Recommended (PowerShell one-liner, dynamic 2-hour window, venv interpreter):

```powershell
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"; $start = (Get-Date).AddHours(-2).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); $end = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); & ".\.venv\Scripts\python.exe" -m wazuh_sysmon_triage run --config .\config.local.yaml --start $start --end $end --case-id "incident-002-eid1-3-11" --agent-name "anon" --no-verify-tls --event-id 1 --event-id 3 --event-id 11
```

## 3) Reproducibility notes

- The tool is designed to produce deterministic bundle structure and stable ordering.
- Bundles include captured inputs and metadata (e.g., `query.json`, `run_metadata.json`, `stats.json`) to support review and reruns.

## 4) Create your own offline dataset (online → NDJSON → offline)

If you want a fully portable artifact for review, first fetch raw hits from OpenSearch into NDJSON, then rerun offline.

Fetch to NDJSON:

```powershell
\.\.venv\Scripts\python.exe -m wazuh_sysmon_triage fetch --agent-name "anon" --start "2026-02-10T00:00:00Z" --end "2026-02-10T02:00:00Z" --event-id 1 --event-id 3 --event-id 11 --raw-save ./samples/my_capture/raw_hits.ndjson --out-dir ./out
```

Replay offline:

```powershell
\.\.venv\Scripts\python.exe -m wazuh_sysmon_triage run --case-id INCIDENT-OFFLINE-REPLAY-001 --input-ndjson ./samples/my_capture/raw_hits.ndjson --out-dir ./out --print-stats
```
