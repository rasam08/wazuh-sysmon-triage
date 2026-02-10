# wazuh-sysmon-triage

Deterministic SOC/IR triage CLI for Windows Sysmon telemetry collected by Wazuh and stored in OpenSearch.
It normalizes noisy SIEM alerts into strict schemas, correlates execution + network + file activity, and produces a reusable “case bundle” for incident documentation.

## Supported data

- Sysmon Event ID 1: Process Create
- Sysmon Event ID 3: Network Connect
- Sysmon Event ID 11: File Create

## Inputs and modes

- Online: query OpenSearch (Wazuh Indexer API)
- Offline: replay an NDJSON export (for demos and reproducible reviews)

## Outputs (case bundle)

Each run writes a deterministic bundle to `out/<case-id>/` (or your chosen output directory):

- `timeline.csv` — flattened, analyst-friendly timeline
- `process_tree.json` — correlated process graph + artifacts + network edges
- `report.md` — SOC-style report written from the correlated model

The bundle also includes run metadata for auditability (e.g., `query.json`, `stats.json`, `run_metadata.json`, and a run log).

## Quickstart (offline, no lab required)

Requirements: Python 3.12+.

Install:

```powershell
python -m venv .venv
\.\.venv\Scripts\python.exe -m pip install -U pip
\.\.venv\Scripts\python.exe -m pip install .
```

Run against the included sample NDJSON:

```powershell
\.\.venv\Scripts\python.exe -m wazuh_sysmon_triage run --case-id INCIDENT-001 --input-ndjson samples/incident_001/raw_hits.ndjson --out-dir ./out --print-stats
```

Note: when querying OpenSearch (online mode), the fetch stage defaults to Sysmon Event IDs 1 and 11 unless you explicitly include others via `--event-id` (repeatable) or `event_ids` in a config file.

## Online run (OpenSearch / Wazuh Indexer)

Important: Wazuh commonly exposes:

- Dashboards/UI on `:443`
- Indexer API (OpenSearch HTTP) on `:9920`

This tool must talk to the Indexer API.

Example (PowerShell):

```powershell
$env:WAZUH_OS_HOST = "https://indexer:9920"
$env:WAZUH_OS_USER = "admin"
$env:WAZUH_OS_PASSWORD = "<password>"

python -m wazuh_sysmon_triage run \
  --case-id INCIDENT-ONLINE-001 \
  --index-pattern "wazuh-alerts-4.x-*" \
  --agent-name "anon" \
  --start "2026-02-10T00:00:00Z" \
  --end   "2026-02-10T02:00:00Z" \
  --event-id 1 --event-id 3 --event-id 11 \
  --out-dir ./out \
  --print-stats
```

TLS note: to disable certificate verification (common in labs), pass `--no-verify-tls`.

### SSH tunnel (common lab topology)

If `:9920` is only reachable from the server itself, forward it over SSH:

```powershell
ssh -N -L 9920:localhost:9920 <user>@<wazuh-server>
```

Then point the tool at the local forwarded port:

```powershell
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"
python -m wazuh_sysmon_triage run --no-verify-tls \
  --case-id INCIDENT-TUNNEL-001 \
  --agent-name "anon" \
  --start "2026-02-10T00:00:00Z" \
  --end   "2026-02-10T02:00:00Z" \
  --event-id 1 --event-id 3 --event-id 11 \
  --out-dir ./out
```

Recommended (PowerShell one-liner, dynamic 2-hour window, venv interpreter):

```powershell
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"; $start = (Get-Date).AddHours(-2).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); $end = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); & ".\.venv\Scripts\python.exe" -m wazuh_sysmon_triage run --config .\config.local.yaml --start $start --end $end --case-id "incident-002-eid1-3-11" --agent-name "anon" --no-verify-tls --event-id 1 --event-id 3 --event-id 11
```

## What success looks like

When a run succeeds, you should see:

- A new output folder: `out/<case-id>/`
- Non-empty `timeline.csv`, `process_tree.json`, and `report.md`
- `stats.json` reflecting counts/timing for the run and indicating whether truncation occurred
- A `query.json` (inputs captured) and `run_metadata.json` (execution context)

For the offline sample, reviewers should be able to run the Quickstart command and consistently get the same bundle structure and stable ordering.

## Documentation

- `docs/LAB_SETUP.md` — minimal lab requirements (Wazuh + Sysmon)
- `docs/REPRODUCE.md` — copy/paste reproduction commands (offline + online)
- `docs/OUTPUTS.md` — how to interpret each output
- `docs/TROUBLESHOOTING.md` — common issues (indexer vs dashboards, TLS, tunnel, auth)

## Scope and limitations

- This is a defensive triage and documentation tool.
- Detection is heuristic and evidence-driven; outputs are designed to be explainable and repeatable.
- Environmental noise (EDR/Defender, browsers, IDEs) is expected in real telemetry.

## Running tests

```powershell
python -m pytest -q
```

## License

MIT. See LICENSE.