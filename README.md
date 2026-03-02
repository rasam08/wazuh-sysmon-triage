# wazuh-sysmon-triage

Deterministic SOC/IR triage CLI for Windows Sysmon telemetry collected by Wazuh and stored in OpenSearch.

## Install

Requirements: Python 3.12+

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install .
```

This package exposes a short command: `triage`.

## Commands

- `triage live` — query OpenSearch/Wazuh Indexer (online mode)
- `triage offline` — replay NDJSON input (offline mode)
- `triage run` — backward-compatible legacy command (shows migration hint)

## Time windows (cross-platform)

No shell time math needed. Use one of:

- `--last 15m|2h|24h|7d`
- `--today`
- `--yesterday`

If `--start` and `--end` are provided, they override relative-time flags.

## Quickstart

1) Live, last 2h, SOC-style defaults:

```powershell
triage live --last 2h --case-id incident-live-soc
```

2) Live, today, alerts-only:

```powershell
triage live --today --alerts-only
```

3) Live, last 24h, full output (not alerts-only):

```powershell
triage live --last 24h --no-alerts-only --print-stats --case-id incident-24h-full
```

4) Offline from sample NDJSON:

```powershell
triage offline --input-ndjson samples/scenario_gym/encoded_powershell.ndjson --case-id encoded
```

5) Live using profile:

```powershell
triage live --profile soc --last 24h --agent-name anon --no-verify-tls
```

6) Override profile values on CLI:

```powershell
triage live --profile soc --last 2h --no-alerts-only --min-alert-score 80
```

7) Explicit start/end (overrides `--last`):

```powershell
triage live --last 24h --start 2026-02-10T00:00:00Z --end 2026-02-10T02:00:00Z --case-id incident-explicit
```

8) Legacy compatibility:

```powershell
python -m wazuh_sysmon_triage run --input-ndjson samples/incident_001/raw_hits.ndjson --case-id INCIDENT-001
```

## Profiles

Config precedence:

`base defaults <- selected profile <- explicit CLI flags`

See `config.example.yaml` for `active_profile` and `profiles:` examples (`soc`, `dev`, `lab`).

## SOC queue routing

- Alerts now carry `category`, `queue`, `confidence`, and `routing_why` metadata.
- `soc` profile defaults to queue focus on `soc_malware` + `soc_policy` (low-noise SOC view).
- Include developer-context queue when needed with `--include-dev-queue`.
- Force explicit queue scope with repeatable `--queue` flags.

Examples:

```powershell
triage live --profile soc --last 24h --queue soc_malware --queue soc_policy
triage live --profile soc --last 24h --include-dev-queue
triage offline --input-ndjson samples/scenario_gym/encoded_powershell.ndjson --queue soc_policy --min-alert-score 0
```

## Config auto-load and precedence

- `triage live` and `triage offline` automatically use `config.local.yaml` when present.
- Override auto-load with `--config <path>`.
- Connection field precedence is:
  - `host`, `user`: CLI > profile/config > environment (`WAZUH_OS_HOST`, `WAZUH_OS_USER`)
  - `password`: CLI > environment (`WAZUH_OS_PASSWORD`) (inline config passwords are ignored and warned)
- TLS field precedence is:
  - `--verify-tls/--no-verify-tls` CLI flag > `WAZUH_OS_VERIFY_TLS` > profile/config > profile default
- `lab` profile defaults to `verify_tls=false` when no explicit override is provided.

## Output behavior

- Runs write to case folders under output root.
- If `--case-id` is omitted, a safe auto-generated case ID is used.
- Optional retention pruning can remove old case folders by age/size (`artifact_retention` in config).
- Typical artifacts:
  - `timeline.csv`
  - `process_tree.json`
  - `alerts.csv`
  - `report.md`
  - `alert_A###_bundle.json` (per alert)
  - `query.json`, `stats.json`, `run_metadata.json`, `run.log.ndjson`
  - `telemetry_history.ndjson`, `telemetry_summary.json` (run success rate, stage p50/p95, top failures)

## Process status lines

During runs, the CLI prints short stage updates, for example:

- `[process] fetch (live): querying opensearch...`
- `[process] normalize: parsing 128 hits...`
- `[process] correlate: building graph...`
- `[process] detect: scoring alerts...`
- `[process] render: writing 4 outputs...`

Structured JSON logging remains intact in `run.log.ndjson`.

## Troubleshooting

- **TLS verify failures**: use `--no-verify-tls` in lab environments.
- **Missing agent selector**: for live mode, provide `--agent-name` or `--agent-id` (or set in profile/config).
- **No results**: widen time window (`--last 24h`), confirm index pattern and agent match.
- **Too noisy**: raise `--min-alert-score`, set `destination_scoring_mode: strict`, or tune `suppressions.rules` in config.

## Documentation

- `docs/LAB_SETUP.md`
- `docs/REPRODUCE.md`
- `docs/OUTPUTS.md`
- `docs/PROJECT_BLUEPRINT.md`
- `docs/API_CONTRACT.md`
- `docs/QUALITY_SCORECARD.md`
- `docs/BRANCH_PROTECTION.md`
- `docs/OUTPUT_SCHEMA_COMPAT.md`
- `docs/TROUBLESHOOTING.md`
- `docs/SIGNAL_MODEL.md`
- `docs/SCENARIO_GYM.md`
- `docs/WAZUH_UI_PROOF.md`

### Environment Variables

See [docs/ENV_VARS.md](docs/ENV_VARS.md) for the complete environment variable reference.

## Running tests

```powershell
python -m pytest -q
```

## UI/API standalone server

Build the React UI, then run the standalone Express server (serves `ui/dist` + `/api/*`):

```powershell
npm --prefix ui install
npm --prefix ui run build
npm --prefix ui start
```

One-command live launcher (PowerShell, recommended for first run):

```powershell
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"
$env:WAZUH_OS_USER = "admin"
$env:WAZUH_OS_PASSWORD = "<password>"
.\scripts\start-ui-live.ps1
```

`start-ui-live.ps1` preflights required live-mode env vars, validates local indexer/tunnel reachability on port `9920`, checks that UI port `4173` is free, builds `ui/dist`, then starts `npm --prefix ui start` with safe local bind defaults.

Default bind: `http://127.0.0.1:4173`

For non-local access, set `PUBLIC_BIND=true` and provide auth credentials:

```powershell
$env:PUBLIC_BIND = "true"
$env:BIND_HOST = "0.0.0.0"
$env:TRIAGE_ALLOW_INSECURE_PUBLIC_BIND = "true"
$env:AUTH_USER = "analyst"
$env:AUTH_PASS = "changeme"
npm --prefix ui start
```

Non-loopback binds are rejected unless `PUBLIC_BIND=true`, `AUTH_USER`/`AUTH_PASS` are both set, and `TRIAGE_ALLOW_INSECURE_PUBLIC_BIND=true`.

The UI server auto-detects the artifacts directory when `--out-dir` is not provided. It checks `out` first, then `output`, preferring whichever already contains case artifacts. The recommended convention is `out`, but earlier runs under `output` are still discovered automatically.

Optional HTTP Basic auth for all routes:

```powershell
$env:AUTH_USER = "analyst"
$env:AUTH_PASS = "changeme"
npm --prefix ui start
```

## Container deployment

Build and run a single deployable image (Python CLI + Node standalone server):

```powershell
docker build -t wazuh-sysmon-triage:latest .
docker run --rm -p 4173:4173 -v ${PWD}/out:/app/out `
  -e PUBLIC_BIND=true -e BIND_HOST=0.0.0.0 `
  -e AUTH_USER=analyst -e AUTH_PASS=changeme `
  wazuh-sysmon-triage:latest
```

Enable optional basic auth in container:

```powershell
docker run --rm -p 4173:4173 -v ${PWD}/out:/app/out `
  -e AUTH_USER=analyst -e AUTH_PASS=changeme `
  wazuh-sysmon-triage:latest
```

Lab deployment via compose:

```powershell
docker compose up --build
```

To enable auth with compose, set `AUTH_USER` and `AUTH_PASS` in your shell (or `.env`) before `docker compose up`.

## Release Gate And Task Aliases

One-click fail-fast release gate:

```powershell
.\scripts\release_gate.ps1
```

Task aliases (PowerShell):

```powershell
.\scripts\tasks.ps1 -Task test
.\scripts\tasks.ps1 -Task build
.\scripts\tasks.ps1 -Task smoke-live
.\scripts\tasks.ps1 -Task smoke-offline
.\scripts\tasks.ps1 -Task release-gate
```

Task aliases (make):

```bash
make test
make build
make smoke-live
make smoke-offline
make release-gate
```

## License

MIT. See LICENSE.
