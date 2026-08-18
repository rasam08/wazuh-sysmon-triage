# wazuh-sysmon-triage

Deterministic SOC/IR triage CLI for high-value Windows endpoint telemetry collected by Wazuh and stored in OpenSearch.

> **v2.0 major rework:** first released in February 2026, paused after the original
> March 2026 development cycle, and revived in August 2026 as an evidence-first,
> Python-only investigation tool. The original commits remain in this repository.

## Project status

The offline pipeline is covered by deterministic fixtures, acceptance scenarios, and bounded
performance tests. Qualification against a declared live Wazuh/Sysmon lab is still pending;
until that is complete, treat live compatibility as experimental. Findings describe observed
or correlated behavior and require analyst review—they are not automated incident verdicts.

All bundled events are synthetic and use documentation or private network ranges. Never commit
real credentials, private keys, or unsanitized case evidence.

## What changed in v2

The original project combined a deterministic CLI with an experimental web UI and score-driven
triage. The rework narrows the product to a reviewable command-line workflow: it preserves raw
provenance, reconstructs bounded endpoint context, exposes collection gaps, and reports observed
or correlated behavior without presenting automated incident verdicts.

This is a breaking release. The React/Node interface, risk scores, confidence labels, queue
routing, and legacy score settings are gone. Existing output consumers should validate the
declared `2.4.0` output schema before adopting v2. See [CHANGELOG.md](CHANGELOG.md) for the full
migration summary.

## Install

Requirements: Python 3.12+

```powershell
git clone https://github.com/rasam08/wazuh-sysmon-triage.git
Set-Location wazuh-sysmon-triage
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -U pip
.\.venv\Scripts\python.exe -m pip install .
```

This package exposes a short command: `triage`.

## Commands

- `triage alert <wazuh-document-id>` — reconstruct bounded endpoint context around one Wazuh alert
- `triage case <case-dir>` — summarize saved evidence, completeness, findings, and process pivots
- `triage process <process-guid> --case-dir <case-dir>` — inspect one process and its focused evidence
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

1) Investigate one Wazuh alert (recommended analyst workflow):

```powershell
triage alert <opensearch-_id> --before 5m --after 10m
```

The command resolves the alert's agent and occurrence time, preserves the trigger in
`investigation_anchor.json`, and fails by default if contextual retrieval is truncated.
By default the surrounding context comes from the Wazuh alert index. If Wazuh archives
are indexed, collect fuller raw context without changing the triggering-alert lookup:

```powershell
triage alert <opensearch-_id> --context-index-pattern "wazuh-archives-4.x-*"
```

Inspect the saved case and then pivot into a finding-linked process:

```powershell
triage case out\endpoint-chain
triage process "{PROCESS-GUID}" --case-dir out\endpoint-chain
triage process "{PROCESS-GUID}" --case-dir out\endpoint-chain --format json
```

2) Live, last 2h, SOC-style defaults:

```powershell
triage live --last 2h --case-id incident-live-soc
```

3) Live, today, alerts-only:

```powershell
triage live --today --alerts-only
```

4) Live, last 24h, full output (not alerts-only):

```powershell
triage live --last 24h --no-alerts-only --print-stats --case-id incident-24h-full
```

5) Offline from the P1 endpoint-chain sample:

```powershell
triage offline --input-ndjson samples/incident_002_endpoint_chain/raw_hits.ndjson --case-id endpoint-chain
```

P2 process-lifecycle and file-deletion evidence:

```powershell
triage offline --input-ndjson samples/incident_003_file_cleanup/raw_hits.ndjson --case-id file-cleanup
triage process "{CLEANUP-CMD}" --case-dir out\file-cleanup
```

P3 remote-logon, service-install, and scheduled-task evidence:

```powershell
triage offline --input-ndjson samples/incident_004_remote_service_task/raw_hits.ndjson --case-id remote-activity
triage case out\remote-activity
```

The P3 result is deliberately a lead, not a lateral-movement verdict. It requires a
same-target-host sequence within 15 minutes and either an exact logon-session ID match
or an exact account match. A source host is named only when the recorded IP or host name
maps to exactly one collected host.

6) Live using profile:

```powershell
triage live --profile soc --last 24h --agent-name anon --no-verify-tls
```

7) Override profile values on CLI:

```powershell
triage live --profile soc --last 2h --no-alerts-only --quarantine-drops
```

8) Explicit start/end (overrides `--last`):

```powershell
triage live --last 24h --start 2026-02-10T00:00:00Z --end 2026-02-10T02:00:00Z --case-id incident-explicit
```

9) Legacy compatibility:

```powershell
python -m wazuh_sysmon_triage run --input-ndjson samples/incident_001/raw_hits.ndjson --case-id INCIDENT-001
```

## Offline input integrity

Offline NDJSON is read as bounded binary records. A malformed JSON line, invalid UTF-8,
non-object JSON value, or oversized record is rejected independently while valid records
before and after it continue through the investigation.

```powershell
triage offline --input-ndjson capture.ndjson --max-record-bytes 4194304 --quarantine-drops
triage offline --input-ndjson capture.ndjson --fail-on-input-errors
```

`--max-events` counts accepted JSON objects, not physical or rejected lines. Input rejection
metadata is written to `quarantine.ndjson`; raw rejected text is included only with
`--quarantine-drops`, capped at a 4 KiB preview, and sanitized when `--sanitize` is active.
The reader stops after 10,000 rejected records to bound quarantine growth.
`--fail-on-input-errors` still writes the normal case artifacts and then exits with code 5.

## Profiles

Config precedence:

`base defaults <- selected profile <- explicit CLI flags`

See `config.example.yaml` for `active_profile` and `profiles:` examples (`soc`, `dev`, `lab`).

## Evidence-based behavior findings

- Local rules emit observed or correlated behavior with an explicit reason.
- Findings carry `finding_kind`, `evidence_strength`, `host_key`, and source references.
- Windows Security evidence covers remote logons (4624 types 3/10), service installs
  (4697), and scheduled-task creation (4698), alongside the supported Sysmon evidence.
- Supported evidence includes process creation, network connections, file creation,
  process termination, process access, registry changes, DNS queries, and file deletion
  (Sysmon 1, 3, 5, 10–14, 22, 23, and 26).
- Numeric risk scores, confidence labels, and automatic queue routing are intentionally absent.
- Use targeted suppression rules for known environment noise; suppressed counts remain visible.

Examples:

```powershell
triage live --profile soc --last 24h --explain
triage offline --input-ndjson samples/scenario_gym/encoded_powershell.ndjson --explain-alert A001
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
  - `investigation_anchor.json` (`triage alert` runs)
  - `query.json`, `stats.json`, `run_metadata.json`, `run.log.ndjson`
  - `quarantine.ndjson` (input rejection metadata; raw text is opt-in)
  - `telemetry_history.ndjson`, `telemetry_summary.json` (run success rate, stage p50/p95, top failures)

## Process status lines

During runs, the CLI prints short stage updates, for example:

- `[process] fetch (live): querying opensearch...`
- `[process] normalize: parsing 128 hits...`
- `[process] correlate: building graph...`
- `[process] detect: evaluating transparent behavior rules...`
- `[process] render: writing <count> outputs...`

Structured JSON logging remains intact in `run.log.ndjson`.

## Troubleshooting

- **TLS verify failures**: use `--no-verify-tls` in lab environments.
- **Missing agent selector**: for live mode, provide `--agent-name` or `--agent-id` (or set in profile/config).
- **No results**: widen time window (`--last 24h`), confirm index pattern and agent match.
- **Too noisy**: add narrow, reviewable `suppressions.rules`; avoid broad rules that hide unrelated evidence.

## Documentation

- [Lab setup](docs/LAB_SETUP.md)
- [Reproducing results](docs/REPRODUCE.md)
- [Output artifacts](docs/OUTPUTS.md)
- [Output schema compatibility](docs/OUTPUT_SCHEMA_COMPAT.md)
- [Signal and evidence model](docs/SIGNAL_MODEL.md)
- [Scenario gym](docs/SCENARIO_GYM.md)
- [Performance qualification](docs/PERFORMANCE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Project blueprint](docs/PROJECT_BLUEPRINT.md)
- [Professional acceptance plan](docs/PROFESSIONAL_ACCEPTANCE_PLAN.md)
- [Publishing checklist](docs/PUBLISHING.md)
- [Security policy](SECURITY.md)

### Environment Variables

See [docs/ENV_VARS.md](docs/ENV_VARS.md) for the complete environment variable reference.

## Security and evidence handling

Raw telemetry and generated artifacts can contain hostnames, usernames, paths, command lines,
and network addresses. Keep real evidence outside the repository, restrict access to output
directories, and use `--sanitize` before sharing artifacts when appropriate. Report security
issues through the process in [SECURITY.md](SECURITY.md).

## Running tests

```powershell
python -m pytest -q
```

Resource-intensive gates are opt-in locally:

```powershell
$env:RUN_PERFORMANCE = "1"
python -m pytest -q tests/performance/test_offline_scale.py
```

## Containerized CLI

The container contains only the Python CLI. It does not expose a web server or network port.

```powershell
docker build -t wazuh-sysmon-triage:latest .
docker run --rm wazuh-sysmon-triage:latest --help
```

Replay the bundled offline sample and persist the output:

```powershell
docker run --rm -v ${PWD}/out:/app/out wazuh-sysmon-triage:latest `
  offline --input-ndjson /app/samples/incident_001/raw_hits.ndjson `
  --case-id INCIDENT-001 --out-dir /app/out
```

For live mode, pass the Wazuh Indexer connection through environment variables:

```powershell
docker run --rm -v ${PWD}/out:/app/out `
  -e WAZUH_OS_HOST -e WAZUH_OS_USER -e WAZUH_OS_PASSWORD -e WAZUH_OS_VERIFY_TLS `
  wazuh-sysmon-triage:latest live --last 2h --agent-name anon --out-dir /app/out
```

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
