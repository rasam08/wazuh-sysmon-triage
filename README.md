# wazuh-sysmon-triage

A Python CLI that turns Wazuh-collected Windows telemetry into a reviewable case bundle: a
timeline, a process tree, behavior findings, and per-finding evidence that traces back to the
source records.

It queries a live Wazuh Indexer/OpenSearch instance or replays a local NDJSON file. Findings
describe observed and correlated behavior; the analyst reaches the verdict.

## What it does

- exact Wazuh alert lookup with a preserved investigation anchor;
- bounded live collection or offline NDJSON replay;
- host-scoped process correlation with source provenance;
- Sysmon process, network, file, registry, DNS, process-access, termination, and deletion
  evidence;
- Windows Security remote-logon, service-install, and scheduled-task evidence;
- per-record input rejection and quarantine, so one bad line does not cost the whole run;
- saved-case and process-focused views that do not query Wazuh again; and
- deterministic acceptance and performance gates.

## Status

The offline path is covered by deterministic fixtures, nine acceptance scenarios,
malformed-input cases, and bounded 10k/50k/100k performance gates. The live OpenSearch path is
implemented but has not been qualified against a real Wazuh/Sysmon lab; treat it as
experimental.

Everything under `samples/` is synthetic. Keep real telemetry, credentials, private keys, and
generated case folders out of Git.

## Version 2

v2 is a breaking release: the web interface, risk scores, confidence labels, and queue routing
are gone, leaving the CLI and its artifacts. Generated JSON uses output schema `2.4.0`;
consumers should check `schema_version`. See [CHANGELOG.md](CHANGELOG.md) for migration details.

## Quick start: offline review

Python 3.12 or later is required.

### Windows PowerShell

```powershell
git clone https://github.com/rasam08/wazuh-sysmon-triage.git
Set-Location wazuh-sysmon-triage
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\triage.exe --version
```

### macOS or Linux

```bash
git clone https://github.com/rasam08/wazuh-sysmon-triage.git
cd wazuh-sysmon-triage
python3.12 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install .
./.venv/bin/triage --version
```

The rest of this README uses `triage` for readability. Activate the virtual environment first, or replace `triage` with `.\.venv\Scripts\triage.exe` on Windows or `./.venv/bin/triage` on macOS/Linux.

Run the smallest bundled example:

```powershell
triage offline --input-ndjson samples/incident_001/raw_hits.ndjson --case-id INCIDENT-001
triage case out\INCIDENT-001
```

That run creates `out/INCIDENT-001/` with a timeline, process tree, behavior findings, report, run metadata, and per-finding evidence bundles. No Wazuh server or network connection is needed.

For a fuller endpoint chain:

```powershell
triage offline --input-ndjson samples/incident_002_endpoint_chain/raw_hits.ndjson --case-id endpoint-chain
triage case out\endpoint-chain
triage process "{PROCESS-GUID}" --case-dir out\endpoint-chain
```

Use `--format json` with `case` or `process` when another tool will consume the result.

## Command map

| Command | What it does |
| --- | --- |
| `triage offline` | Replays a local NDJSON file and writes a case bundle. |
| `triage live` | Queries a bounded time window from Wazuh Indexer/OpenSearch. |
| `triage alert <document-id>` | Looks up one Wazuh alert, derives its host and time, and collects nearby context. |
| `triage case <case-dir>` | Summarizes an existing case without contacting Wazuh. |
| `triage process <process-guid>` | Builds a focused view of one process from a saved case. |
| `triage fetch` | Fetches raw hits and optional NDJSON without running the full analysis pipeline. |
| `triage run` | Keeps the older combined interface working; new usage should prefer `live` or `offline`. |

Run `triage <command> --help` for every option.

## Connecting to Wazuh

The CLI talks to the Wazuh Indexer/OpenSearch HTTP API, usually on port `9200`. It does not connect to Wazuh Dashboards on port `443`.

Copy the example before editing it:

```powershell
Copy-Item config.example.yaml config.local.yaml
```

`config.local.yaml` is Git-ignored. Put the endpoint, read-only username, agent selector, and index pattern there; keep the password in the environment:

```powershell
$env:WAZUH_OS_PASSWORD = "<password>"
triage live --config config.local.yaml --agent-name "windows-lab-01" --last 2h --case-id LAB-001
```

`config.local.yaml` is auto-loaded for `live`, `alert`, and `offline` when present. `.env.example` is a template only; the CLI does not read `.env` files.

Precedence, highest first:

- `host`, `user`: CLI flag, profile, config, environment;
- `password`: CLI flag, then `WAZUH_OS_PASSWORD`. YAML passwords are ignored with a warning;
- TLS verification: CLI flag, `WAZUH_OS_VERIFY_TLS`, profile, config, profile default; and
- everything else (`out_dir`, `index_pattern`, agent selectors): CLI flag, profile, config, built-in default.

The `soc` profile ships the placeholder agent name `anon`; override it with `--agent-name`/`--agent-id` or in `config.local.yaml`. The `lab` profile disables certificate verification and warns; use it only in an isolated lab.

`live` defaults to the last two hours. Use `--last 15m|2h|24h|7d`, `--today`, `--yesterday`, or an explicit `--start`/`--end` pair, which overrides the relative flags. Windows are UTC.

### Alert-centered workflow

Given the OpenSearch `_id` of a Wazuh alert:

```powershell
triage alert <opensearch-_id> --before 5m --after 10m --case-id ALERT-001
```

The exact trigger is saved in `investigation_anchor.json`. Context truncation fails by default so an incomplete collection is not presented as complete.

Context comes from the alert index by default, which misses events that did not trigger a Wazuh rule. If archives are indexed, keep the lookup on the alert index and draw context from archives:

```powershell
triage alert <opensearch-_id> --context-index-pattern "wazuh-archives-4.x-*" --case-id ALERT-001
```

Wazuh archives carry storage and retention cost. Live-lab requirements are in [docs/LAB_SETUP.md](docs/LAB_SETUP.md) and [docs/PROFESSIONAL_ACCEPTANCE_PLAN.md](docs/PROFESSIONAL_ACCEPTANCE_PLAN.md).

### Configuration check

Resolve the selected config and print the query without contacting Wazuh:

```powershell
triage live --dry-run-query --agent-name "windows-lab-01" --last 2h
```

This checks query construction only, not credentials, TLS, index permissions, or field mappings.

## Reading findings

Each finding carries a kind (`observed_pattern`, `correlated_pattern`, `aggregate_pattern`, or `hypothesis`), an evidence-strength label, and source references. Evidence strength describes support for the stated relationship, not the probability that the activity is malicious.

A remote logon followed by service creation is worth reviewing, but routine administration produces the same sequence. The tool reports it as a bounded lead rather than calling it lateral movement.

Use `--explain` to show why findings matched:

```powershell
triage offline --input-ndjson samples/scenario_gym/encoded_powershell.ndjson --explain
```

Targeted suppression rules can remove known environment noise. Suppressed counts and matched rule names remain visible in the artifacts.

## Bad or incomplete offline input

Offline NDJSON is read one bounded binary record at a time. Malformed JSON, invalid UTF-8, non-object JSON, and oversized records are rejected individually while valid records continue through the pipeline.

```powershell
triage offline --input-ndjson capture.ndjson --max-record-bytes 4194304 --quarantine-drops
triage offline --input-ndjson capture.ndjson --fail-on-input-errors
```

Rejection metadata goes to `quarantine.ndjson`. Raw rejected text is included only with `--quarantine-drops`, is capped at a 4 KiB preview, and is sanitized when `--sanitize` is active. Strict mode still writes the case bundle and then exits with code `5` if any input record was rejected.

## Output and evidence handling

Each run writes a case below the output root (default `./out`). Common artifacts are:

- `timeline.csv`
- `process_tree.json`
- `alerts.csv`
- `report.md`
- `alert_A###_bundle.json`
- `investigation_anchor.json` for `triage alert`
- `query.json`, `stats.json`, `run_metadata.json`, and `run.log.ndjson`
- `quarantine.ndjson` when input or normalization drops need to be recorded

The output root also keeps `telemetry_history.ndjson` and `telemetry_summary.json` so repeated runs can be reviewed for success rate and stage timing.

Real telemetry exposes usernames, command lines, paths, internal hosts, and network addresses. Restrict access to case directories, and use `--sanitize` before sharing. Sanitization reduces obvious exposure; it does not replace reviewing evidence before publication.

See [docs/OUTPUTS.md](docs/OUTPUTS.md) for the artifact guide and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Container use

The Dockerfile is CLI-only: no web server, no exposed port. No prebuilt image is published.

```powershell
docker build -t wazuh-sysmon-triage:local .
docker run --rm wazuh-sysmon-triage:local --version
docker run --rm wazuh-sysmon-triage:local --help
```

Create `out/` first, then mount it when replaying a bundled sample:

```powershell
New-Item -ItemType Directory -Force out | Out-Null
docker run --rm -v "${PWD}\out:/app/out" wazuh-sysmon-triage:local `
  offline --input-ndjson /app/samples/incident_001/raw_hits.ndjson `
  --case-id INCIDENT-001 --out-dir /app/out
```

The runtime image runs as the unprivileged `triage` user. On Linux, make sure the mounted output directory is writable by the container user. More examples are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Development and release checks

Install the development tools listed in [CONTRIBUTING.md](CONTRIBUTING.md), then run:

```powershell
python -m ruff check src tests scripts
python -m mypy src
python -m pytest -q
python scripts/check_markdown_links.py
```

The local convenience gate runs tests, documentation links, and a no-network live-query dry run:

```powershell
.\scripts\release_gate.ps1
```

Performance qualification and the release process are described in [docs/PERFORMANCE.md](docs/PERFORMANCE.md) and [docs/PUBLISHING.md](docs/PUBLISHING.md).

## Documentation map

Start here:

- [Installation and deployment](docs/DEPLOYMENT.md)
- [Reproducing bundled results](docs/REPRODUCE.md)
- [Live lab setup](docs/LAB_SETUP.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Operational runbooks](docs/runbooks/)
- [Environment variables](docs/ENV_VARS.md)

Understand the evidence:

- [Output artifacts](docs/OUTPUTS.md)
- [Output schema compatibility](docs/OUTPUT_SCHEMA_COMPAT.md)
- [Finding and evidence model](docs/SIGNAL_MODEL.md)
- [Scenario and acceptance fixtures](docs/SCENARIO_GYM.md)

Maintainer references:

- [Project structure](docs/PROJECT_BLUEPRINT.md)
- [Performance qualification](docs/PERFORMANCE.md)
- [Acceptance status and pending live work](docs/PROFESSIONAL_ACCEPTANCE_PLAN.md)
- [Publishing and release process](docs/PUBLISHING.md)
- [Current branch protection](docs/BRANCH_PROTECTION.md)

## AI-assisted development

This project was built with extensive use of AI coding agents. I use AI for implementation, refactoring, tests, documentation, and technical exploration.
I am responsible for the project's goals, design decisions, experiments, acceptance criteria, review, and validation. I do not claim hand-authorship of every line of source code.
Because AI-assisted implementation can introduce subtle errors, the project emphasizes deterministic testing, explicit claim boundaries, reproducibility, and independent validation wherever possible.

## License

MIT. See [LICENSE](LICENSE).
