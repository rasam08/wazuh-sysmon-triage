# Project Blueprint

## Scope

`wazuh-sysmon-triage` is a local-first SOC triage toolchain with:

- Python CLI (`triage live|offline|run`) for ingest/correlation/detection/render.
- React UI for run control and analyst workflows.
- Vite middleware API (`/api/*`) that spawns the CLI and serves case artifacts.

No database, queue, or external service is required for offline operation.

## Core flow

1. Operator starts a run from CLI or UI.
2. CLI writes a case folder under `out/<case_id>/`.
3. Middleware reads case artifacts from disk and exposes normalized JSON contracts.
4. UI renders runs, case overview, alert workbench, bundles, and report content.

## Artifact contract (MVP)

Primary artifacts:

- `timeline.csv`
- `process_tree.json`
- `alerts.csv`
- `report.md`
- `alert_A###_bundle.json`

Supporting artifacts:

- `query.json`
- `stats.json`
- `run_metadata.json`
- `run.log.ndjson`

Schema version is currently `1.1.0` for generated JSON artifacts.

## Security boundaries

- Case identifiers are validated via allowlist pattern and traversal rejection.
- Artifact reads are constrained to the configured `out/` root using realpath checks.
- Middleware run params are validated/coerced before spawn.
- CLI spawn uses argument arrays (no shell).
- Single in-process run lock prevents concurrent clobbering.
- Existing case overwrite requires explicit `allow_overwrite=true` or `force=true`.

## Test/CI gates

- Python tests: `python -m pytest -q`
- UI tests: `npm --prefix ui run test`
- UI build: `npm --prefix ui run build`

CI fails on Python or UI gate failures.
