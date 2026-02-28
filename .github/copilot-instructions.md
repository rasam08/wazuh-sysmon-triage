# Copilot Instructions for wazuh-sysmon-triage

## Product architecture (read first)
- This repo is a local-first triage pipeline: Python CLI generates case artifacts, then UI middleware reads those artifacts and serves normalized API payloads.
- Main flow: CLI run -> case folder in output root -> middleware loader -> React UI views.
- Key boundaries:
  - CLI: src/wazuh_sysmon_triage (fetch/normalize/correlate/detect/render)
  - Middleware API: ui/server/lib (routes, validators, runner, artifact-loader)
  - UI client/types: ui/src (data/api.ts, types/index.ts, features/*)

## Critical contracts and compatibility
- Artifact schema target is 1.1.0; preserve legacy-read compatibility (see docs/OUTPUT_SCHEMA_COMPAT.md).
- JSON artifacts: process_tree.json, stats.json, run_metadata.json, alert_A###_bundle.json include schema_version.
- run_metadata.json now includes both run_id and case_id; keep fallback handling for older cases.
- Alert routing fields (category, queue, confidence, routing_why) are first-class and used across CLI, loader, and UI.

## API + middleware behavior you must preserve
- API routes are /api/* with /api/v1/* alias (ui/server/lib/routes.ts).
- case_id safety is strict (allowlist + traversal rejection) in ui/server/lib/validators.ts and artifact-loader.ts.
- Spawning must use argument arrays (no shell interpolation) in ui/server/lib/runner.ts.
- dry_run is preview-only in middleware flow: use POST /api/runs/preview, not POST /api/runs.
- out_dir is server-owned in middleware validation; do not reintroduce silent client overrides.
- Output root resolution prefers artifact-bearing out/ or output/ roots (see routes.ts default context resolution).

## Change patterns (important)
- If you change RunParams fields or semantics, update all of:
  - ui/server/lib/validators.ts
  - ui/server/lib/runner.ts
  - ui/src/types/index.ts
  - docs/API_CONTRACT.md
- If you change artifact shape or defaults, update all of:
  - src/wazuh_sysmon_triage pipeline/cli writers
  - ui/server/lib/artifact-loader.ts legacy derivation logic
  - docs/OUTPUT_SCHEMA_COMPAT.md
  - tests/test_schema_compat.py and ui/src/test/server-contract.test.ts

## Dev workflows used in this repo
- Python tests: python -m pytest -q (or repo venv executable if multiple envs exist).
- UI tests: npm --prefix ui run test -- --run
- UI build: npm --prefix ui run build
- Full gate: scripts/release_gate.ps1
- Convenience tasks: scripts/tasks.ps1 and Makefile targets (test/build/smoke-live/smoke-offline/release-gate).

## Practical implementation conventions
- Prefer small, deterministic transformations over hidden side effects; this project relies heavily on reproducible artifacts.
- Keep legacy loaders defensive: missing fields should be safely derived/defaulted instead of hard-failing when possible.
- Maintain stable SOC queue semantics (soc_malware, soc_policy, soc_dev, soc_info) and align inference with detector routing.
- Keep security boundaries intact: output-root confinement via realpath checks and validated case IDs.
- For UI/server contract changes, validate with ui/src/test/server-contract.test.ts before broad test runs.
