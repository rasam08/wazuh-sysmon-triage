# Copilot Instructions for wazuh-sysmon-triage

## Product architecture

- This repository is a Python-only, local-first triage CLI.
- Main flow: fetch or read NDJSON -> normalize -> correlate -> detect -> render case artifacts.
- Core package: `src/wazuh_sysmon_triage`.
- The project intentionally has no web UI, HTTP API, Node runtime, or frontend build.

## Critical contracts

- Generated JSON artifacts use the schema version defined in `output_schema.py`.
- Preserve deterministic ordering and stable artifact shapes unless a breaking change is explicitly approved.
- Keep credentials out of configuration files and generated artifacts.
- Output paths and case IDs must remain confined to the selected output root.

## Change patterns

- Parser changes require normalization tests with realistic Wazuh records.
- Correlation changes require tests for ordering, missing fields, and duplicate identifiers.
- Artifact changes require updates to `docs/OUTPUT_SCHEMA_COMPAT.md`, relevant render tests,
  and golden snapshots when their public shape changes.
- CLI changes require subprocess-level tests for arguments, exit behavior, and generated files.

## Development workflow

- Python tests: `python -m pytest -q`
- Lint: `python -m ruff check src tests scripts`
- Type-check: `python -m mypy src`
- Local documentation links: `python scripts/check_markdown_links.py`
- Full gate: `scripts/release_gate.ps1`
- Convenience tasks: `scripts/tasks.ps1` and `Makefile`

Prefer small, deterministic transformations and explicit errors. Do not add presentation-only services or derived evidence that cannot be traced to input records.
