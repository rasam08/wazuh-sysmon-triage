# Changelog

## Unreleased

## v2.1.0 - 2026-08-21

This maintenance release brings the public documentation in line with the rebuilt CLI,
restores the documented config-precedence rules, and simplifies private implementation
modules without changing the public CLI or output schema `2.4.0`.

- Rewrote the README, setup, deployment, lab, evidence, troubleshooting, security, and
  maintainer documentation around the current CLI and the still-pending live qualification.
- Replaced generated acceptance-scenario boilerplate with a short explanation of what each
  fixture proves.
- Fixed CLI defaults so YAML/profile `out_dir` and `index_pattern` values are honored when
  their command-line flags are omitted.
- Collapsed the `cli_helpers` and `pipeline/detect` re-export shim chains into one module each,
  renamed the `cli_helpers_runtime_*` modules to `cli_helpers_*`, and declared their re-export
  surface with `__all__`. No behavior change.
- Fixed setting precedence so built-in profile presets rank below values written in the config
  file. A preset is a default, so `agent_name`, `verify_tls`, and the rest now follow CLI flag,
  selected profile, config file, preset, model default.
- Stopped ignoring the retired `ROADMAP_TO_10.md` and `REVIEW_REPORT.md` scratch-note
  filenames.

## v2.0.0 - 2026-08-18

A major, evidence-first rework of the February 2026 release: the earlier score-driven,
UI-assisted design is replaced by a deterministic investigation CLI.

- Added schema 2.4 per-record NDJSON isolation for malformed JSON, invalid UTF-8,
  non-object values, and oversized records, with streamed quarantine metadata and strict mode.
- Added nine manifest-driven professional acceptance scenarios covering benign activity,
  incident chains, degraded telemetry, remote administration, and deterministic endpoint noise.
- Added measured 10k/50k/100k runtime and memory gates, nonlinear-growth checks, and a
  one-million-line bounded-source safety qualification.
- Added P3 provider-scoped Windows Security evidence for successful remote logons
  (4624 types 3/10), service installation (4697), and scheduled-task creation (4698).
- Added bounded same-host logon-session correlation, exact source-host resolution, and
  explicitly non-verdict remote-activity leads with a realistic multi-host fixture.
- Added dedicated authentication/service/task case evidence, host-level pivot bundles,
  remote-source finding fields, and additive output schema `2.3.0`.
- Added P2 saved-case `case` and `process` commands with JSON output, explicit noise
  accounting, collection caveats, unresolved relationships, and evidence-backed pivots.
- Added exact cross-host observable scoping leads without asserting lateral movement.
- Added separate alert and archive context index selection for `triage alert`.
- Added canonical Sysmon process termination (5) and file deletion (23/26) evidence,
  a realistic lifecycle fixture, and additive output schema `2.2.0`.
- Added the P1 `triage alert` workflow for exact Wazuh-trigger lookup and bounded,
  host-specific context collection with fail-closed truncation behavior.
- Added canonical Sysmon registry (12–14), process access (10), and DNS (22)
  parsing, correlation, reporting, pivots, and evidence-backed endpoint findings.
- Added a realistic endpoint-chain fixture and bumped the additive output schema to `2.1.0`.
- Completed the P0 integrity pass: host-scoped process correlation, explicit PID fallback,
  preserved source provenance, native Wazuh metadata, and transparent retrieval failures.
- Replaced arbitrary risk scores, confidence labels, queue routing, and destination verdicts
  with evidence-backed behavior findings that distinguish observations from hypotheses.
- Bumped the output schema to `2.0.0`; legacy score and queue settings are now rejected.
- Removed the React UI, Node middleware/API, browser tests, and UI-specific operational files.
- Converted Docker, CI, release automation, developer setup, and documentation to a Python CLI-only workflow.
- Updated Typer to a Python 3.12-compatible release so the packaged `triage` entrypoint starts correctly.

### Breaking changes

- Removed the experimental React UI and its Node API; v2 is a Python CLI-only tool.
- Removed arbitrary risk scores, confidence labels, queue routing, and destination verdicts.
- Rejects legacy score and queue configuration instead of silently changing its meaning.
- Bumped the output schema to `2.4.0`; consumers must validate the declared schema version.

## v1.0.0

- End-to-end Sysmon triage pipeline (fetch → normalize → correlate → render)
- Online OpenSearch mode (PIT + `search_after`) and offline NDJSON replay
- Deterministic outputs: `timeline.csv`, `process_tree.json`, `report.md`, plus case bundle files
- Guardrails (`--max-events`, `--max-pages`, `--fail-on-truncation`) and stage/total timing metrics
