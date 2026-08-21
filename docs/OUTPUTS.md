# Reading a case bundle

A successful run writes one case directory below the output root, normally `./out/<case-id>`. The files are meant to work together: CSV for quick review, JSON for exact structure and automation, and Markdown for a readable handoff.

## Files in a case

The core bundle contains:

- `timeline.csv`: flattened activity in timestamp order
- `process_tree.json`: the host-scoped correlated evidence model
- `alerts.csv`: flat export of local behavior findings
- `report.md`: readable evidence summary and Wazuh pivot queries
- `alert_A###_bundle.json`: one focused evidence package per finding
- `investigation_anchor.json`: the exact triggering Wazuh document for `triage alert` runs

Most runs also write:

- `query.json`: resolved collection/input parameters
- `stats.json`: event, drop, suppression, truncation, and timing counts
- `run_metadata.json`: run context and stage durations
- `run.log.ndjson`: structured runtime log
- `quarantine.ndjson`: rejected input metadata and, only when requested, bounded raw previews

The output root itself keeps `telemetry_history.ndjson` and `telemetry_summary.json` across runs. Those files summarize run success/failure and stage latency; they are not part of one individual case.

JSON case artifacts include `schema_version` where the compatibility contract applies. The current contract is documented in [OUTPUT_SCHEMA_COMPAT.md](OUTPUT_SCHEMA_COMPAT.md).

## Input quality and quarantine

For offline replay, `stats.json` and `run_metadata.json` include `input_quality`:

- physical and blank line counts;
- accepted and rejected object counts;
- stable rejection reasons;
- configured record-size/rejection limits;
- confirmed truncation; and
- `complete` or `degraded` collection integrity.

An input-stage quarantine row records the stage, reason, line number, byte offset, record size, SHA-256 digest, and a traceback-free error summary. `raw_line` is absent unless `--quarantine-drops` was supplied. Raw previews are capped at 4 KiB, oversized previews are marked, and sanitization happens before a raw preview is written.

The reader stops after 10,000 rejected records to prevent an invalid source from growing quarantine output without bound.

## `timeline.csv`

Use the timeline for fast filtering and sorting. It preserves occurrence, Wazuh ingestion, and indexing times separately when the source provides them.

Useful pivots include:

- event ID and event type;
- image, parent image, command line, user, and ProcessGuid;
- created/deleted file paths and hashes;
- destination IP/port and DNS query/results;
- registry targets and values;
- process-access source/target pairs;
- process termination; and
- Windows Security remote logon (4624 types 3/10), service install (4697), and scheduled-task creation (4698).

A missing row is not proof that the underlying action did not happen. Collection policy, alert-only indexing, unsupported fields, truncation, and sensor gaps all matter.

## `process_tree.json`

This is the machine-readable correlation model behind the report. It contains host-scoped process nodes and parent/child edges, along with attached network, file, registry, DNS, process-access, authentication, service, task, termination, and deletion activity.

Edges and artifacts keep relationship strength and source references. Unresolved parents or other incomplete relationships stay in `unresolved_relationships` rather than being guessed.

Remote-activity leads are bounded by host, time, and exact session/account evidence. They are scoping leads, not proof of lateral movement.

## `report.md`

The report turns the correlated model into a readable case narrative. It describes what was recorded, what matched a local behavior rule, which evidence supports the match, and what remains unknown.

Its **Wazuh Pivot Queries** section provides copy/paste query strings for observed ProcessGuids, parent ProcessGuids, destinations, and related network/file/registry/DNS/process-access evidence.

Read the **Behavior findings** section as investigative leads. `finding_kind` and `evidence_strength` describe the match and its support; neither field estimates malicious intent.

## `alerts.csv`

The filename is retained for compatibility, but rows are local behavior findings rather than Wazuh alert verdicts.

Important columns include:

- `alert_type`, `category`, `finding_kind`, and `evidence_strength`;
- `reason`, `host_key`, and `evidence_refs`;
- image, command line, destination, and process context; and
- `source_host_key`, `source_ip`, and `source_port` for bounded remote-activity leads.

## `alert_A###_bundle.json`

Each finding bundle keeps the rule metadata, nearest anchor event, bounded sibling/context windows, ancestry, child processes, linked activity, suppression context, and source evidence.

For host-level remote findings, the bundle includes the relevant authentication, service-install, and scheduled-task records. A bundle narrows review; it does not replace the complete timeline.

## `investigation_anchor.json`

`triage alert` saves the exact alert document/index identity, occurrence time, agent, Wazuh rule metadata, source digest, selected alert/context index patterns, and context window.

The original Wazuh trigger is preserved as an anchor. It is not reclassified as a local verdict.

## Reviewing a saved case

`triage case <case-dir>` reports collection integrity separately from telemetry coverage, summarizes findings, and offers evidence-backed process pivots. If the source was a Wazuh alert index, it warns that non-alerting events may be absent.

`triage process <guid> --case-dir <case-dir>` returns the selected process, ancestry, bounded descendants, exact ProcessGuid-linked activity, focused timeline, findings, unknowns, unresolved relationships, and Wazuh pivots. Its `selection` object accounts for matching, omitted, and unrelated events so the reduced view is still auditable.

Use `--format json` for piping or automation. If the same ProcessGuid exists on multiple hosts, add `--host-key` instead of allowing cross-host evidence to mix.

## Before sharing

Case bundles may contain usernames, hostnames, command lines, paths, hashes, and network addresses. `--sanitize` removes common identifiers, but always review the result manually before publishing or sending it outside the investigation boundary.
