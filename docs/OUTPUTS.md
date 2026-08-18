# Outputs (case bundle)

A completed run produces a case directory under your output root (default: `./out/<case-id>`):

- `timeline.csv`
- `process_tree.json`
- `alerts.csv`
- `report.md`
- `alert_A001_bundle.json` (and one file per emitted alert)
- `investigation_anchor.json` (for `triage alert` runs)

Most runs also include supporting artifacts such as:

- `query.json` — the resolved query parameters used for fetching
- `stats.json` — counts and timing
- `run_metadata.json` — environment and run context
- `run.log.ndjson` — structured logs
- `quarantine.ndjson` — input rejection metadata plus optional raw input and normalization drops

JSON artifacts (`process_tree.json`, `stats.json`, `run_metadata.json`, `alert_A###_bundle.json`)
include `schema_version` for compatibility tracking.

For offline input rejection, `quarantine.ndjson` is created whenever a record is rejected,
even when raw quarantine was not requested. Offline `stats.json` and
`run_metadata.json` include `input_quality`: physical and blank line counts, accepted and
rejected records, stable rejection counts by reason, integrity, and truncation.

Input-stage quarantine rows always include stage, stable reason, line number, byte offset,
record size, SHA-256 digest, and a traceback-free error summary. `raw_line` is absent unless
`--quarantine-drops` is supplied. Oversized raw text is bounded and marked
`raw_truncated`; all raw previews are capped at 4 KiB and the reader stops after 10,000
rejections. `--sanitize` applies before any raw text is written.

Console also prints concise process stage lines for operator visibility:

- `[process] fetch ...`
- `[process] normalize ...`
- `[process] correlate ...`
- `[process] detect ...`
- `[process] render ...`

## timeline.csv

Purpose: A flattened, analyst-friendly view of the activity ordered by timestamp.

Typical use:

- Pivot by `event_id` (1, 3, 5, 10–14, 22, 23, 26)
- Group by `image` and `parent_image`
- Review `command_line` for execution context
- Review file paths (`target_filename`) for artifacts
- Review network destinations (when present) for outbound connections
- Review registry targets, DNS queries/results, and process-access source/target pairs
- Review file deletion and process termination without treating missing events as proof of absence
- Review Windows Security remote logons (4624 types 3/10), service installs (4697),
  and scheduled-task creation (4698)

## process_tree.json

Purpose: The correlated model used to drive the report.

It captures:

- Process nodes and parent/child edges
- File artifacts created (EID 11)
- File deletions (EID 23/26)
- Process termination times (EID 5)
- Network connections (EID 3)
- Registry changes (EID 12–14)
- DNS queries (EID 22)
- Process access source/target evidence (EID 10)
- Remote authentication, service installation, and scheduled-task creation evidence
- Bounded remote-activity leads with explicit relationship strength and source resolution
- Correlation evidence (why a node/edge/artifact exists)

This file is intended to be machine-readable so the bundle can be re-rendered or programmatically reviewed.

## report.md

Purpose: A human-readable SOC-style narrative built from the correlated model.

Professional usage guidance:

- Treat the report as documentation of observed telemetry and heuristic flags.
- Avoid attributing intent unless you have additional evidence outside Sysmon/Wazuh.
- Use the report as a starting point for follow-on validation (host-based triage, enrichment, or scoping).

The report also includes a **Wazuh Pivot Queries** section with copy/paste-ready query strings for:

- Process create events by `processGuid`
- Network, file, registry, and DNS events by `processGuid`
- Process-access events by `sourceProcessGUID`
- Child process pivots by `parentProcessGuid`
- Destination pivots for observed outbound connections

The **Behavior findings** section shows the exact rule match, finding kind,
evidence strength, host identity, and source evidence locators. These are leads,
not maliciousness verdicts.

## alerts.csv

Purpose: Flat behavior-finding export for analyst review and downstream ingestion.

Key columns:

- `alert_type`, `category`, `finding_kind`, `evidence_strength`
- `reason`, `host_key`, `evidence_refs`
- process/network context (`image`, `command_line`, `destination_ip`, `process_guid`)
- remote-source context (`source_host_key`, `source_ip`, `source_port`)

## alert_A###_bundle.json

Purpose: Per-alert pivot package for analyst workflow.

Each bundle includes:

- Finding metadata (`alert_id`, rule fields, kind, evidence strength, reason)
- Anchor event nearest to alert time and primary event type
- Bounded pivot windows (siblings ±2m, contextual activity ±5m)
- Process ancestry, sibling spawns, file creation/deletion, network/registry/DNS activity,
  process access, and process termination
- Native authentication, service-install, and scheduled-task evidence for host-level findings
- Suppression context summary (`suppressed_related_event_count`, `matched_rules`)

## investigation_anchor.json

Purpose: Preserve the exact Wazuh alert that initiated `triage alert`, including
document/index identity, occurrence timestamp, agent, rule metadata, source digest,
and the contextual collection window. The anchor is not treated as a local verdict.

## Saved-case analyst views

`triage case <case-dir>` reads the stable case artifacts and reports collection
integrity separately from telemetry coverage. It explicitly warns when the evidence
originates from Wazuh alert indices because events that did not trigger a Wazuh rule
may be absent. Exact domains, destinations, or process hashes reused on multiple hosts
are shown as scoping leads, never as proof of lateral movement.
When no local behavior finding exists, the case view offers at most 20 collected
processes as neutral evidence pivots and labels their basis accordingly.

`triage process <guid> --case-dir <case-dir>` returns the selected process, resolved
ancestry, bounded descendants, findings, exact ProcessGuid-linked activity, a focused
timeline, unresolved relationships, unknown fields, and copy/paste Wazuh pivots.
The `selection` object accounts for matching, omitted, and unrelated events so noise
reduction remains visible and reviewable. Use `--format json` for piping or automation.
