# Outputs (case bundle)

A completed run produces a case directory under your output root (default: `./out/<case-id>`):

- `timeline.csv`
- `process_tree.json`
- `alerts.csv`
- `report.md`
- `alert_A001_bundle.json` (and one file per emitted alert)

Most runs also include supporting artifacts such as:

- `query.json` — the resolved query parameters used for fetching
- `stats.json` — counts and timing
- `run_metadata.json` — environment and run context
- `run.log.ndjson` — structured logs
- `quarantine.ndjson` — optional dropped-event quarantine (when `--quarantine-drops` is enabled)

JSON artifacts (`process_tree.json`, `stats.json`, `run_metadata.json`, `alert_A###_bundle.json`)
include `schema_version` for compatibility tracking.

Console also prints concise process stage lines for operator visibility:

- `[process] fetch ...`
- `[process] normalize ...`
- `[process] correlate ...`
- `[process] detect ...`
- `[process] render ...`

## timeline.csv

Purpose: A flattened, analyst-friendly view of the activity ordered by timestamp.

Typical use:

- Pivot by `event_id` (1/3/11)
- Group by `image` and `parent_image`
- Review `command_line` for execution context
- Review file paths (`target_filename`) for artifacts
- Review network destinations (when present) for outbound connections

## process_tree.json

Purpose: The correlated model used to drive the report.

It captures:

- Process nodes and parent/child edges
- File artifacts created (EID 11)
- Network connections (EID 3)
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
- Network events by `processGuid`
- Child process pivots by `parentProcessGuid`
- Destination pivots for suspicious outbound connections

The **Alerts** section now includes queue routing context (`category`, `queue`, `confidence`, `routing_why`) and a **Queue summary** table.

## alerts.csv

Purpose: Flat alert export for SOC queue triage and downstream ingestion.

Key columns:

- `score`, `alert_type`
- `category`, `queue`, `confidence`
- `reason`, `routing_why`
- process/network context (`image`, `command_line`, `destination_ip`, `process_guid`)

## alert_A###_bundle.json

Purpose: Per-alert pivot package for analyst workflow.

Each bundle includes:

- Alert metadata (`alert_id`, rule fields, score, reason)
- Anchor event nearest to alert time and primary event type
- Bounded pivot windows (siblings ±2m, network ±5m)
- Process ancestry (depth-limited), sibling spawns, related file artifacts, and network events
- Suppression context summary (`suppressed_related_event_count`, `matched_rules`)
