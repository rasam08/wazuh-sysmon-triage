# Outputs (case bundle)

A completed run produces a directory under your output root (default: `./out`):

- `timeline.csv`
- `process_tree.json`
- `report.md`

Most runs also include supporting artifacts such as:

- `query.json` — the resolved query parameters used for fetching
- `stats.json` — counts and timing
- `run_metadata.json` — environment and run context
- `run.log.ndjson` — structured logs

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
