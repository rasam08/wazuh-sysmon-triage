# Output Schema Compatibility

## Current target

Generated case artifacts use schema version `1.1.0` (see `src/wazuh_sysmon_triage/output_schema.py`).

JSON artifacts expected to include `schema_version`:

- `process_tree.json`
- `stats.json`
- `run_metadata.json`
- `alert_A###_bundle.json`

## v1.1.0 expectations

### `run_metadata.json`

- `schema_version`
- `run_id`
- `case_id`
- `profile`
- `counts` (`normalized_events`, `alerts`, `suppressed_alerts`, ...)
- stage durations (`fetch_duration_ms`, `normalize_duration_ms`, `correlate_duration_ms`, `detect_duration_ms`, `render_duration_ms`, `total_duration_ms`)

### `stats.json`

- `schema_version`
- `total_events`
- `events_by_type`
- `suppression_hits`
- `truncation`

### `process_tree.json`

- `schema_version`
- `agent`
- `time_range`
- `nodes`, `edges`, `artifacts`

### `alerts.csv`

Preferred header includes:

- `utc_time,score,alert_type,category,queue,confidence,reason,routing_why,image,command_line,parent_image,destination_ip,destination_port,process_guid,tags`

## Legacy compatibility rules (middleware loader)

When reading older folders (for example pre-`1.1.0`):

1. Missing `schema_version` defaults to `"1.1.0"` in API payloads.
2. Missing alert routing columns are derived:
   - `category` inferred from `alert_type`
   - `queue` inferred from `category` (`policy_violation -> soc_policy`)
   - `confidence` inferred from `score`
   - `routing_why` defaults to empty string
3. Missing arrays/objects default safely:
   - `nodes`, `edges`, `artifacts`, `alerts`, `timeline` -> `[]`
   - suppression/drop dictionaries -> `{}`
4. Query event IDs default to `[1, 3, 11]` if not derivable from legacy query shape.
5. Missing numeric fields default to `0` where required for UI stats cards/charts.

## Non-goals

- Backporting legacy artifacts to exactly match modern on-disk files.
- Supporting malformed JSON (invalid JSON returns API error).
