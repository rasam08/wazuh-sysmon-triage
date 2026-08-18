# Output Schema Compatibility

## Current target

Generated case artifacts and saved-case views use schema version `2.4.0` (see `src/wazuh_sysmon_triage/output_schema.py`).

JSON artifacts expected to include `schema_version`:

- `process_tree.json`
- `stats.json`
- `run_metadata.json`
- `alert_A###_bundle.json`
- `investigation_anchor.json` when the run starts from `triage alert`

## v2.4.0 additions

Version 2.4 adds the offline `input_quality` object to `stats.json` and
`run_metadata.json`. It records physical, blank, accepted, and rejected input counts;
stable rejection reasons; bounded-record configuration; integrity; and confirmed
truncation. `max_rejected_records` records the quarantine-count guardrail, and
`fail_on_input_errors` records whether strict automation was requested.

Input-stage `quarantine.ndjson` rows use stable reasons: `invalid_utf8`,
`malformed_json`, `non_object_json`, and `record_too_large`. This change is additive;
consumers of older v2 artifacts must treat absent input quality as unknown.

## v2.3.0 additions

Version 2.3 adds canonical Windows Security successful-logon (4624), service-install
(4697), and scheduled-task creation (4698) evidence. Process trees add
`authentication_activity`, `service_install_activity`, `scheduled_task_activity`, and
`remote_activity_leads`. Findings and CSV exports add `source_host_key`, `source_ip`,
and `source_port`; host-level finding bundles include native Windows activity.

Remote-activity leads are bounded hypotheses. `strong` means the target 4624
`TargetLogonId` exactly matched the 4697/4698 `SubjectLogonId`; it does not mean the
activity was malicious. Account-only matches are `circumstantial`.

## v2.2.0 additions

Version 2.2 adds process termination (Sysmon 5), file deletion (23/26), and the
`triage case` / `triage process` saved-evidence views. Process nodes can include
`terminated_at`; process trees include `file_delete_activity` and
`process_termination_activity`. Timeline columns append `event_type`, `hashes`,
`is_executable`, and `archived`. Alert-centered collection can use separate alert and
archive index patterns, and the selected evidence scope is preserved in the anchor.

## v2.1.0 additions

Version 2.1 adds canonical Sysmon registry (12–14), process access (10), and DNS
(22) evidence. `timeline.csv`, `process_tree.json`, reports, statistics, and per-finding
bundles expose those records without inventing maliciousness labels. `triage alert`
also preserves its exact Wazuh trigger and bounded context window.

## v2.0.0 expectations

Version 2 is a breaking evidence-model revision. It preserves original path casing,
scopes process identities to a host, and replaces unsupported artifact confidence
labels with explicit relationship strength and evidence references.

### `run_metadata.json`

- `schema_version`
- `run_id`
- `case_id`
- `profile`
- `counts` (`normalized_events`, `alerts`, `suppressed_alerts`, ...)
- stage durations (`fetch_duration_ms`, `normalize_duration_ms`, `correlate_duration_ms`, `detect_duration_ms`, `render_duration_ms`, `total_duration_ms`)
- `stage_durations_ms` and `slowest_stage` for direct performance diagnosis

### `stats.json`

- `schema_version`
- `total_events`
- `events_by_type`
- `suppression_hits`
- `truncation`
- `unsupported_count`, `unsupported_by_eid`
- `input_quality` for offline runs

### `process_tree.json`

- `schema_version`
- `agent`
- `host_keys`
- `time_range`
- `nodes`, `edges`, `artifacts`
- `registry_activity`, `dns_activity`, `process_access_activity`, `network_activity`
- `file_delete_activity`, `process_termination_activity`
- `authentication_activity`, `service_install_activity`, `scheduled_task_activity`
- `remote_activity_leads`
- `unresolved_relationships`

Nodes and edges include `host_key`. Edges and artifacts include
`relationship_strength` and `evidence_refs`. Evidence references can identify an
OpenSearch index/document or a digest of the original Wazuh JSON.

### `timeline.csv`

The timeline preserves the Sysmon occurrence time, Wazuh ingestion time, and
indexing time as separate columns. It also includes host/process identity and
source-provenance fields.

### `alerts.csv`

Schema v2 header includes:

- `alert_id,utc_time,alert_type,category,finding_kind,evidence_strength,reason,host_key,image,command_line,parent_image,destination_ip,destination_port,process_guid,evidence_refs,tags,source_host_key,source_ip,source_port`

## Compatibility policy

- Writers include the current `schema_version` in JSON artifacts.
- Schema changes are additive within a major version.
- CLI readers must not silently invent missing evidence fields when loading older artifacts.
- Consumers should treat absent optional fields as unknown rather than as zero, false, or suspicious.

## Non-goals

- Backporting legacy artifacts to exactly match modern on-disk files.
- Treating rejected input as silently successful collection.
