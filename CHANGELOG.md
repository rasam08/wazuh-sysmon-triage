# Changelog

## v1.0.0

- End-to-end Sysmon triage pipeline (fetch → normalize → correlate → render)
- Online OpenSearch mode (PIT + `search_after`) and offline NDJSON replay
- Deterministic outputs: `timeline.csv`, `process_tree.json`, `report.md`, plus case bundle files
- Guardrails (`--max-events`, `--max-pages`, `--fail-on-truncation`) and stage/total timing metrics
