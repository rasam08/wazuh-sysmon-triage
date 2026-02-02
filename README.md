# wazuh-sysmon-triage

SOC/IR portfolio tool for triaging Sysmon Event ID 1 and 11 alerts collected by Wazuh and stored in OpenSearch. It fetches raw alerts, normalizes fields into a strict schema, correlates processes and artifacts, and produces deterministic outputs for timelines, graphs, and analyst-friendly reports.

## What it does

- Triage Sysmon EID 1 (process create) and EID 11 (file create)
- Normalize Wazuh/OpenSearch alerts into a stable model
- Build explainable process graphs and artifact lists
- Produce portable outputs: timeline CSV, process graph JSON, and a SOC-style report
- Run online (OpenSearch) or offline (NDJSON sample)

## Architecture

```
OpenSearch/Wazuh
    |
    v
Fetch (PIT + search_after)
    |
    v
Normalize (strict schema)
    |
    v
Correlate (process graph + artifacts)
    |
    v
Render (timeline.csv, process_tree.json, report.md)
```

## Quickstart

### Install

Using pipx:

```
pipx install .
```

Using pip:

```
pip install .
```

### Offline demo (NDJSON sample)

```
python -m wazuh_sysmon_triage run \
  --input-ndjson samples/incident_001/raw_hits.ndjson \
  --out-dir ./out
```

### Useful flags

- Guardrails: `--max-events`, `--max-pages`, `--fail-on-truncation`
- Timing + summary: `--print-stats` (prints counts + total duration)

### Golden demo (case bundle)

One command that generates a complete case bundle (including `query.json`, `stats.json`, `run_metadata.json`):

```
python -m wazuh_sysmon_triage run \
  --case-id INCIDENT-001 \
  --input-ndjson samples/incident_001/raw_hits.ndjson \
  --out-dir ./out \
  --print-stats
```

### OpenSearch run (Wazuh indexer)

Example config (config.example.yaml):

```
start: "2024-01-01T00:00:00Z"
end: "2024-01-01T01:00:00Z"
agent_id: "010"
out_dir: "./out"
host: "https://indexer:9200"
user: "admin"
pass: "password"
verify_tls: true
index_pattern: "wazuh-alerts-4.x-*"
```

Command:

```
python -m wazuh_sysmon_triage run \
  --start 2024-01-01T00:00:00Z \
  --end 2024-01-01T01:00:00Z \
  --agent-id 010 \
  --host https://indexer:9200 \
  --user admin \
  --password password \
  --out-dir ./out
```

## Output examples

timeline.csv (rows):

```
ts,event_id,image,command_line,parent_image,target_filename,user,rule_id,agent_name,agent_id
2024-01-01T00:00:00Z,1,C:\Windows\System32\schtasks.exe,schtasks.exe /create,,,HOST-A\user,92203,anon,010
2024-01-01T00:01:00Z,1,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,powershell.exe -enc aQBlAHgA,C:\Windows\System32\schtasks.exe,,,92204,anon,010
2024-01-01T00:02:00Z,11,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,,,,C:\ProgramData\lab_demo.ps1,HOST-A\user,92205,anon,010
```

process_tree.json (keys):

```
{
  "agent": { "name": "anon" },
  "time_range": { "start": "2024-01-01T00:00:00Z", "end": "2024-01-01T00:02:00Z" },
  "nodes": [ ... ],
  "edges": [ ... ],
  "artifacts": [ ... ]
}
```

report.md (headings):

```
# Incident Summary
## Executive summary
## Observed process chains
## Artifacts & IOCs
## Detections
## Notes
```

## Design decisions

- PIT + search_after: stable pagination across large indices
- Normalized schema: strict, typed fields for downstream processing
- Explainable correlation: explicit edge reasons and artifact confidence
- Deterministic outputs: stable ordering for repeatable reports

## Running tests

```
python -m pytest -q
python -m pytest --cov=src/wazuh_sysmon_triage --cov-report=term-missing
```

## Roadmap

- Add EID 3 (network), EID 7 (image load), EID 13 (registry set)
- Improve ATT&CK mappings
- Sigma-like rule tagging and enrichment

## License

MIT. See LICENSE.