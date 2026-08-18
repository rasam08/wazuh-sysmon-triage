# Project Blueprint

## Purpose

`wazuh-sysmon-triage` is a Python command-line utility for deterministic triage of high-value Windows endpoint telemetry stored by Wazuh.

## Runtime flow

1. `alert` resolves one Wazuh trigger, or `fetch`/`live` query a selected window; `offline`
   reads bounded binary NDJSON and isolates individual malformed records.
2. Normalization converts supported Sysmon and Windows Security records into typed events with provenance.
3. Correlation builds host-scoped process relationships and attaches file, network,
   registry, DNS, and process-access activity.
4. Detection evaluates configured behavioral signals.
5. Rendering writes deterministic case artifacts under the output root.

## Core modules

- `cli.py`: command definitions and user-facing options
- `clients/opensearch_client.py`: Indexer transport
- `pipeline/fetch.py`: bounded event retrieval
- `pipeline/investigate.py`: exact Wazuh alert lookup and anchor context
- `pipeline/case_view.py`: saved-case overview and process-centric analyst pivots
- `pipeline/normalize.py`: Wazuh/Sysmon parsing
- `pipeline/correlate.py`: process and artifact relationships
- `pipeline/remote_activity.py`: bounded Windows logon-session/action relationships
- `pipeline/detect*.py`: detection logic and suppression
- `pipeline/pivot.py`: per-alert evidence bundles
- `pipeline/render.py`: CSV, JSON, and Markdown artifacts
- `models/`: typed input, event, alert, and finding contracts

## Product boundary

The repository intentionally contains no web interface, HTTP API, middleware server, or Node.js runtime. Analyst interaction and automation happen through the `triage` CLI and generated machine-readable artifacts.

## Validation

```powershell
python -m pytest -q
python -m ruff check src tests
python scripts/benchmark_offline.py --source-events 10000 --selected-events 10000 --repeat 2 --max-seconds 30 --max-rss-mib 512
python -m mypy src
python -m mypy --strict src/wazuh_sysmon_triage/pipeline
```

The release gate also performs an offline suite and a bounded live-query dry run.
