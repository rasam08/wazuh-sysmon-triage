# How the project fits together

`wazuh-sysmon-triage` is a Python command-line application for bounded review of Windows endpoint telemetry collected by Wazuh.

## Runtime flow

1. `alert` resolves one exact Wazuh trigger, `live`/`fetch` query a selected window, or `offline` reads NDJSON one bounded record at a time.
2. Normalization turns supported Sysmon and Windows Security records into typed events while keeping their source provenance.
3. Correlation builds host-scoped process relationships and attaches file, network, registry, DNS, authentication, service, task, and process-access evidence.
4. Detection evaluates transparent local behavior rules and configured suppressions.
5. Rendering writes a deterministic case bundle below the output root.
6. `case` and `process` read those saved artifacts without contacting Wazuh again.

## Main modules

- `cli.py`: commands and user-facing options
- `clients/opensearch_client.py`: Wazuh Indexer/OpenSearch transport
- `pipeline/fetch.py`: bounded event retrieval
- `pipeline/investigate.py`: exact alert lookup and context anchoring
- `pipeline/ndjson.py`: bounded offline input and per-record rejection
- `pipeline/normalize.py`: Wazuh, Sysmon, and Windows Security parsing
- `pipeline/correlate.py`: process and artifact relationships
- `pipeline/remote_activity.py`: bounded logon-session/action relationships
- `pipeline/detect*.py`: behavior rules and suppression
- `pipeline/pivot.py`: per-finding evidence bundles
- `pipeline/render.py`: CSV, JSON, Markdown, and run artifacts
- `pipeline/case_view.py`: saved-case and process-focused views
- `models/`: typed input, event, finding, and artifact contracts

## Deliberate boundary

The current repository has no web interface, HTTP API, middleware server, or Node.js runtime. Analyst work and automation happen through the `triage` CLI and the generated machine-readable artifacts.

It is also not a bulk SIEM export processor. Fetch and input limits are part of the design, and truncation is recorded so a bounded investigation is not confused with complete collection.

## Validation

```powershell
python -m ruff check src tests scripts
python -m mypy src
python -m mypy --strict src/wazuh_sysmon_triage/pipeline
python -m pytest -q
python scripts/check_markdown_links.py
python scripts/benchmark_offline.py --source-events 10000 --selected-events 10000 --repeat 2 --max-seconds 30 --max-rss-mib 512
```

`scripts/release_gate.ps1` runs the test suite, selected output-contract tests, documentation links, and a no-network live-query dry run. It does not perform the outstanding real Wazuh trial.
