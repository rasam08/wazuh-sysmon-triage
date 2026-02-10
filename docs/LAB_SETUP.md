# Lab setup (minimal)

This project is designed to be reproducible in a small lab and reviewable without any lab via the offline NDJSON sample.

## Option A: Offline-only (recommended for reviewers)

No infrastructure required.

- Install Python 3.12+
- Run the offline quickstart in [../README.md](../README.md)

## Option B: Online lab (Wazuh + Sysmon + OpenSearch)

### Minimum components

1. Windows endpoint
   - Sysmon installed and configured to generate Event IDs 1/3/11.
   - Wazuh agent installed and configured to ship Sysmon events.

2. Wazuh server / indexer
   - Wazuh Indexer (OpenSearch) reachable via the OpenSearch HTTP API.
   - Index pattern containing alerts (commonly `wazuh-alerts-4.x-*`).

### Connectivity expectation

Wazuh commonly exposes:

- Dashboards/UI on `:443`
- Indexer API (OpenSearch HTTP) on `:9920`

This tool must talk to the Indexer API endpoint, not the UI.

If `:9920` is only reachable from the server itself, use an SSH local port forward and point the tool at `https://127.0.0.1:9920`.

### Data generation (benign)

You do not need “attack simulation” to validate the tool.

A simple way to generate Sysmon events:

- EID 1 (Process Create): open `cmd.exe` or `powershell.exe` and run a few commands.
- EID 11 (File Create): create a file (e.g., `echo test > C:\Temp\triage_test.txt`).
- EID 3 (Network Connect): make an outbound connection (e.g., `curl https://example.com` or open a browser).

The tool is designed to handle normal background noise (Defender, browser traffic, IDE processes).
