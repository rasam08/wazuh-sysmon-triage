# Lab setup (minimal)

This project is designed to be reproducible in a small lab and reviewable without any lab via the offline NDJSON sample.

## Option A: Offline-only (recommended for reviewers)

No infrastructure required.

- Install Python 3.12+
- Run the offline quickstart in [../README.md](../README.md)

## Option B: Disposable online lab (Wazuh + Sysmon + OpenSearch)

Do not use a production Wazuh deployment for qualification. Snapshot the lab before testing,
synchronize both systems' clocks, and record the exact Wazuh, agent, Sysmon, and Sysmon
configuration versions.

### Minimum components

1. Windows endpoint
   - A separate Windows VM with administrator access.
   - Sysmon installed with a fixed XML configuration covering the required event types.
   - Wazuh agent installed, uniquely named, and configured to collect
     `Microsoft-Windows-Sysmon/Operational`.

2. Wazuh server / indexer
   - A single-node lab with at least 4 CPU cores, 8 GB RAM, and 50 GB storage.
   - Wazuh Indexer (OpenSearch) reachable via the OpenSearch HTTP API.
   - Index pattern containing alerts (commonly `wazuh-alerts-4.x-*`).
   - Archives explicitly enabled and indexed as `wazuh-archives-4.x-*` for non-alert context.

3. Triage workstation
   - Python 3.12+ and this package installed.
   - A dedicated Indexer account with read access only to the required alert and archive indices.
   - The Indexer CA certificate, or an explicitly documented disposable-lab TLS exception.

### Connectivity expectation

Wazuh commonly exposes:

- Dashboards/UI on `:443`
- Indexer API (OpenSearch HTTP) on `:9200`
- Agent event transport on `:1514`
- Agent enrollment on `:1515`

This tool must talk to the Indexer API endpoint, not the UI.

If `:9200` is only reachable from the server itself, use an SSH local port forward. For
example, expose it locally as `9920` while leaving the remote default unchanged:

```powershell
ssh -N -L 9920:localhost:9200 <user>@<wazuh-indexer>
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"
```

### Data generation (benign)

You do not need “attack simulation” to validate the tool.

A simple way to generate Sysmon events:

- EID 1 (Process Create): open `cmd.exe` or `powershell.exe` and run a few commands.
- EID 11 (File Create): create a file (e.g., `echo test > C:\Temp\triage_test.txt`).
- EID 3 (Network Connect): make an outbound connection (e.g., `curl https://example.com` or open a browser).

The tool is designed to handle normal background noise (Defender, browser traffic, IDE
processes) and supports configurable suppression rules in `config.local.yaml` for
environment-specific tuning.

See the [professional acceptance plan](PROFESSIONAL_ACCEPTANCE_PLAN.md) for the full live
qualification boundary and pass criteria. Enabling Wazuh archives increases storage consumption,
so define retention and cleanup before collecting trial data.

Official references:

- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Wazuh Indexer indices and archives](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
- [Microsoft Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
