# Live lab setup

You do not need a lab to review the project: the offline samples and acceptance corpus exercise the full local pipeline. A lab is only needed to qualify the live path from a Windows endpoint through Wazuh and back into this CLI.

That live qualification has not been run. This document describes what the trial requires; it does not claim any Wazuh/Sysmon version has passed.

## What the trial needs

### A disposable Windows endpoint

- A Windows VM or separate lab machine with administrator access.
- Sysmon installed with a fixed, recorded XML configuration.
- A Wazuh agent with a unique agent name.
- Collection of `Microsoft-Windows-Sysmon/Operational`.
- Windows Security auditing for any 4624, 4697, or 4698 checks included in the trial.
- A snapshot or other easy rollback point.

Use a disposable endpoint rather than a production workstation. Some full-coverage checks require administrator-only actions such as creating a temporary service or scheduled task.

### A Wazuh server and Indexer

- A non-production Wazuh deployment with the manager and Indexer/OpenSearch available.
- The alert index pattern, commonly `wazuh-alerts-4.x-*`.
- Indexed archives, commonly `wazuh-archives-4.x-*`, if the trial will verify context that did not trigger a Wazuh rule.
- A retention and cleanup plan before archives are enabled.
- Enough CPU, memory, and storage for the chosen Wazuh deployment. A practical single-node lab starting point is 4 CPU cores, 8 GB RAM, and 50 GB of free storage, but the Wazuh deployment guidance should be treated as authoritative for the version being installed.

Alerts and archives are not interchangeable. Alert indices only contain events that produced Wazuh alerts; archive indices can provide the fuller surrounding stream when archive indexing is enabled.

### A triage workstation

- Python 3.12+ or a locally built project container.
- This repository/package installed.
- A dedicated Indexer account with read access only to the required alert and archive patterns.
- The Indexer CA certificate, or a documented TLS exception limited to the disposable lab.
- A safe location outside Git for raw captures and generated case bundles.

Synchronize clocks across the Windows endpoint, Wazuh components, and triage workstation. Record the timezone and exact versions before generating evidence.

## Network path

Common Wazuh ports are:

- `443`: Wazuh Dashboards
- `9200`: Wazuh Indexer/OpenSearch HTTP API
- `1514`: agent event transport
- `1515`: agent enrollment

This CLI needs the Indexer API, not Dashboards. A redirect to `/app/login` or an HTML login page usually means `WAZUH_OS_HOST` points to the wrong service.

If the Indexer listens only on the Wazuh host, use an SSH tunnel instead of exposing it broadly:

```powershell
ssh -N -L 9920:localhost:9200 <user>@<wazuh-indexer>
```

In a second terminal:

```powershell
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"
$env:WAZUH_OS_USER = "triage-readonly"
$env:WAZUH_OS_PASSWORD = "<password>"
```

`9920` is only the local end of this example tunnel; Wazuh Indexer still uses `9200` on the remote side.

## Prepare the CLI without connecting

Copy and edit the example:

```powershell
Copy-Item config.example.yaml config.local.yaml
triage live --config config.local.yaml --agent-name "windows-lab-01" --last 2h --dry-run-query
```

The dry run checks resolved settings and query construction. It does not verify network reachability, credentials, certificates, permissions, index existence, Wazuh field mappings, or event flow.

Keep certificate verification enabled when possible. `--no-verify-tls` is acceptable only as an explicit, temporary exception in this isolated lab.

## Generate harmless smoke-test telemetry

A basic connectivity run does not need attack simulation:

- Sysmon 1: open `cmd.exe` or PowerShell and run a recognizable benign command.
- Sysmon 11: create a named file under a temporary lab directory.
- Sysmon 3: make an outbound request to `https://example.com`.
- Sysmon 5: close the process used for the test.

Give the events time to move through the agent, manager, and Indexer. Then query a small window with the real agent selector and a low event/page cap.

Full qualification also needs safe, named exercises for registry, DNS, process access, file deletion, remote logon, service creation, and scheduled-task creation. Those should be planned for the disposable VM, reviewed before execution, and cleaned up immediately afterward. Ordinary background activity must not be presented as malicious merely because it matches a correlation rule.

## What to record

The eventual qualification bundle should record:

- Wazuh manager, Indexer, agent, and Sysmon versions;
- the Sysmon configuration hash;
- tested alert and archive index patterns;
- CLI version and output schema;
- event IDs actually observed in each index;
- whether PIT pagination or scroll fallback was exercised;
- authentication, TLS, missing-index, timeout, and truncation results;
- sanitized artifact hashes and a pass/fail matrix; and
- cleanup confirmation.

Do not include credentials, private keys, or unsanitized production identities in that bundle.

The complete remaining pass criteria are in [PROFESSIONAL_ACCEPTANCE_PLAN.md](PROFESSIONAL_ACCEPTANCE_PLAN.md).

Official references:

- [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Wazuh Indexer indices and archives](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
- [Microsoft Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
