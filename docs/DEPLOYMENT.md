# CLI Deployment Guide

The project is distributed as a Python package and as a CLI-only container. It does not run a web server or expose a network port.

## Python installation

Requirements: Python 3.12 or later.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
triage --help
```

On Windows PowerShell, activate with:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Container image

Build and inspect the CLI:

```bash
docker build -t wazuh-triage .
docker run --rm wazuh-triage --help
```

Run the bundled offline sample and persist artifacts:

```bash
docker run --rm \
  -v "$(pwd)/out:/app/out" \
  wazuh-triage offline \
  --input-ndjson /app/samples/incident_001/raw_hits.ndjson \
  --case-id INCIDENT-001 \
  --out-dir /app/out
```

Run a live query:

```bash
docker run --rm \
  -v "$(pwd)/out:/app/out" \
  -e WAZUH_OS_HOST \
  -e WAZUH_OS_USER \
  -e WAZUH_OS_PASSWORD \
  -e WAZUH_OS_VERIFY_TLS \
  wazuh-triage live \
  --last 2h \
  --agent-name anon \
  --out-dir /app/out
```

## Output storage

Case artifacts are written below the configured output directory. Back up or archive that directory according to local evidence-handling policy. Treat unsanitized outputs as potentially sensitive because they can contain hostnames, usernames, paths, command lines, and network addresses.
