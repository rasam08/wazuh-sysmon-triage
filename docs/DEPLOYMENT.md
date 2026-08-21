# Installation and deployment

This project is a local CLI. It does not start an HTTP service, expose a port, or require the retired web UI.

The GitHub release contains a Python wheel and source distribution. The package is not currently published to PyPI, and the Dockerfile is provided for local builds rather than a published container-registry image.

## Install from a source checkout

Python 3.12 or later is required.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\triage.exe --version
```

macOS/Linux:

```bash
python3.12 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install .
./.venv/bin/triage --version
```

You can activate the environment and use the shorter `triage` command, or keep calling the executable by its full virtual-environment path.

## Install a release wheel

Download the wheel and `SHA256SUMS.txt` from the matching GitHub release, verify the checksum, and install the local file:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .\wazuh_sysmon_triage-2.0.0-py3-none-any.whl
.\.venv\Scripts\triage.exe --version
```

Replace the filename with the version you downloaded. Installing `wazuh-sysmon-triage` by name from PyPI is not a supported installation path today.

## Build the container locally

```bash
docker build -t wazuh-sysmon-triage:local .
docker run --rm wazuh-sysmon-triage:local --version
docker run --rm wazuh-sysmon-triage:local --help
```

The image contains the CLI, bundled samples, and `config.example.yaml`. It runs as the unprivileged `triage` user.

Offline replay on macOS/Linux:

```bash
mkdir -p out
docker run --rm \
  -v "$(pwd)/out:/app/out" \
  wazuh-sysmon-triage:local offline \
  --input-ndjson /app/samples/incident_001/raw_hits.ndjson \
  --case-id INCIDENT-001 \
  --out-dir /app/out
```

Offline replay in Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force out | Out-Null
docker run --rm -v "${PWD}\out:/app/out" wazuh-sysmon-triage:local `
  offline --input-ndjson /app/samples/incident_001/raw_hits.ndjson `
  --case-id INCIDENT-001 --out-dir /app/out
```

On Linux, a bind-mounted output directory must be writable by the container user. If it is not, fix the host directory ownership or permissions according to your environment rather than running the container as root by default.

## Live container configuration

Pass connection settings through environment variables and mount an output directory:

```bash
docker run --rm \
  -v "$(pwd)/out:/app/out" \
  -e WAZUH_OS_HOST \
  -e WAZUH_OS_USER \
  -e WAZUH_OS_PASSWORD \
  -e WAZUH_OS_VERIFY_TLS \
  wazuh-sysmon-triage:local live \
  --last 2h \
  --agent-name windows-lab-01 \
  --out-dir /app/out
```

The CLI does not load `.env` files on its own. Docker's explicit `--env-file` option can load one, but that file must stay outside Git and should be protected like any other credential file.

Live compatibility is still awaiting real-lab qualification. Read [LAB_SETUP.md](LAB_SETUP.md) before treating a successful query as a supported deployment.

## Output storage

Case bundles are written below `--out-dir` (default `./out`). Back up, retain, and delete that directory according to your evidence-handling policy. Unsanitized output may contain usernames, hostnames, command lines, paths, and network addresses.
