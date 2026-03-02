# Deployment Guide

## Prerequisites

- Docker path: Docker Engine `24+` and Docker Compose plugin.
- Bare-metal path: Python `3.12+` and Node.js `20+` with npm.

## Docker Single-Image

Build:

```bash
docker build -t wazuh-triage .
```

Run with persistent output and common runtime environment variables:

```bash
docker run --rm -p 4173:4173 \
  -v "$(pwd)/out:/app/out" \
  -e PORT=4173 \
  -e PUBLIC_BIND=true \
  -e BIND_HOST=0.0.0.0 \
  -e TRIAGE_ALLOW_INSECURE_PUBLIC_BIND=true \
  -e AUTH_USER=analyst \
  -e AUTH_PASS=changeme \
  -e WAZUH_OS_HOST=https://indexer:9200 \
  -e WAZUH_OS_USER=admin \
  -e WAZUH_OS_PASSWORD=changeme \
  -e WAZUH_OS_VERIFY_TLS=true \
  wazuh-triage
```

Notes:

- Server defaults to loopback bind (`127.0.0.1`). For container or remote access, set `PUBLIC_BIND=true` and provide non-empty `AUTH_USER`/`AUTH_PASS`.
- Non-loopback binds also require `TRIAGE_ALLOW_INSECURE_PUBLIC_BIND=true` because the standalone app serves HTTP directly. Use this only behind a trusted TLS-terminating reverse proxy/network boundary.
- Basic auth brute-force throttling is enabled by default. Tune with `TRIAGE_AUTH_MAX_FAILURES`, `TRIAGE_AUTH_WINDOW_MS`, and `TRIAGE_AUTH_LOCKOUT_MS` if needed.
- Optionally constrain OpenSearch health probe targets with `TRIAGE_OPENSEARCH_HOST_ALLOWLIST` (exact hosts, `*.suffix`, and IPv4 CIDR).
- Container output artifacts are written under `/app/out`, mapped above to local `./out`.

## Docker Compose

Start:

```bash
docker compose up --build
```

Use a `.env` file in the repo root for compose variable expansion:

```dotenv
AUTH_USER=analyst
AUTH_PASS=changeme
PUBLIC_BIND=true
BIND_HOST=0.0.0.0
TRIAGE_ALLOW_INSECURE_PUBLIC_BIND=true
```

Override auth at runtime without editing compose:

```bash
AUTH_USER=analyst AUTH_PASS=changeme docker compose up --build
```

## Bare-Metal Install

Install Python package and UI dependencies, then build and run the standalone UI/API server:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install .
npm --prefix ui install
npm --prefix ui run build
npm --prefix ui start
```

Windows PowerShell activation:

```powershell
.\.venv\Scripts\Activate.ps1
```

## TLS Termination

For production HTTPS, terminate TLS at a reverse proxy (recommended: Nginx or Caddy) in front of the app on `:4173`.

## Health Check

```bash
curl http://localhost:4173/api/health
```

## Backup And Restore

Backup:

```bash
cp -r out out.backup
```

Restore:

```bash
rm -rf out
cp -r out.backup out
```

