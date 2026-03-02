# Wazuh Sysmon Triage UI

Web interface for `wazuh-sysmon-triage` with:

- Vite middleware API for local dev (`npm run dev`)
- standalone Express API+static server for production (`npm start`)

Both server paths:

- spawns Python CLI runs
- reads real case artifacts from disk
- exposes `/api/*` (and `/api/v1/*`) endpoints used by the React app

## Setup

```bash
cd ui
npm install
npm run dev
npm run test
npm run build
npm start
```

Requirements: Node.js 18+ (CI uses Node 20).

## Runtime architecture

```text
React UI (src/*)
  -> fetch /api/*
Standalone Express server OR Vite middleware (server/*)
  -> validates input
  -> spawns `python -m wazuh_sysmon_triage ...`
  -> reads artifacts under ../out/<case_id>/
Python CLI (../src/wazuh_sysmon_triage/*)
  -> writes timeline.csv, alerts.csv, process_tree.json, report.md, bundles, metadata/stats
```

## Standalone runtime

After `npm run build`, run:

```bash
npm start
```

From repo root, Windows operators can use the guided launcher:

```powershell
.\scripts\start-ui-live.ps1
```

This runs preflight checks (required live env vars, tunnel/indexer port check, port availability) before starting the standalone server.

Default bind is `0.0.0.0:4173` (override with `PORT`).

Optional HTTP Basic auth:

```bash
AUTH_USER=analyst AUTH_PASS=changeme npm start
```

## API endpoints

- `GET /api/runs`
- `POST /api/runs`
- `POST /api/runs/preview`
- `GET /api/cases/:caseId`
- `GET /api/alerts?case=<caseId>`
- `GET /api/alerts/:alertId/bundle?case=<caseId>`
- `GET /api/report?case=<caseId>`

See [../docs/API_CONTRACT.md](../docs/API_CONTRACT.md) for request/response details.

## Security and safety

- `case_id` allowlist validation blocks traversal patterns.
- Artifact reads are constrained to the output root via realpath checks.
- Run params are validated before spawn.
- Spawn uses argument arrays (no shell interpolation).
- Single in-process run lock prevents parallel clobbering.
- Existing case overwrite requires `allow_overwrite=true` or `force=true`.

## Current limitations

- Optional HTTP Basic auth only (`AUTH_USER`/`AUTH_PASS`), no full session/RBAC model.
- In-process run lock is per middleware process (not distributed).
- UI settings exports/annotations remain local-browser state.
