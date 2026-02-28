# API Contract

## Base path

Active middleware routes are exposed at:

- `/api/*`
- `/api/v1/*` (alias to `/api/*` for versioned clients)

## Error model

All error responses use:

```json
{ "error": "message" }
```

Common statuses:

- `400` invalid JSON/params/case id
- `404` case/bundle/route not found
- `409` run conflict (already running, overwrite denied)
- `413` artifact too large
- `500` internal execution/read failure

## Types (high level)

- `RunParams`
  - `mode`: `live | offline`
  - `profile`: `soc | dev | lab`
  - `time_preset`: `15m | 2h | 24h | 7d | today | yesterday | custom`
  - `start`, `end` (required only when `time_preset=custom`)
  - `queues`: `soc_malware | soc_policy | soc_dev | soc_info`[]
  - `include_dev_queue`, `min_alert_score`, `out_dir`, `case_id`
  - `dry_run`, `alerts_only`, `print_stats`, optional `verify_tls`
    - when omitted, CLI resolves TLS mode from env/profile defaults
  - `allow_overwrite`, `force`

`out_dir` is normalized to the middleware-configured output root (server-owned boundary).

- `Run`, `Case`, `Alert`, `AlertBundle`, `RunStats` follow UI type definitions in `ui/src/types/index.ts`.

## Endpoints

### `GET /api/runs`

Response:

```json
{ "runs": [Run] }
```

### `POST /api/runs`

Request body:

```json
{ "params": RunParams }
```

Unknown fields are ignored and never forwarded to spawn.

Behavior:

- validates/coerces params
- enforces run mutex
- enforces overwrite policy
- spawns `python -m wazuh_sysmon_triage ...`

Response:

```json
{ "run": Run }
```

### `POST /api/runs/preview`

Request body:

```json
{ "params": RunParams }
```

Response:

```json
{
  "preview": {
    "params": RunParams,
    "cli_args": ["..."],
    "command": "python ...",
    "warnings": ["..."]
  }
}
```

### `GET /api/cases/:caseId`

Response:

```json
{ "case": Case }
```

### `DELETE /api/cases/:caseId`

Deletes the case directory and all case artifacts from the middleware output root.

Response:

```json
{ "deleted": true, "case_id": "..." }
```

### `GET /api/alerts?case=<caseId>`

If `case` is omitted, middleware uses latest run.

Response:

```json
{ "alerts": [Alert], "case_id": "..." }
```

### `GET /api/alerts/:alertId/bundle?case=<caseId>`

Response:

```json
{ "bundle": AlertBundle }
```

### `GET /api/report?case=<caseId>`

Response:

```json
{ "report": "markdown text" }
```

### `GET /api/health?profile=<soc|dev|lab>`

Returns runtime health from middleware perspective:

```json
{
  "health": {
    "checked_at": "2026-02-26T01:00:00Z",
    "profile": "soc",
    "opensearch_host": "https://indexer:9920",
    "opensearch_connectivity": "reachable",
    "opensearch_http_status": 200,
    "tls_mode": "verify",
    "last_successful_fetch_at": "2026-02-26T00:58:00Z"
  }
}
```

## `/api/v1` alias policy

Recommended client policy:

1. Prefer `/api/v1/*` in new clients.
2. Keep `/api/*` support during migration.
3. Introduce breaking changes only under future versioned prefixes (for example `/api/v2/*`).
