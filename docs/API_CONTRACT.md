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
- `403` CSRF or origin policy rejection (when enabled)
- `404` case/bundle/route not found
- `408` run timeout
- `409` run conflict (already running, overwrite denied, active-case delete blocked)
- `413` artifact too large
- `429` middleware rate limit
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
  - `input_file` (offline only): must be a relative path under middleware-allowed offline roots

`out_dir` is normalized to the middleware-configured output root (server-owned boundary).

- `Run`, `Case`, `Alert`, `AlertBundle`, `RunStats` follow UI type definitions in `ui/src/types/index.ts`.

## Endpoints

### `GET /api/runs`

Optional query params (all additive):

- `limit=<n>`
- `offset=<n>`
- `status=<pending|running|success|failed|cancelled>`
- `mode=<live|offline>`

Response:

```json
{ "runs": [Run] }
```

Implementation note:
- Responses are cached using a run index manifest (`.run-index/run_manifest.json`) with a short TTL.
- Mutating run/case routes invalidate the manifest cache.

### `POST /api/runs`

Request body:

```json
{ "params": RunParams }
```

Unknown fields are ignored and never forwarded to spawn.

Optional headers:

- `Idempotency-Key: <token>` to safely replay identical submits within the idempotency retention window.

Behavior:

- validates/coerces params
- enforces offline input path boundary (no absolute/traversal; allowed roots only)
- enforces run mutex
- enforces overwrite policy
- spawns `python -m wazuh_sysmon_triage ...`
- when `Idempotency-Key` is present:
  - identical replay returns the original response without starting a second run
  - same key with a different body is rejected with `409`

Response:

```json
{ "run": Run }
```

### `POST /api/runs/:caseId/cancel`

Requests cancellation of an active run for `caseId`.

Response:

```json
{ "cancelled": true, "case_id": "...", "reason": "user" }
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
If the target case has an active run, delete is blocked with `409`.

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

Health probe host policy:
- If `TRIAGE_OPENSEARCH_HOST_ALLOWLIST` is configured, the resolved OpenSearch host must match an allowlist rule (exact host, `*.suffix`, or IPv4 CIDR) before any network call is attempted.
- Disallowed hosts are returned as `opensearch_connectivity: "unreachable"` with an error token like `host_not_allowlisted:<host>`.

### `POST /api/runs/submit` (feature flag)

Async run submit endpoint gated by `TRIAGE_ASYNC_RUNS_ENABLED`.

- disabled flag: treated as unknown route (`404`)
- enabled flag: accepts run and queues execution (`202`)

Request body:

```json
{ "params": RunParams }
```

Optional headers:

- `Idempotency-Key: <token>` for stable replay of identical submit bodies.

Response:

```json
{
  "job_id": "uuid",
  "case_id": "CASE-...",
  "accepted_at": "2026-02-28T20:00:00.000Z"
}
```

Implementation note:
- Queue orchestration state is durably persisted under `.run-queue/run_queue.sqlite3`.
- If SQLite persistence is unavailable, middleware falls back to legacy `.run-queue/run_queue_state.json`.

### `GET /api/runs/jobs/:jobId`

Returns job lifecycle state:

```json
{
  "job": {
    "job_id": "uuid",
    "case_id": "CASE-...",
    "status": "queued|running|success|failed|cancelled",
    "stage": "queued|running|completed|failed|cancelled",
    "progress_pct": 0,
    "accepted_at": "2026-02-28T20:00:00.000Z"
  }
}
```

### `POST /api/runs/jobs/:jobId/cancel`

Requests cancellation for queued/running async jobs.

Response:

```json
{
  "cancelled": true,
  "job": { "job_id": "uuid", "status": "cancelled" }
}
```

### `GET /api/runs/jobs/:jobId/stream`

SSE progress stream (`text/event-stream`) for async jobs.

Event payload schema:

```json
{
  "event": "progress|terminal",
  "job_id": "uuid",
  "case_id": "CASE-...",
  "stage": "queued|running|completed|failed|cancelled",
  "progress_pct": 0,
  "status": "queued|running|success|failed|cancelled",
  "ts": "2026-02-28T20:00:00.000Z",
  "message": "optional",
  "cancel_reason": "optional"
}
```

### `GET /metrics`

Prometheus-compatible runtime metrics endpoint (also available at `/api/metrics`).

Includes:
- request totals/errors/success ratio
- per-route request and latency counters
- run queue depth and job status counts
- run submit/cancel counters
- health endpoint request counter

Health responses are cached by `(rootDir, outDir, profile)` per `TRIAGE_HEALTH_CACHE_MS` using stale-while-revalidate semantics.

## Browser mutation CSRF policy

When `TRIAGE_ENFORCE_CSRF=true`, browser-origin mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`) must satisfy:

- `X-Requested-With: XMLHttpRequest`
- `Origin` must match request host/protocol (when `Origin` is present)
- `Sec-Fetch-Site` must be `same-origin`, `same-site`, or `none` (when present)

Non-browser/internal calls without browser-origin headers remain supported.

## `/api/v1` alias policy

Recommended client policy:

1. Prefer `/api/v1/*` in new clients.
2. Keep `/api/*` support during migration.
3. Introduce breaking changes only under future versioned prefixes (for example `/api/v2/*`).
