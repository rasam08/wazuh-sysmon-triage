# Environment Variables

Reference for runtime environment variables used by this project.

| Variable | Component | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `WAZUH_OS_HOST` | both | string | none | OpenSearch / Wazuh Indexer base URL used by the CLI for live mode; also read by the UI server health probe as a host fallback. |
| `WAZUH_OS_USER` | CLI | string | none | OpenSearch username for CLI live queries. |
| `WAZUH_OS_PASSWORD` | CLI | string | none | OpenSearch password for CLI live queries (preferred over inline config secrets). |
| `WAZUH_OS_VERIFY_TLS` | CLI | boolean | profile/config-dependent (typically `true`) | TLS verification override for OpenSearch connections. Parsed as a boolean when set. |
| `AUTH_USER` | UI server | string | none | Optional HTTP Basic Auth username for the standalone UI server. Must be set together with `AUTH_PASS`. |
| `AUTH_PASS` | UI server | string | none | Optional HTTP Basic Auth password for the standalone UI server. Must be set together with `AUTH_USER`. |
| `PUBLIC_BIND` | UI server | boolean | `false` | Explicit flag to permit non-local bind hosts. When `false`, server only allows loopback bind addresses. |
| `BIND_HOST` | UI server | string | `127.0.0.1` (or `0.0.0.0` if `PUBLIC_BIND=true`) | Host/interface used by the standalone UI server listener. Non-loopback binds require `PUBLIC_BIND=true` and auth. |
| `PORT` | UI server | integer | `4173` | Bind port for the standalone UI server. |
| `TRIAGE_RUN_TIMEOUT_MS` | UI middleware | integer | `900000` | Maximum run duration before middleware cancels the run and returns timeout. |
| `TRIAGE_OFFLINE_INPUT_ROOTS` | UI middleware | path list (OS-delimited) | `<repo>/samples` | Allowed root directories for offline `input_file` paths accepted by `/api/runs` and `/api/runs/preview`. |
| `TRIAGE_ASYNC_RUNS_ENABLED` | UI middleware | boolean | `false` | Feature flag reserved for async run orchestration endpoints. Existing synchronous `/api/runs` behavior is unchanged when disabled. |
| `TRIAGE_ENFORCE_CSRF` | UI middleware | boolean | `false` | Enables browser-focused CSRF checks on mutating API routes (`POST`, `PUT`, `PATCH`, `DELETE`) using `X-Requested-With` plus same-origin validation. |
| `TRIAGE_HEALTH_CACHE_MS` | UI middleware | non-negative integer | `30000` | Health snapshot cache TTL in milliseconds. `0` disables cache; positive values use stale-while-revalidate behavior. |
| `TRIAGE_OPENSEARCH_HOST_ALLOWLIST` | UI middleware | comma/space-separated host rules | none (allow all) | Optional allowlist for health probe OpenSearch targets. Supports exact hosts (`indexer.example.local`), wildcard suffixes (`*.example.local`), and IPv4 CIDR (`10.10.0.0/16`). Disallowed hosts are rejected before any network request. |
| `TRIAGE_IDEMPOTENCY_WINDOW_MS` | UI middleware | integer | `86400000` | Retention window for `Idempotency-Key` replay cache on `POST /api/runs`. |
| `TRIAGE_RUN_INDEX_TTL_MS` | UI middleware | integer | `5000` | TTL in milliseconds for the run index manifest cache used by `GET /api/runs` and latest-run selection paths. |
| `TRIAGE_PYTHON_EXE` | UI middleware | string | `python` | Python executable used by queue-state SQLite persistence bridge in async run orchestration. |
| `TRIAGE_AUTH_MAX_FAILURES` | UI server | integer | `8` | Maximum failed Basic Auth attempts per client within the auth failure window before lockout starts. |
| `TRIAGE_AUTH_WINDOW_MS` | UI server | integer | `300000` | Rolling window for counting Basic Auth failures per client. |
| `TRIAGE_AUTH_LOCKOUT_MS` | UI server | integer | `120000` | Lockout period applied after excessive failed Basic Auth attempts. |
| `TRIAGE_ALLOW_INSECURE_PUBLIC_BIND` | UI server | boolean | `false` | Required for non-loopback bind hosts because standalone server transport is HTTP. Set to `true` only when TLS is terminated at a trusted reverse proxy/network boundary. |
