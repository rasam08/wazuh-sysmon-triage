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
