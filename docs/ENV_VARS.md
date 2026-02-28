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
| `PORT` | UI server | integer | `4173` | Bind port for the standalone UI server. |
