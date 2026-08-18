# Environment Variables

The CLI uses these environment variables for live Wazuh Indexer queries.

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `WAZUH_OS_HOST` | string | none | OpenSearch/Wazuh Indexer base URL. |
| `WAZUH_OS_USER` | string | none | OpenSearch username. |
| `WAZUH_OS_PASSWORD` | string | none | OpenSearch password. Inline configuration passwords are ignored and warned. |
| `WAZUH_OS_VERIFY_TLS` | boolean | profile/config dependent | Overrides TLS certificate verification when set. |

CLI flags take precedence over profile/config values where supported. Credentials should be
supplied through environment variables or an external secret manager, not committed configuration
files. Use a dedicated account with read access only to the required alert and archive indices.
