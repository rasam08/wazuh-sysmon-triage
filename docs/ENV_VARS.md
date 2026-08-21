# Environment variables

Only four environment variables are read by the CLI, all for Wazuh Indexer/OpenSearch connections:

| Variable | Required for live use | Default | Meaning |
| --- | --- | --- | --- |
| `WAZUH_OS_HOST` | Yes, unless set by CLI/config | None | Base URL for the Indexer API, such as `https://indexer:9200`. |
| `WAZUH_OS_USER` | Yes, unless set by CLI/config | None | Indexer username. Use a read-only account. |
| `WAZUH_OS_PASSWORD` | Yes, unless passed on the CLI | None | Indexer password. YAML passwords are ignored. |
| `WAZUH_OS_VERIFY_TLS` | No | Profile/config dependent | `true` or `false` override for certificate verification. |

PowerShell example:

```powershell
$env:WAZUH_OS_HOST = "https://indexer:9200"
$env:WAZUH_OS_USER = "triage-readonly"
$env:WAZUH_OS_PASSWORD = "<password>"
$env:WAZUH_OS_VERIFY_TLS = "true"
```

macOS/Linux example:

```bash
export WAZUH_OS_HOST="https://indexer:9200"
export WAZUH_OS_USER="triage-readonly"
export WAZUH_OS_PASSWORD="<password>"
export WAZUH_OS_VERIFY_TLS="true"
```

`.env.example` is a template only. The CLI does not automatically read `.env`; set the variables in the current process or use a secret manager.

For `host` and `user`, precedence is CLI flag, selected profile, base config, then environment. Password precedence is CLI flag then environment; any password in YAML is ignored with a warning. TLS precedence is CLI flag, environment, selected profile, base config, then the profile default.

Keep TLS verification enabled outside an isolated disposable lab. Use a dedicated account with read access only to the alert and archive index patterns needed for the investigation.
