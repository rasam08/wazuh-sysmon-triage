# Troubleshooting

## 1) "Redirect to /app/login" or unexpected HTML responses

Cause: The host points to Wazuh Dashboards/UI (often `:443`) instead of the Indexer API.

Fix: Point `WAZUH_OS_HOST` / `--host` to the OpenSearch HTTP API endpoint (commonly `:9920`).

## 2) TLS certificate errors

Cause: Self-signed or lab certificates.

Fix: Use `--no-verify-tls` for lab environments.

## 3) Connection refused to :9920

Cause: Indexer API bound to localhost on the server.

Fix: Use an SSH local port forward:

```powershell
ssh -N -L 9920:localhost:9920 <user>@<wazuh-server>
```

Then set:

```powershell
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"
```

## 4) Authentication failures

Fix:

- Verify `WAZUH_OS_USER` / `WAZUH_OS_PASSWORD`
- Confirm the account has read access to the alert indices matching your `--index-pattern`

## 5) No results returned

Checklist:

- Confirm the time window (`--start`, `--end`) contains events.
- Confirm the agent selector (`--agent-name` or `--agent-id`) matches the endpoint.
- Confirm the index pattern (`--index-pattern`) matches your Wazuh alert indices.
- Try widening the time window to validate connectivity and filtering.

## 6) Pagination / PIT

Some indexer builds do not support `/_pit`. The tool should fall back automatically.
If you see unexpected truncation, consider:

- Using `--max-events` / `--max-pages`
- Using `--fail-on-truncation` when you need strict completeness
