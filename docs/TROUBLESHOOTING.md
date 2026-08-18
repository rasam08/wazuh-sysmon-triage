# Troubleshooting

## 1) "Redirect to /app/login" or unexpected HTML responses

Cause: The host points to Wazuh Dashboards/UI (often `:443`) instead of the Indexer API.

Fix: Point `WAZUH_OS_HOST` / `--host` to the Indexer API endpoint. Wazuh uses `:9200`
by default; `:9920` is only a local or deployment-specific remap.

## 2) TLS certificate errors

Cause: Self-signed or lab certificates.

Fix: Prefer the Indexer CA certificate. Use `--no-verify-tls` only for an isolated,
disposable lab and document the exception.

## 3) Connection refused to :9200

Cause: Indexer API bound to localhost on the server.

Fix: Use an SSH local port forward:

```powershell
ssh -N -L 9920:localhost:9200 <user>@<wazuh-indexer>
```

Then set:

```powershell
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"
```

## 4) Authentication failures

Fix:

- Verify `WAZUH_OS_USER` / `WAZUH_OS_PASSWORD`
- Confirm the account has read access to the alert indices matching your `--index-pattern` and,
  when used, the archive indices matching `--context-index-pattern`

## 5) Unexpected host/user/TLS settings

Cause: Effective settings may come from different sources (CLI flags, profile/config, environment).

Notes:

- `triage live` and `triage offline` auto-load `config.local.yaml` if present.
- Runtime prints: `[process] config: using config.local.yaml (override with --config)` when this occurs.
- Precedence is:
	- `host`, `user`: CLI > profile/config > environment
	- `password`: CLI > environment; inline configuration passwords are ignored and warned

Fix:

- Pass explicit flags (`--host`, `--user`, `--no-verify-tls`) for one-off runs, or
- set them in your selected profile/config and remove stale environment variables.

## 6) No results returned

Checklist:

- Confirm the time window (`--start`, `--end`) contains events.
- Confirm the agent selector (`--agent-name` or `--agent-id`) matches the endpoint.
- Confirm the index pattern (`--index-pattern`) matches your Wazuh alert indices.
- Try widening the time window to validate connectivity and filtering.

## 7) Pagination / PIT

Some indexer builds do not support `/_pit`. The tool should fall back automatically.
If you see unexpected truncation, consider:

- Using `--max-events` / `--max-pages`
- Using `--fail-on-truncation` when you need strict completeness

## 8) Too many alerts from normal background activity

Cause: Environment noise differs between lab, dev, and production endpoints.

Fix:

- Add targeted `suppressions.rules` in config (image glob/regex, user, destination class, ports).
- Use `suppressions.allowlist_override` to keep high-interest processes visible even when broad suppressions exist.
