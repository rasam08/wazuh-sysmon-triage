# Troubleshooting

## The response is HTML or redirects to `/app/login`

The host is probably Wazuh Dashboards (often port `443`), not the Indexer API.

Point `WAZUH_OS_HOST` or `--host` to the Wazuh Indexer/OpenSearch HTTP endpoint, commonly `https://<host>:9200`. Port `9920` is only a local/deployment-specific remap such as the SSH tunnel below.

## TLS certificate verification fails

Use the Indexer CA certificate when possible. `--no-verify-tls` is limited to an isolated disposable lab and prints a warning because it exposes the connection to man-in-the-middle attacks.

Check whether a stale `WAZUH_OS_VERIFY_TLS` value is overriding the YAML profile before changing the config.

## Port 9200 refuses the connection

The Indexer may listen only on the Wazuh host. Create a local tunnel:

```powershell
ssh -N -L 9920:localhost:9200 <user>@<wazuh-indexer>
```

Then, in another terminal:

```powershell
$env:WAZUH_OS_HOST = "https://127.0.0.1:9920"
```

Keep the SSH session open for the entire query.

## Authentication or authorization fails

- Verify `WAZUH_OS_USER` and `WAZUH_OS_PASSWORD` in the same shell that starts the CLI.
- Confirm the account has read permission for `--index-pattern`.
- For `triage alert --context-index-pattern ...`, confirm it can also read that archive/custom pattern.
- Do not put the password in YAML; the CLI ignores inline config passwords and warns.

## The effective config is surprising

`live`, `alert`, and `offline` auto-load `config.local.yaml` from the current directory. The CLI prints a short config line when it does this. An explicit `--config` path wins over auto-loading.

Precedence is:

- host/user: CLI, selected profile, base config, environment;
- password: CLI, environment; and
- TLS verification: CLI, environment, selected profile, base config, profile default.

The built-in `soc` profile includes the placeholder agent name `anon`. Pass a real `--agent-name`/`--agent-id`, or set `agent_name` in your config file or selected profile.

Use a no-network dry run to inspect the resolved query:

```powershell
triage live --config config.local.yaml --agent-name "windows-lab-01" --last 2h --dry-run-query
```

A successful dry run does not test reachability, credentials, permissions, certificates, or Wazuh mappings.

## A live query returns no events

- Widen the UTC window with `--last 24h`.
- Confirm the real agent selector and whether `--agent-mode all` is requiring both an ID and name.
- Confirm `--index-pattern` matches the installed Wazuh index names.
- Check Wazuh itself to make sure the event reached the Indexer.
- Remember that alert indices omit events that did not trigger a rule.

If alert-centered context is too sparse and archives are enabled/indexed, use:

```powershell
triage alert <opensearch-_id> --context-index-pattern "wazuh-archives-4.x-*"
```

## Results are truncated

The tool stops at `--max-events` or `--max-pages` and records the reason. Use `--fail-on-truncation` when an incomplete result must be a non-zero outcome.

Indexer builds without point-in-time support should fall back to scroll automatically. A fallback is not permission to ignore the recorded truncation state.

## Offline input is rejected

Look at `stats.json`/`run_metadata.json` `input_quality` and `quarantine.ndjson`. Stable reasons are `invalid_utf8`, `malformed_json`, `non_object_json`, and `record_too_large`.

`--quarantine-drops` includes a bounded raw preview. Treat it as sensitive. `--fail-on-input-errors` writes the normal case and then exits with code `5` if any input record was rejected.

## Normal endpoint activity produces too many findings

Add narrow `suppressions.rules` for known local behavior. Prefer a specific image/user/destination rule over a broad allowlist, and use `allowlist_override` when an important process must stay visible.

Suppression affects local findings, not whether the underlying event remains available in the timeline/process model. Review suppression counts after every tuning change.

## Artifacts cannot be written

Check free space and permissions for `--out-dir`. The Docker image runs as an unprivileged user, so Linux bind mounts must be writable by that user.

Do not delete old case directories casually. Archive or remove them according to the evidence-retention policy, then rerun a small offline sample to confirm writes work.
