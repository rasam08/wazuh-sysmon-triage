# Runbook: Wazuh Indexer is unreachable

Use this when a live command reports a connection, authentication, TLS, or timeout failure.

## First checks

1. Confirm `WAZUH_OS_HOST` points to the Indexer API rather than Wazuh Dashboards.
2. Check host/port reachability from the same workstation or container running the CLI.
3. Verify the username, password source, TLS setting, and certificate chain.
4. Confirm the account can read the selected alert/archive pattern.

```powershell
triage live --dry-run-query --last 15m --agent-name <name>
```

This validates only resolved configuration and query construction; it does not contact Wazuh.

## Recovery

After correcting the network, authentication, or certificate issue, run a small bounded query with a short window and low event/page caps. Confirm every pipeline stage finishes before returning to the original investigation window.

Record whether the cause was routing/firewall, wrong service/port, credentials, certificate trust, permissions, or configuration drift. Update the lab/config guardrail if the same mistake is likely to recur.
