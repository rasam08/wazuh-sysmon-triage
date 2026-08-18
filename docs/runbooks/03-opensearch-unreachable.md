# Runbook: OpenSearch Unreachable

## Detection
- A live CLI run reports a connection, authentication, or TLS failure.
- A bounded fetch cannot reach the configured Indexer endpoint.

## Immediate Actions
1. Verify OpenSearch host/port reachability from the analyst host or container.
2. Validate credentials/TLS mode and certificate chain.
3. Confirm `WAZUH_OS_HOST` points to the Indexer API rather than Wazuh Dashboards.

## Recovery
1. Correct host/auth/TLS settings.
2. Run `triage live --dry-run-query --last 15m --agent-name <name>` to validate resolved
   configuration and query construction without contacting Wazuh.
3. Run a small bounded live query to validate connectivity and end-to-end fetch success.

## Post-Incident
- Document root cause (network, auth, certificate, config drift).
- Add/update environment configuration guardrails.
