# Runbook: OpenSearch Unreachable

## Detection
- `/api/health` returns `opensearch_connectivity=unreachable`
- UI health indicator turns degraded

## Immediate Actions
1. Verify OpenSearch host/port reachability from server host.
2. Validate credentials/TLS mode and certificate chain.
3. Confirm SSRF allowlist and environment config permit target host.

## Recovery
1. Correct host/auth/TLS settings.
2. Re-run `/api/health?profile=<profile>` until reachable.
3. Run a small triage job to validate end-to-end fetch success.

## Post-Incident
- Document root cause (network, auth, certificate, config drift).
- Add/update environment configuration guardrails.
