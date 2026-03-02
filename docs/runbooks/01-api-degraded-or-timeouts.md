# Runbook: API Degraded or Timeouts

## Detection
- Elevated `triage_api_errors_total`
- Increased `triage_api_route_duration_ms_max` on `/api/runs` or `/api/health`
- User reports of stalled dashboard loads

## Immediate Actions
1. Check `/metrics` and identify affected route(s).
2. Verify filesystem latency and output directory accessibility.
3. Inspect API logs for repeated 5xx errors and request IDs.

## Recovery
1. Reduce load source (polling clients, repeated refresh loops).
2. Restart standalone server if error pattern is persistent.
3. Validate `/api/runs`, `/api/health`, and `/api/alerts` post-restart.

## Post-Incident
- Capture top offending routes and durations.
- Add regression tests for the triggering condition.
