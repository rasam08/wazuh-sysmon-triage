# Runbook: Run Failure Spike

## Detection
- Rising failed terminal statuses in `/api/runs/jobs/:jobId`
- Increased `triage_run_submit_errors_total` or frequent failed runs in UI

## Immediate Actions
1. Sample failed job payloads for common error text.
2. Verify artifact output directory write permissions and free space.
3. Confirm input file paths/case IDs pass validation.

## Recovery
1. Fix shared configuration or filesystem issue.
2. Retry one known-failing run and confirm success.
3. Monitor queue/job metrics for normalization.

## Post-Incident
- Add regression test for the failure class.
- Update docs/runbooks with new diagnostics if needed.
