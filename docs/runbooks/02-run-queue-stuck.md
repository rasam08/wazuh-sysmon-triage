# Runbook: Run Queue Stuck

## Detection
- `triage_run_queue_depth{state="queued"}` remains high for extended period
- No progress/terminal SSE events for active jobs

## Immediate Actions
1. Query `/api/runs/jobs/:jobId` for affected job(s).
2. Verify runner active case lock state and process health.
3. Review queue state under `.run-queue/run_queue.sqlite3` (or legacy `.run-queue/run_queue_state.json` fallback).

## Recovery
1. Cancel blocked job via `POST /api/runs/jobs/:jobId/cancel`.
2. If queue remains blocked, restart server and verify job state recovery.
3. Confirm new submit transitions `queued -> running -> terminal`.

## Post-Incident
- Record job IDs and error messages.
- Add test coverage for observed stuck condition.
