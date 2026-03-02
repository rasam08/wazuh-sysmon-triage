# ADR 0001: Async Run Orchestration

## Status
Accepted

## Context
Synchronous run execution blocks request lifecycle and weakens cancellation/progress UX.

## Decision
Introduce async run orchestration with:
- `POST /api/runs/submit`
- `GET /api/runs/jobs/:jobId`
- `GET /api/runs/jobs/:jobId/stream` (SSE)
- `POST /api/runs/jobs/:jobId/cancel`

Keep legacy `POST /api/runs` behavior unchanged for compatibility.
Separate queue orchestration (`RunQueueService`) from execution (`RunExecutor`), with runner-backed adapter wiring.

## Consequences
- Existing clients continue working.
- New clients get queue-based UX with progress and cancellation.
- Queue durability uses SQLite-backed state under `.run-queue/run_queue.sqlite3` with legacy JSON fallback.
- Execution concerns are isolated behind a narrow executor contract, reducing orchestration/execution coupling.
