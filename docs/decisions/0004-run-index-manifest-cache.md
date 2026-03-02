# ADR 0004: Run Index Manifest Cache

## Status
Accepted

## Context
Repeated `GET /api/runs` requests can repeatedly rescan artifacts and degrade responsiveness.

## Decision
Add a run index manifest cache under output directory:
- Path: `.run-index/run_manifest.json`
- Contents: serialized run list and generation timestamp
- TTL-based reuse with explicit invalidation after run/cancel/delete mutations

## Consequences
- Steady-state run listing avoids repeated full artifact scans.
- Bounded staleness window controlled by `TRIAGE_RUN_INDEX_TTL_MS`.
