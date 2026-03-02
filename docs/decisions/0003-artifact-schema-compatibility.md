# ADR 0003: Artifact Schema Compatibility

## Status
Accepted

## Context
Downstream tooling consumes existing artifact files and schema conventions.

## Decision
Preserve existing artifact schema contracts for:
- `run_metadata.json`
- `stats.json`
- `alerts.csv`
- `timeline.csv`
- `report.md`

New metadata is additive only (`job_state.json`) and must not break existing readers.

## Consequences
- Backward compatibility for existing v1 consumers.
- Lower migration risk when introducing async orchestration metadata.
