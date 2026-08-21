# ADR 0003: Artifact schema compatibility

## Status

Accepted

## Context

Downstream tooling may consume the generated artifact files directly. Silent changes to names, types, or meaning would make old case bundles difficult to compare and could mislead an automated reader.

## Decision

Within a major output-schema version, keep changes additive for:

- `run_metadata.json`
- `stats.json`
- `alerts.csv`
- `timeline.csv`
- `report.md`

Writers include `schema_version`, readers treat missing optional evidence as unknown, and breaking semantic changes require a new major schema.

## Consequences

- Existing v2 consumers can ignore additive fields they do not understand.
- The v2 schema is intentionally not a promise of byte-for-byte compatibility with v1.
- New metadata takes more care because defaults must not invent evidence that an older artifact never recorded.
