# ADR 0005: API Evolution with v1 Safety

## Status
Accepted

## Context
Product improvements require API growth without breaking existing integrations.

## Decision
Use additive API evolution:
- Keep existing route semantics unchanged.
- Add new endpoints and optional fields instead of mutating required payloads.
- Normalize route keys for logging/metrics and preserve consistent error model.

## Consequences
- New capabilities ship incrementally without forced client migrations.
- Contract testing remains the primary compatibility guard.
