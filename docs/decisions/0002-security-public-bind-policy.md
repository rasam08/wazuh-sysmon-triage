# ADR 0002: Public Bind Security Policy

## Status
Accepted

## Context
Binding to non-loopback interfaces without auth/transport constraints is unsafe.

## Decision
Require explicit intent and authentication for non-local bind:
- `PUBLIC_BIND=true`
- `AUTH_USER` and `AUTH_PASS` required for non-loopback host

Apply request hardening:
- CSRF guard for browser mutating routes (feature-flagged)
- Rate limiting per normalized route + client key
- Basic auth brute-force lockout in standalone server

## Consequences
- Safer defaults for local and public usage.
- Misconfigured public deployments fail fast at startup.
