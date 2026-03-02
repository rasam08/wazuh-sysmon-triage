# Contributing

## Scope
This repository contains:
- Python triage engine in `src/wazuh_sysmon_triage`
- UI and middleware API in `ui/`
- CI and release automation in `.github/workflows`

All contributions must preserve v1 API and artifact compatibility unless explicitly approved as a breaking change.

## Local Setup
1. Install Python 3.12 and Node 20.
2. Install Python deps:
```powershell
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install pytest pytest-cov ruff mypy types-PyYAML
```
3. Install UI deps:
```powershell
npm --prefix ui ci
```

## Development Workflow
1. Create a focused branch from `main`.
2. Keep changes additive for API contracts where possible.
3. Add tests for behavior changes (unit/integration/e2e as applicable).
4. Update docs when runtime behavior, env vars, routes, or operational posture changes.

## Required Validation Before PR
Run the same gates CI enforces:
```powershell
python -m pytest -q
npm --prefix ui run test -- --run
npm --prefix ui run build
```

Recommended additional checks:
```powershell
python -m ruff check src tests
python -m mypy src
npm --prefix ui run test:e2e:smoke
```

## Code Standards
- Prefer smallest safe change over broad refactors.
- Keep route contracts stable; new behavior should be additive.
- Avoid sync FS in API hot paths when adding new code.
- Use explicit errors with stable status codes and clear messages.
- Avoid introducing new global state unless required for service-level caching/metrics.

## PR Checklist
- [ ] Behavior is covered by tests.
- [ ] Existing tests remain green.
- [ ] API contract docs updated (`docs/API_CONTRACT.md`) when needed.
- [ ] Env var docs updated (`docs/ENV_VARS.md`) when needed.
- [ ] Security impact reviewed (auth, CSRF, SSRF, secrets).
- [ ] Performance impact reviewed for `/api/runs`, `/api/health`, and alert rendering paths.

## Commit Message Guidance
Use concise conventional style:
- `feat: ...`
- `fix: ...`
- `chore: ...`
- `docs: ...`
- `test: ...`

## Incident/Operations Docs
Operational runbooks live in `docs/runbooks/`.
Architectural decisions are captured under `docs/decisions/`.
