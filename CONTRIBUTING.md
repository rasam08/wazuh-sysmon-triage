# Contributing

## Scope

This repository contains:

- Python triage engine in `src/wazuh_sysmon_triage`
- CI and release automation in `.github/workflows`

All contributions must preserve CLI and artifact compatibility unless explicitly approved as a breaking change.

## Local Setup

1. Install Python 3.12.
2. Install Python deps:

```powershell
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install build twine pytest pytest-cov ruff mypy types-PyYAML
```

## Development Workflow

1. Create a focused branch from `main`.
2. Keep changes additive for CLI and artifact contracts where possible.
3. Add tests for behavior changes (unit/integration as applicable).
4. Update docs when runtime behavior, environment variables, or output contracts change.

## Required Validation Before PR

Run the same gates CI enforces:

```powershell
python -m ruff check src tests scripts
python -m mypy src
python -m pytest -q
python scripts/check_markdown_links.py
python -m build
python -m twine check dist/*
python scripts/benchmark_offline.py --source-events 10000 --selected-events 10000 --repeat 2 --max-seconds 30 --max-rss-mib 512 --report benchmark-report-10k.json
```

Recommended additional checks:
```powershell
python -m ruff check src tests
python -m mypy src
```

## Code Standards

- Prefer smallest safe change over broad refactors.
- Keep CLI and artifact contracts stable; new behavior should be additive.
- Use explicit errors with stable status codes and clear messages.
- Avoid introducing new global state.
- Use synthetic fixtures with reserved domains and address ranges; never commit real telemetry.

## PR Checklist

- [ ] Behavior is covered by tests.
- [ ] Existing tests remain green.
- [ ] CLI and output contract docs updated when needed.
- [ ] Env var docs updated (`docs/ENV_VARS.md`) when needed.
- [ ] Security impact reviewed (credentials, TLS, paths, and secrets).
- [ ] New samples contain synthetic data only.
- [ ] Performance impact reviewed for fetch, normalization, correlation, and rendering paths.

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
