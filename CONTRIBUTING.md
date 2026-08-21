# Contributing

Thanks for taking an interest in the project. The most useful contributions are usually small, testable changes that make the evidence clearer without quietly changing what an existing case bundle means.

## Before you start

The maintained product is the Python CLI in `src/wazuh_sysmon_triage/`. The old React/Node interface is part of the repository history, not the current application.

Please open an issue before starting a large feature or a breaking CLI/schema change. Bug fixes, focused documentation corrections, new synthetic fixtures, and narrow parser improvements can usually go straight to a pull request.

Never include real incident telemetry, credentials, internal hostnames, or organization-specific identities in a contribution.

## Local setup

Python 3.12 or later is required. From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install build twine pytest pytest-cov ruff mypy types-PyYAML vulture bandit pip-audit detect-secrets pre-commit
```

On macOS/Linux, use `./.venv/bin/python` instead of the Windows interpreter path.

## Working on a change

1. Branch from the latest `main`.
2. Keep the change focused and preserve CLI/output contracts unless the change is intentionally breaking.
3. Add a unit, integration, or fixture test for behavior changes.
4. Update the relevant documentation when an option, environment variable, artifact, or limitation changes.
5. Run the checks below before opening the pull request.

Use synthetic fixtures with reserved domains and documentation/private address ranges. If a test needs noisy or large input, prefer a deterministic generator over a large committed capture.

## Checks

The quick local pass is:

```powershell
python -m ruff check src tests scripts
python -m mypy src
python -m pytest -q
python scripts/check_markdown_links.py
```

CI also enforces strict pipeline typing, dead-code and security checks, at least 80% coverage, golden snapshots, package validation, and the bounded 10k benchmark. To mirror the non-performance checks:

```powershell
python -m bandit -q -r src -lll
python -m pip_audit --local --skip-editable
python scripts/scan_tracked_secrets.py --repo-root . --include-untracked
python -m mypy --strict src/wazuh_sysmon_triage/pipeline
python -m vulture src tests --min-confidence 80
python -m pytest -q --cov=src/wazuh_sysmon_triage --cov-report=term-missing --cov-fail-under=80 --ignore=tests/test_golden_snapshots.py
python -m pytest -q tests/test_golden_snapshots.py
python -m build
python -m twine check dist/*
```

The performance command and thresholds are documented in [docs/PERFORMANCE.md](docs/PERFORMANCE.md). The convenience release gate is useful, but it does not run every CI security/build check and its live probe does not contact Wazuh.

## Pull request checklist

- [ ] New behavior is covered by a test.
- [ ] Existing tests still pass.
- [ ] CLI and artifact documentation reflects the new behavior.
- [ ] `docs/ENV_VARS.md` is updated if configuration changed.
- [ ] Credential, TLS, path, and evidence-handling impact was reviewed.
- [ ] Every new sample is synthetic and contains no real identity.
- [ ] Fetch, normalization, correlation, and rendering costs remain bounded.

`main` is protected, so changes land through a pull request after the required `quality-gate` check passes.

Short commit subjects such as `fix: ...`, `docs: ...`, `test: ...`, and `feat: ...` fit the existing history well.
