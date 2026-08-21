# Publishing and releases

## Current public state

The repository is public at `rasam08/wazuh-sysmon-triage`. Release `v2.1.0` is the August 2026 maintenance release built on the evidence-first `v2.0.0` major rework, and the earlier Git history is preserved.

The release currently provides a wheel, source distribution, and `SHA256SUMS.txt` through GitHub Releases. Nothing is published to PyPI or a container registry.

GitHub private vulnerability reporting is enabled. `main` is protected with pull requests, strict `quality-gate` checks, conversation resolution, admin enforcement, and force-push/deletion protection. The exact rule is recorded in [BRANCH_PROTECTION.md](BRANCH_PROTECTION.md).

## Before a future release

Review the whole repository state, not only the last commit:

- confirm every tracked change is intentional;
- scan history and the current tree for secrets, private keys, internal URLs, real telemetry, and unwanted author addresses;
- keep `config.local.*`, `.env`, output folders, generated benchmarks, and local review notes ignored;
- confirm new fixtures are synthetic and use safe identities, domains, and address ranges; and
- update the version, changelog, output-schema notes, and documentation together.

Rewriting public history is disruptive. If sensitive history is found, stop the release and clean it deliberately rather than relying on a later deletion commit.

The maintainer identity for package metadata and normal local commits is `Rasam Moghaddam <rasammgg@gmail.com>`.

## Validation

From a clean Python 3.12 environment:

```powershell
python -m pip install --upgrade pip
python -m pip install .
python -m pip install build twine pytest pytest-cov ruff mypy types-PyYAML vulture bandit pip-audit detect-secrets
python -m bandit -q -r src -lll
python -m pip_audit --local --skip-editable
python scripts/scan_tracked_secrets.py --repo-root . --include-untracked
python -m ruff check src tests scripts
python -m mypy src
python -m mypy --strict src/wazuh_sysmon_triage/pipeline
python -m vulture src tests --min-confidence 80
python -m pytest -q
python scripts/check_markdown_links.py
python -m build
python -m twine check dist/*
```

The convenience gate is:

```powershell
.\scripts\release_gate.ps1
```

It runs contract tests, the Python suite, documentation links, and a dry-run live query. The last step performs no network call and is not a substitute for the pending Wazuh/Sysmon lab qualification.

Run the bounded performance commands in [PERFORMANCE.md](PERFORMANCE.md) before a performance-sensitive release.

## Tag and release flow

1. Merge the release pull request after `quality-gate` passes.
2. Confirm `pyproject.toml` and `wazuh_sysmon_triage.__version__` match the intended version.
3. Move completed changelog entries into the dated version section.
4. Create and push an annotated `vX.Y.Z` tag.
5. Let `.github/workflows/release.yml` test the tagged commit, build the wheel and source distribution, generate checksums, and create the GitHub release.
6. Download the published wheel into a clean environment and run `triage --version`, `triage --help`, and one bundled offline sample.

Build the Dockerfile from the final commit as a separate release check. A successful local Docker build does not publish an image.
