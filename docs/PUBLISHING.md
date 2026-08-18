# Publishing Checklist

Use this checklist before making the repository public or creating a release.

## Repository review

- Review `git status --short` and confirm every deletion and new file is intentional.
- Review the complete Git history, not only the current tree, for credentials, private keys,
  internal URLs, real telemetry, and unwanted author email addresses.
- Confirm bundled samples are synthetic and use reserved documentation domains or address ranges.
- Keep `config.local.*`, `.env`, output directories, benchmarks, and local review reports ignored.
- Enable GitHub private vulnerability reporting and branch protection for `main`.

Rewriting published Git history is disruptive. If sensitive history is found, stop and clean it
before publication rather than relying on a later deletion commit.

## Validation

Run from a clean checkout with Python 3.12:

```powershell
python -m pip install --upgrade pip
python -m pip install .
python -m pip install build twine pytest pytest-cov ruff mypy types-PyYAML
python -m ruff check src tests scripts
python -m mypy src
python -m pytest -q
python scripts/check_markdown_links.py
python scripts/scan_tracked_secrets.py --repo-root . --include-untracked
python -m build
python -m twine check dist/*
```

The local release gate runs contract tests, the complete Python suite, documentation links,
and a bounded live-query dry run that does not contact Wazuh:

```powershell
.\scripts\release_gate.ps1
```

The live Wazuh trial remains a separate, explicitly authorized qualification and is not part of
ordinary pull-request CI.

## Release preparation

- Move completed entries from `Unreleased` in `CHANGELOG.md` into a versioned section.
- Keep `pyproject.toml` and `wazuh_sysmon_triage.__version__` synchronized.
- Create a signed or annotated `vX.Y.Z` tag only after CI passes.
- Verify the GitHub release contains both wheel and source distribution plus `SHA256SUMS.txt`.
- Install the wheel into a fresh environment and run `triage --help` plus one offline sample.

This repository's release workflow creates GitHub release assets. It does not publish to PyPI.
