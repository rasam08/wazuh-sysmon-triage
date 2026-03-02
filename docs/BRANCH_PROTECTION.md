# Branch Protection Guidance

Target branch: `main`

## Required GitHub Settings

1. Require pull request before merging.
2. Require at least 1 approving review.
3. Dismiss stale pull request approvals when new commits are pushed.
4. Require conversation resolution before merge.
5. Require status checks to pass before merging.
6. Do not allow force pushes.
7. Do not allow deletions.

## Required Status Checks

Configure this workflow check as required:

- `quality-gate`

This maps to `.github/workflows/ci.yml` and enforces security scans, lint, type-checks, tests, e2e smoke, and build.

## Recommended Admin Policy

1. Include administrators in branch protection.
2. Restrict who can push directly to `main`.
3. Use squash merges for linear, auditable history.
