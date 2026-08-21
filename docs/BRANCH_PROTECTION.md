# Current branch protection

`main` is protected on GitHub. This file records the policy that is actually enabled, not a future recommendation.

## Enabled settings

- Changes must arrive through a pull request.
- The `quality-gate` status check is required and must be up to date with `main`.
- Review conversations must be resolved before merge.
- Administrators are included in the rule.
- Force pushes and branch deletion are disabled.
- Required approving reviews are set to `0`.

The zero-review setting is intentional for a solo-maintained repository: it preserves the pull-request and CI boundary without making every maintainer-authored change impossible to merge. If additional maintainers become active, this should be raised to at least one approval and stale approvals should be dismissed after new commits.

`quality-gate` is defined in `.github/workflows/ci.yml`. It runs security scans, documentation-link validation, linting, typing, tests and coverage, golden snapshots, package checks, and the bounded 10k performance benchmark.

Squash merging is preferred for focused documentation or dependency pull requests. A merge commit is still appropriate for a deliberately preserved major-rework branch, as used for v2.0.0.
