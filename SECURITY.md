# Security Policy

## Supported versions

Security fixes are applied to the latest release and the `main` branch. Older releases may not
receive patches. Live Wazuh/Sysmon compatibility remains experimental until the qualification
described in `docs/PROFESSIONAL_ACCEPTANCE_PLAN.md` is complete.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository: open the **Security** tab,
choose **Advisories**, and select **Report a vulnerability**. Do not open a public issue with
exploit details, credentials, or real telemetry.

Include the affected version or commit, impact, reproduction steps, and any suggested mitigation.
Use synthetic data and remove secrets from logs or screenshots. If private reporting is not yet
enabled, contact the maintainer through the GitHub profile without including sensitive details.

## Sensitive evidence

Real Wazuh and Sysmon records may contain personal data, credentials in command lines, internal
hostnames, paths, and network addresses. Keep live captures and generated case directories out of
Git, apply least-privilege access, and sanitize artifacts before sharing them.
