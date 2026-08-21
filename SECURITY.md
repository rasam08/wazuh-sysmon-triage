# Security policy

## Supported versions

Security fixes are made on the latest release and `main`. Older releases may not receive a backport.

The offline pipeline is the qualified part of v2. Live Wazuh/Sysmon compatibility remains experimental until the real-lab work in [docs/PROFESSIONAL_ACCEPTANCE_PLAN.md](docs/PROFESSIONAL_ACCEPTANCE_PLAN.md) is complete.

## Report a vulnerability privately

Private vulnerability reporting is enabled for this repository. Open the repository's **Security** tab, choose **Advisories**, and select **Report a vulnerability**.

If GitHub's private reporting form is unavailable, email `rasammgg@gmail.com`. Do not put exploit details, credentials, private telemetry, or unredacted screenshots in a public issue.

A useful report includes the affected version or commit, the impact, clear reproduction steps, and any mitigation you have already found. Use synthetic data wherever possible and remove secrets from logs.

## Handle evidence as sensitive data

Wazuh and Sysmon records can contain usernames, command lines, file paths, internal hostnames, IP addresses, and secrets accidentally passed on a command line. Keep live captures and generated case directories out of Git, restrict access to them, and review sanitized output before sharing it.

`--sanitize` reduces common identity and network exposure in generated artifacts. It is a sharing aid, not a guarantee that a case is safe to publish.
