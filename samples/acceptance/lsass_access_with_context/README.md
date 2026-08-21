# LSASS access with context

A recorded Sysmon process-access event targets LSASS while preserving the source process. The result is an evidence-backed lead, not proof of credential theft.

All identities and records are synthetic; there are no production credentials or organization-specific names in this scenario.

`raw_hits.ndjson` is a deterministic checked-in synthetic fixture. See `expected.yaml` for the machine-checked conclusions.
