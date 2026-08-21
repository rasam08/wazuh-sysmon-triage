# Runbook: output storage is full

Use this when a run cannot write artifacts or the output volume is close to capacity.

## First checks

1. Pause new high-volume runs.
2. Check free space on the volume holding `--out-dir` and temporary files.
3. Identify large old case directories, raw captures, benchmark reports, and build artifacts.
4. Check whether `artifact_retention` is enabled and appropriate for this evidence policy.

## Recovery

Archive or remove old evidence only under the applicable retention policy. Avoid deleting an active or unreviewed case just to make a command succeed.

After freeing space, run a small bundled offline sample and confirm the timeline, JSON, Markdown, log, and root telemetry files can all be created. Resume larger work gradually while watching for write failures.

For a recurring problem, set reviewed age/size limits, move long-term evidence to managed storage, and alert before the volume is exhausted.
