# Runbook: Disk Space Exhaustion

## Detection
- Write failures in run execution/logging
- Repeated 5xx responses with filesystem error context
- OS alerts for low disk space on output volume

## Immediate Actions
1. Check free space on volume containing output and temp directories.
2. Identify large stale case directories and build artifacts.
3. Pause high-volume run submissions.

## Recovery
1. Free space safely (archive/delete old case outputs per retention policy).
2. Validate server can create/update artifacts.
3. Resume submissions gradually and monitor error rate.

## Post-Incident
- Define retention limits and cleanup automation.
- Add capacity alerts based on disk usage thresholds.
