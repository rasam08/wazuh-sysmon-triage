# Bounded Performance Qualification

The product boundary is a bounded investigation, not unbounded in-memory SIEM export
processing. Runtime and memory gates therefore distinguish selected events from physical
source lines.

## Required gates

| Gate | Selected events | Source lines | Maximum wall time | Maximum peak RSS | Frequency |
| --- | ---: | ---: | ---: | ---: | --- |
| Pull request | 10,000 | 10,000 | 30 seconds | 512 MiB | Every CI run |
| Scaling profile | 50,000 | 50,000 | 90 seconds | 1,024 MiB | Scheduled/release |
| Release | 100,000 | 100,000 | 180 seconds | 1,536 MiB | Scheduled/release |
| Source safety | 10,000 | 1,000,000 | 30 seconds | 512 MiB | Scheduled/release |

The scheduled workflow also rejects wall-time or memory growth with an empirical exponent
of 1.5 or greater between 10k, 50k, and 100k. This is stricter than merely checking that
the 100k job eventually completes.

## What the harness measures

`scripts/benchmark_offline.py` writes a deterministic mixed-event source, runs the normal
CLI in a subprocess, and records:

- subprocess wall time and peak resident memory;
- fetch, normalize, correlate, detect, and render durations;
- selected, normalized, dropped, unsupported, node, edge, and finding counts;
- truncation and input-quality reports;
- every artifact size; and
- a stable digest over the timeline, process tree, finding table, and finding bundles.

Volatile run identifiers, durations, logs, metadata, and absolute input paths are excluded
from the stable digest. Repeated identical 10k and 100k runs must produce the same digest.

The one-million-line source contains realistic mixed records through the bounded lookahead
and a compact deterministic JSON-object tail after it. The reader must stop after exactly
`max_events + 1` accepted objects, report truncation, and never retain the uninspected tail.

## Commands

```powershell
python scripts/benchmark_offline.py --source-events 10000 --selected-events 10000 --repeat 2 --max-seconds 30 --max-rss-mib 512 --report benchmark-report-10k.json
python scripts/benchmark_offline.py --source-events 50000 --selected-events 50000 --repeat 1 --max-seconds 90 --max-rss-mib 1024 --report benchmark-report-50k.json
python scripts/benchmark_offline.py --source-events 100000 --selected-events 100000 --repeat 2 --max-seconds 180 --max-rss-mib 1536 --report benchmark-report-100k.json
python scripts/benchmark_offline.py --source-events 1000000 --selected-events 10000 --repeat 1 --max-seconds 30 --max-rss-mib 512 --report benchmark-report-million-source.json
python scripts/compare_benchmarks.py benchmark-report-10k.json benchmark-report-50k.json benchmark-report-100k.json --output benchmark-scaling-report.json
```

Set `RUN_PERFORMANCE=1` to run the pytest 10k wrapper. Set
`RUN_RELEASE_PERFORMANCE=1` to run the 100k and one-million-source wrappers. Ordinary unit
tests collect but skip these resource-intensive qualifications.

## Current local evidence

On 2026-08-17, Windows with Python 3.14.2 produced the following results. This local run is
supporting evidence; the declared reference automation remains GitHub's `ubuntu-latest`
runner with Python 3.12.

| Selected/source | Maximum wall time | Maximum peak RSS | Result |
| --- | ---: | ---: | --- |
| 10k / 10k, repeated twice | 3.000 s | 177.324 MiB | Pass |
| 50k / 50k | 12.799 s | 680.125 MiB | Pass |
| 100k / 100k, repeated twice | 25.295 s | 1,304.641 MiB | Pass |
| 10k / 1,000k | 3.101 s | 177.129 MiB | Pass |

The observed wall-time growth exponents were 0.901 and 0.983; memory-growth exponents
were 0.835 and 0.940. The injected PowerShell chain remained recoverable at every scale,
and repeated-run stable digests matched.

## Interpretation

The 100k memory result uses roughly 85% of the 1.5 GiB release ceiling. A regression in
process-tree materialization can therefore fail the release gate before runtime becomes
the visible bottleneck. Do not raise the threshold without a new documented reference
runner and a retained benchmark report.
