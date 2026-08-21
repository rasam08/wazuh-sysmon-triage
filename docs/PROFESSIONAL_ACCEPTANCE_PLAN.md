# Acceptance status and remaining live qualification

This file used to be a forward-looking implementation plan. Workstreams 1 through 3 are now implemented, so it now records what has evidence behind it and what is still unfinished.

## Status for v2.1.0

| Workstream | Status | Evidence in the repository |
| --- | --- | --- |
| Per-record malformed-input isolation | Complete | `pipeline/ndjson.py`, input-quality artifacts, quarantine behavior, and NDJSON/e2e tests |
| Conclusion-oriented synthetic corpus | Complete | Nine `samples/acceptance/` scenarios, manifests, generator, and corpus tests |
| Bounded runtime and memory qualification | Complete locally and enforced at 10k in PR CI | Benchmark scripts, 10k CI gate, scheduled 50k/100k/million-source workflow, and [PERFORMANCE.md](PERFORMANCE.md) |
| Real Wazuh alerts-and-archives qualification | **Pending** | No declared real Wazuh/Sysmon qualification bundle exists yet |

The first three workstreams were completed and locally qualified on 2026-08-17. The fourth is intentionally on hold until a disposable lab and an explicitly authorized live trial are available.

That means the offline product boundary has strong automated evidence. It does not mean the project can honestly claim production-ready compatibility with every Wazuh version, index mapping, custom decoder, or Sysmon configuration.

## What is already closed

### 1. Bad input is isolated per record

Offline NDJSON is read as bounded binary records. Malformed JSON, invalid UTF-8, non-object JSON, and oversized records are rejected individually. Valid records before and after a rejection still reach the investigation.

The case records physical, blank, accepted, and rejected counts, stable rejection reasons, truncation state, and integrity. Raw rejected text is opt-in, preview-bounded, and passed through sanitization when requested. Strict mode writes reviewable artifacts before exiting with code `5`.

### 2. The fixture corpus tests conclusions and non-conclusions

The acceptance corpus includes:

1. benign administrative PowerShell;
2. benign software installation;
3. benign remote-maintenance activity;
4. PowerShell download/execution context;
5. LSASS process access with source context;
6. Run-key persistence evidence;
7. remote service and scheduled-task relationships;
8. degraded, duplicated, malformed, unsupported, missing-parent, invalid-time, and out-of-order telemetry; and
9. a deterministic noisy workstation with one injected chain.

Each manifest asserts required and forbidden findings, evidence kind/strength, source references, unknowns, relationship minima, input/drop counts, and provenance. The large noisy raw file is generated on demand rather than committed.

### 3. Bounded scale has measured limits

The normal pull-request gate processes 10,000 selected events under a 30-second/512-MiB ceiling. The scheduled workflow adds 50,000 and 100,000 selected-event profiles, rejects strongly nonlinear growth, and checks a one-million-line source while selecting only 10,000 records.

The latest recorded local results and their reference environment are in [PERFORMANCE.md](PERFORMANCE.md). Benchmark reports are workflow/local artifacts; they are not currently attached to the GitHub release.

## What the live trial still has to prove

The remaining work is not another mocked client test or `--dry-run-query`. It must use a declared Wazuh deployment and an enrolled Windows/Sysmon endpoint.

### Indexer contract

Against isolated test indices, verify:

- authenticated TLS and the expected failures for bad credentials/certificates;
- exact alert-document lookup;
- supported alert and archive field variants;
- PIT pagination and scroll fallback;
- explicit handling of missing indices, timeouts, and partial shards;
- duplicate, delayed, and out-of-order hits; and
- event/page caps with visible truncation.

Any write-side integration test must use a clearly isolated scratch prefix. It must never write into production-style `wazuh-alerts-*` or `wazuh-archives-*` patterns.

### Full endpoint path

Exercise and record this path:

```text
Windows event -> Wazuh agent -> Wazuh manager -> alert/archive index -> triage CLI
```

The trial should safely cover the event families the CLI claims to understand:

- process creation and termination;
- DNS and network activity;
- file creation and deletion;
- registry changes;
- process access;
- network/remote-interactive logon;
- service installation; and
- scheduled-task creation.

Use named, reversible lab-only actions. Do not run destructive attack simulation against a production endpoint.

### Qualification record

Retain a sanitized bundle with:

- exact Wazuh manager, Indexer, agent, and Sysmon versions;
- Sysmon configuration hash;
- tested alert/archive patterns and observed event IDs;
- CLI version and output schema;
- artifact digests;
- error-path results;
- offline replay comparison; and
- a dated pass/fail matrix.

Replaying the saved raw capture offline should produce the same stable investigative result after documented volatile fields are removed.

## Completion criteria

Live qualification is complete only when:

- exact alert lookup preserves the correct document, agent, and occurrence time;
- archive-backed context returns supported non-alerting evidence around that anchor;
- alert-only context clearly warns that telemetry may be incomplete;
- unsupported/rejected records and truncation remain visible;
- pagination does not lose or duplicate accepted hits in the test window;
- TLS, authentication, missing-index, and timeout behavior are explicit;
- a sanitized qualification record names the exact supported versions; and
- the documentation is updated to describe the tested boundary rather than generic Wazuh compatibility.

## Deliberate non-goals

- Processing an unbounded SIEM export as one in-memory investigation
- Automatically declaring remote administration malicious
- Reintroducing numeric risk scores or confidence percentages
- Bundling a permanent Wazuh deployment into this repository
- Claiming support for untested Wazuh versions or arbitrary custom decoders

Until the live criteria pass, the honest release statement remains: offline behavior is qualified; live Wazuh integration is experimental.
