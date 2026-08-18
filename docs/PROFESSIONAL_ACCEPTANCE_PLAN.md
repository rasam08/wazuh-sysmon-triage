# Professional Acceptance Closure Plan

## Status

Workstreams 1 through 3 were implemented and locally qualified on 2026-08-17. Workstream
4 is intentionally on hold pending an explicitly authorized disposable Wazuh/Sysmon lab.
Professional acceptance remains incomplete until that live qualification passes.

The objective is to close the remaining professional-acceptance gaps without turning
the project into a bulk SIEM, a generic detection platform, or another dashboard.

## Definition of success

Professional acceptance requires all four workstreams below to pass. Passing the normal
unit-test suite alone is not sufficient.

1. One malformed input record cannot destroy an otherwise usable investigation.
2. The fixture corpus represents benign administration, realistic incident chains,
   degraded telemetry, and noisy endpoints.
3. The bounded triage workflow has measured runtime and memory behavior at 10k and 100k
   selected events, and safely limits a one-million-record source.
4. Alert lookup and archive-backed context collection work against a real supported Wazuh
   deployment, not only mocks or a dry-run query.

## Implementation order

The workstreams must be implemented in this order:

1. Input isolation and quarantine
2. Acceptance fixture corpus
3. Performance and memory qualification
4. Live Wazuh qualification

Input behavior must be stable before building corpus expectations. The corpus generator
must be stable before measuring performance. Live qualification comes last so failures
can be attributed to the integration rather than unresolved local-pipeline behavior.

---

## Workstream 1: Per-record malformed-input isolation

### Objective

Continue processing valid NDJSON records when individual lines are malformed, invalid
UTF-8, oversized, or valid JSON with a non-object top level. Make every rejected record
visible and reviewable.

### Current limitation

`cli_helpers_runtime.py::_run_fetch_stage()` calls `json.loads()` inside the main file
loop. A decoding error exits the whole fetch stage. Normalization quarantine begins only
after JSON parsing, so it cannot preserve syntactically malformed input.

### Design decisions

- Read NDJSON as binary, one record at a time, so invalid UTF-8 is isolated to one line.
- Count `--max-events` against accepted JSON objects, not physical lines or rejected
  records.
- Read no more than one accepted record beyond the limit so truncation is confirmed
  rather than assumed.
- Continue by default and mark collection integrity as `degraded` when any record is
  rejected.
- Add `--fail-on-input-errors` for strict automation. Strict mode still writes the input
  report, quarantine file when requested, and normal case artifacts before returning a
  documented non-zero exit code.
- Preserve rejected raw text only when `--quarantine-drops` is enabled. Always record a
  SHA-256 digest, line number, reason, and safe parser summary.
- Apply the existing output sanitizer to quarantined raw content when sanitization is
  enabled.
- Enforce a configurable maximum record size to prevent a single line from consuming
  unbounded memory.

### Proposed types and artifacts

Add an input reader report containing:

- `total_lines`
- `blank_lines`
- `accepted_records`
- `rejected_records`
- `rejected_by_reason`
- `truncated`
- `truncation_reason`

Rejection reasons must be stable values:

- `invalid_utf8`
- `malformed_json`
- `non_object_json`
- `record_too_large`

Each `quarantine.ndjson` input-stage entry must contain:

- `stage: input`
- `reason`
- `line_number`
- `byte_offset`
- `raw_sha256`
- `error` with no traceback
- `raw_line` only when quarantine was explicitly requested

Expose the report as `input_quality` in `stats.json` and `run_metadata.json`. This is an
additive output-contract change and should bump the schema from 2.3 to 2.4.

### Expected file changes

- New `src/wazuh_sysmon_triage/pipeline/ndjson.py`
- `src/wazuh_sysmon_triage/cli_helpers_runtime.py`
- `src/wazuh_sysmon_triage/cli_helpers_runtime_types.py`
- `src/wazuh_sysmon_triage/cli_helpers_runtime_output.py`
- `src/wazuh_sysmon_triage/cli_helpers_runtime_stages.py`
- `src/wazuh_sysmon_triage/cli.py`
- `src/wazuh_sysmon_triage/output_schema.py`
- `tests/test_ndjson.py`
- `tests/test_cli.py`
- `tests/test_e2e_offline.py`
- Output-contract documentation

### Acceptance tests

- A file with valid, malformed, valid records produces evidence from both valid records.
- Invalid UTF-8, arrays, scalars, and oversized records are independently rejected.
- Rejection counts and line numbers are exact.
- Raw rejected content is absent unless quarantine is requested.
- Sanitized quarantine does not leak private IP addresses, users, or paths.
- Strict mode produces reviewable artifacts and a documented non-zero exit status.
- Repeated runs produce identical input-quality counts and quarantine ordering.
- A malformed line does not count toward `--max-events`.

---

## Workstream 2: Realistic professional fixture corpus

### Objective

Replace confidence based on tiny happy-path samples with an auditable corpus that tests
analyst conclusions, non-conclusions, missing evidence, false positives, and noise
reduction.

### Corpus structure

Create `samples/acceptance/`. Each checked-in scenario contains:

- `raw_hits.ndjson`
- `expected.yaml`
- `README.md`

`expected.yaml` describes facts rather than implementation snapshots:

- required findings and forbidden findings
- expected evidence strength and finding kind
- required process edges and unresolved relationships
- required source evidence references
- expected unknowns and drop counts
- minimum input, selected, and omitted event counts
- provenance label: `synthetic` or `sanitized_capture`

Large noisy inputs are generated deterministically and are not committed as giant files.
The generator must use a fixed seed and publish a manifest containing the seed, event
mix, injected chain, and expected conclusions.

### Minimum scenarios

1. `benign_admin_powershell`
   - Interactive administrative PowerShell with ordinary network and file activity.
   - Must not become a malicious verdict.
2. `benign_software_installation`
   - Installer, service creation, scheduled maintenance, and expected child processes.
3. `benign_rmm_remote_maintenance`
   - Remote logon followed by a service or scheduled task.
   - May remain a remote-activity lead but must never claim malicious lateral movement.
4. `powershell_download_execute`
   - Office or script parent, encoded/download behavior, file creation, child execution,
     DNS, and network evidence.
5. `lsass_access_with_context`
   - Accessing process, target process, ancestry, user, and surrounding activity.
6. `registry_runkey_persistence`
   - Exact registry location and originating process.
7. `remote_service_and_task`
   - Multi-host, out-of-order 4624/4697/4698 evidence with strong and circumstantial
     variants.
8. `degraded_telemetry`
   - Missing parent, duplicate records, PID reuse, unsupported IDs, invalid timestamps,
     malformed JSON, and out-of-order events.
9. `noisy_workstation`
   - Thousands of browser, Defender, Office, developer-tool, update, and background
     events surrounding one injected chain.

### Expected file changes

- New `samples/acceptance/` scenarios and manifests
- New `scripts/generate_acceptance_corpus.py`
- New `tests/test_acceptance_corpus.py`
- `docs/SCENARIO_GYM.md`
- `docs/REPRODUCE.md`
- `README.md`

### Acceptance tests

- Every manifest is schema-validated before its scenario runs.
- Every emitted finding has at least one source reference.
- Forbidden findings are asserted, not merely omitted from documentation.
- Duplicate and out-of-order inputs yield the same conclusions and stable ordering.
- Benign scenarios prove non-escalation behavior.
- The noisy scenario reports exactly how many events were selected, omitted, unsupported,
  and dropped.
- Sanitized captures contain no credentials, internal host identities, private user names,
  or organization-specific values.

---

## Workstream 3: Scale, runtime, and memory qualification

### Objective

Prove that bounded investigations remain predictable as event volume grows. This is not
an objective to process an unbounded SIEM export entirely in memory.

### Current limitation

`tests/test_perf_smoke.py` creates 200 records and processes 25. It verifies truncation
determinism but does not establish useful 10k or 100k behavior. Correlation also currently
materializes its input with `list(events)`, so peak memory must be measured explicitly.

### Qualification levels

#### Pull-request gate

- 10,000 selected mixed events
- Complete normalize/correlate/detect/render pipeline
- Maximum 30 seconds on the standard GitHub Linux runner
- Maximum 512 MiB peak resident memory
- Stable artifact digest after removing documented volatile fields such as run ID and
  duration

#### Scheduled or release gate

- 100,000 selected mixed events
- Maximum 180 seconds on the documented reference runner
- Maximum 1.5 GiB peak resident memory
- No quadratic growth when comparing 10k, 50k, and 100k profiles
- Finding, edge, unresolved-relationship, and omission counts match the manifest

#### Million-record safety gate

- Stream a deterministic one-million-line source with the normal bounded event limit.
- Retain no more than `max_events + 1` accepted raw records.
- Mark truncation explicitly and deterministically.
- Do not exhaust memory or create an unbounded quarantine collection.
- Full analysis of one million selected events is outside the product boundary unless a
  future architecture is specifically designed and qualified for it.

### Implementation approach

1. Add a deterministic mixed-event generator shared by corpus and benchmarks.
2. Add a subprocess benchmark harness that records wall time, exit code, peak resident
   memory, artifact sizes, and stable result digests.
3. Profile before optimizing. Record the slowest stages in `run_metadata.json`.
4. Replace repeated full scans or quadratic joins only where the profiles demonstrate a
   problem.
5. Keep 100k and one-million-source tests out of ordinary unit-test runs; run them in a
   scheduled/release workflow with retained benchmark artifacts.

### Expected file changes

- New `scripts/benchmark_offline.py`
- Replacement or expansion of `tests/test_perf_smoke.py`
- New `tests/performance/test_offline_scale.py`
- `.github/workflows/ci.yml` for the bounded 10k gate
- New `.github/workflows/performance.yml` for scheduled/release qualification
- Possible indexed-correlation changes based on profiling evidence
- `docs/PERFORMANCE.md`

### Acceptance tests

- Thresholds above pass on the documented runner.
- Benchmark failures show stage timing, peak memory, artifact size, and event mix.
- Two identical runs have identical stable artifact digests.
- Truncation is a visible integrity condition, never a silent success.
- The generated suspicious chain remains recoverable at every tested scale.

---

## Workstream 4: Real Wazuh alerts-and-archives qualification

### Objective

Prove that exact alert lookup and bounded archive context work against a real, declared
Wazuh version and an enrolled Windows/Sysmon endpoint.

### Environment boundary

Use a dedicated disposable lab, never a production Wazuh deployment. The official Wazuh
single-node Docker deployment is suitable for the central components but requires
substantial resources. A separate Windows endpoint or VM is required for authentic
Windows Security and Sysmon telemetry.

The Wazuh indexer API default is port 9200. Port 9920 is valid only when a lab explicitly
remaps it. Documentation and examples must state that distinction.

Wazuh archives must be explicitly enabled because alert indices do not contain every
received event. The lab runbook must include the storage warning and cleanup procedure.

### Two integration layers

#### A. Indexer contract integration

Run against a disposable Wazuh indexer using dedicated scratch indices. Validate:

- authenticated TLS connection
- correct error for wrong credentials
- exact document lookup
- alerts and archives field variants
- PIT pagination when available
- scroll fallback when PIT is unavailable
- partial-shard and timeout rejection
- duplicate, delayed, and out-of-order hits
- event-cap and page-cap truncation

Scratch indices must use a clearly isolated prefix and explicit opt-in credentials. Tests
must never write to `wazuh-alerts-*` or `wazuh-archives-*` production patterns.

#### B. Full Wazuh/Sysmon path

Run a safe lab workflow through:

`Windows event -> Wazuh agent -> Wazuh manager -> alerts/archives -> Wazuh indexer -> triage CLI`

Generate and clean up named lab-only activity for:

- process creation
- DNS and network connection
- file creation and deletion
- registry modification
- process termination
- remote/network logon where the lab permits it
- scheduled task and service creation where administrative lab access permits it

Capture a sanitized qualification bundle containing:

- Wazuh version
- Sysmon version and configuration hash
- tested index patterns
- CLI version and output schema
- event IDs observed in alerts and archives
- case artifact digests
- pass/fail matrix

Never capture credentials or private keys.

### Proposed test and runbook layout

- New `tests/integration/test_wazuh_indexer.py`
- New `tests/integration/test_wazuh_live_pipeline.py`
- New `scripts/validate_wazuh_lab.ps1`
- New `docs/WAZUH_INTEGRATION_QUALIFICATION.md`
- Pytest marker `integration`
- Explicit environment switch such as `RUN_WAZUH_INTEGRATION=1`
- Manual or self-hosted scheduled workflow; not an implicit public pull-request job

### Supported-version policy

The first qualification declares one exact current Wazuh release and one Sysmon
configuration. Additional versions are unsupported until they pass the same contract.
The repository must not claim generic compatibility with every Wazuh or custom decoder
deployment.

### Acceptance tests

- `triage alert <id>` preserves the exact real alert and correct agent/time anchor.
- Archive-backed collection returns supported non-alerting context around that anchor.
- Alert-only collection explicitly warns that telemetry may be incomplete.
- Normalization reports every unsupported or rejected record.
- PIT or fallback pagination produces no missing or duplicated accepted hits in the test
  window.
- TLS, authentication, missing-index, timeout, and truncation failures are explicit.
- Replaying the saved raw capture offline produces the same stable investigative result.

Authoritative references:

- Wazuh Docker deployment: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
- Wazuh indexer API: https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html
- Wazuh alert and archive indices: https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html

---

## Release-gate structure after implementation

### Required on every pull request

- Existing unit, type, lint, security, and schema tests
- Malformed-input isolation suite
- Acceptance corpus except large noisy variants
- Deterministic 10k performance gate

### Required on schedule and before release

- Full acceptance corpus
- 100k performance and memory gate
- One-million-record bounded-input safety gate
- Indexer contract integration against the declared Wazuh version

### Required for professional acceptance sign-off

- A dated successful full Wazuh/Sysmon lab qualification bundle
- No unresolved failures in any of the four workstreams
- Documentation states the exact qualified versions and unsupported boundaries
- A reviewer can reproduce the offline bundle without external enrichment

## Explicit non-goals

- Processing an unbounded SIEM export as a single in-memory investigation
- Automatically deciding that remote administration is malicious
- Adding more numerical scores, confidence percentages, or generic detections
- Running destructive attack simulation against a production endpoint
- Bundling a permanent Wazuh deployment into this CLI repository
- Claiming compatibility with untested Wazuh versions or arbitrary custom decoders

## Completion checklist

- [x] Workstream 1 passes all malformed-input acceptance tests.
- [x] Workstream 2 corpus and manifests pass all analyst-conclusion tests.
- [x] Workstream 3 passes 10k, 100k, and one-million-source safety gates.
- [ ] Workstream 4 passes indexer-contract and full Wazuh/Sysmon lab qualification.
- [x] Output schema and compatibility documentation are updated.
- [ ] Release artifacts contain the performance report and live qualification bundle.
- [ ] Professional acceptance is re-evaluated from evidence rather than feature count.
