# Local behavior finding model

The local detector emits transparent rule matches. A match is an investigative lead,
not a verdict that activity is malicious.

## Output contract

Each finding records:

- `alert_type` and stable local rule metadata
- a neutral behavior `category`
- `finding_kind`: `observed_pattern`, `correlated_pattern`, `aggregate_pattern`, or `hypothesis`
- `evidence_strength`: `deterministic`, `strong`, or `circumstantial`
- the exact reason the rule matched
- `host_key`, process identity, event context, and source evidence references

There is no numeric risk score, severity percentage, confidence label, or automatic
SOC queue. Findings are sorted by time, host, type, process GUID, and image.

`evidence_strength` describes the support for the stated relationship or pattern. It
does not estimate the probability that an incident is malicious.

## Host isolation

All process, file, child, network, registry, DNS, and process-access contexts are
keyed by `(host_key, ProcessGuid)`. Identical GUID strings on two endpoints cannot
enrich one another.

## Rules

### PowerShell patterns

- `powershell_dev_tooling`: VS Code or PowerShellEditorServices tokens.
- `powershell_policy_bypass`: no-profile or execution-policy bypass flags when no
  encoded/download or reflection pattern also matched.
- `powershell_encoded_or_download_pattern`: encoded-command flags,
  Invoke-Expression, DownloadString, FromBase64String, or web-fetch command tokens.
- `powershell_reflection_or_native_api_pattern`: configured reflection, native API,
  or named-DLL tokens.

The direct command-line match is `observed_pattern` / `deterministic`. When the same
host/process GUID also has public network activity, a temporary file creation, or a
network-active LOLBin child, the finding becomes `correlated_pattern` / `strong` and
includes the related evidence references.

### Process and persistence patterns

- `scheduled_task_create`: `schtasks.exe` with `/Create`. The reason separately
  records interpreter/user-writable task actions and SYSTEM/highest flags.
- `process_launch_burst`: a bounded count of selected process launches on one host.
  It is an `aggregate_pattern`; its text explicitly says the count is not a
  maliciousness verdict.
- `registry_persistence_location_modified`: Sysmon recorded a change to a specific
  Run/RunOnce, Winlogon, AppInit DLL, IFEO Debugger, or service ImagePath/ServiceDll
  location. The exact target and value are retained.
- `lsass_process_access`: Sysmon EID 10 recorded a source process accessing
  `lsass.exe`. It is explicitly presented as an investigation lead, not proof of
  credential theft.

DNS queries are retained as process context and are not independently classified as
malicious. Registry and process-access relationships use their recorded ProcessGuid
fields; they do not fall back to filename or time proximity.

Process termination (EID 5) and file deletion (EID 23/26) are retained as lifecycle
evidence. They do not independently generate a behavior finding. Missing termination
or deletion events are reported as unknown coverage, not as proof that a process kept
running or that a file remained on disk.

### Remote activity patterns

- `remote_logon_followed_by_service_install`: a Windows Security 4624 network or
  remote-interactive logon preceded a 4697 service installation on the same target host.
- `remote_logon_followed_by_scheduled_task`: the same bounded relationship for a
  Windows Security 4698 scheduled-task creation.

The correlation window is 15 minutes. An exact `TargetLogonId`/`SubjectLogonId` match
is `strong`; an exact account-only match is `circumstantial`. Both are `hypothesis`
findings because legitimate administration produces the same telemetry. Source-host
attribution requires one exact collected-agent IP or host-name match. Ambiguous or
missing source identity remains unresolved. None of these labels asserts lateral
movement, remote execution success, or maliciousness.

### Network patterns

- `lolbin_outbound`: a configured LOLBin image made a network connection.
- `user_writable_path_outbound`: the connecting image path is under AppData or
  ProgramData.
- `periodic_outbound_pattern`: repeated public-destination connections meet the
  documented interval and jitter bounds. It is labeled `hypothesis` /
  `circumstantial` and explicitly states that periodic timing alone does not prove
  beaconing.

Public IP status and common ports are recorded as observations. Hard-coded vendor
IP-prefix attribution is not used.

## Suppression

Default image allowlists and explicit suppression rules can hide local findings.
Suppression counts and matched rule names remain in run artifacts. An
`allowlist_override` rule can keep selected activity visible. Role mappings add
context tags only; they do not silently adjust risk or confidence.
