# BATCAVE Alerts Signal Model (Current Implementation)

This document matches the detection logic implemented in:

- `src/wazuh_sysmon_triage/pipeline/detect.py`

It describes what the local detector does today, including scoring, routing, suppressions, and alert ordering.

## Output and ordering

- Input: normalized Sysmon events (`ProcessCreate`, `NetworkConnect`, `FileCreate`).
- Output: `DetectionRunResult` with:
  - `alerts`
  - `suppressed_alerts`
  - `suppressed_events`
  - `suppression_hits`
- Final alert sort order is deterministic:
  1. `score` descending
  2. `utc_time` ascending
  3. `alert_type`
  4. `process_guid`
  5. `image`

## Rule families and scoring

### 1) PowerShell developer tooling

- Rule: `powershell_dev_tooling` (`BATCAVE-PS-DEV-001`)
- Trigger:
  - image basename is `powershell.exe` or `pwsh.exe`
  - command/image matches VS Code or PowerShellEditorServices pattern
- Score: `10`
- Route: `category=developer_tooling`, `queue=soc_dev`, `confidence=low`

### 2) PowerShell policy bypass pattern

- Rule: `powershell_policy_bypass` (`BATCAVE-PS-POLICY-001`)
- Trigger:
  - PowerShell process
  - policy bypass indicators present:
    - `-noprofile` or `-nop`
    - `-executionpolicy bypass`
  - no obfuscation hits
  - no advanced injection hit
- Score: `30`
- Route: `category=policy_violation`, `queue=soc_policy`, `confidence=medium`

### 3) PowerShell obfuscation / download

- Rule: `powershell_obfuscation` (`BATCAVE-PS-001`)
- Trigger: PowerShell process with one or more:
  - encoded command flag (`-enc` or `-encodedcommand`)
  - `Invoke-Expression` / `iex`
  - `DownloadString`
  - `FromBase64String`
  - web-fetch primitive (`invoke-webrequest`, `iwr`, `wget`, `curl`)
- Score:
  - base `70`
  - `+15` when hit count >= 2
  - `+10` when hit count >= 3
  - clamped to `0..100`
- Base route: `category=malware_execution`, `queue=soc_malware`, `confidence=high`

### 4) PowerShell advanced injection

- Rule: `powershell_advanced_injection` (`BATCAVE-PS-ADV-001`)
- Trigger: PowerShell command contains advanced reflection/injection indicators:
  - `definedynamicassembly`, `definepinvokemethod`, `reflection.emit`, `pidgenx.dll`, `pkeyhelper.dll`
- Base score: `55`
- Base route: `category=policy_violation`, `queue=soc_policy`, `confidence=medium`
- Escalates to malware route when any is true:
  - has public non-Microsoft outbound traffic
  - wrote script/executable/dll artifact to temp path
  - spawned LOLBin child that has network activity
- Escalated state:
  - `category=malware_execution`, `queue=soc_malware`, `confidence=high`
  - `score=max(score, 80)`
  - tag `escalator:advanced_combo`

### 5) Persistence via schtasks /Create

- Rule: `persistence_schtasks_create` (`BATCAVE-PERSIST-001`)
- Trigger:
  - image basename is `schtasks.exe`
  - command contains `/create`
- Score:
  - base `70`
  - `+15` random-ish token in task command
  - `+15` suspicious action (`powershell`, `cmd /c`, `\temp\`, `\appdata\`)
  - `+10` high-privilege flags (`/ru system` or `/rl highest`)
  - clamped to `0..100`
- Route: `category=persistence`, `queue=soc_malware`, `confidence=high`

### 6) LOLBin outbound

- Rule: `lolbin_outbound` (`BATCAVE-NET-001`)
- Trigger: `NetworkConnect` where image basename is one of:
  - `rundll32.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`
- Score:
  - base `60`
  - `+20` public destination IP
  - `+10` destination port `80` or `443`
  - clamped to `0..100`
- Route: `category=c2_outbound`, `queue=soc_malware`, confidence:
  - `high` if public IP
  - `medium` otherwise

### 7) Suspicious-path outbound

- Rule: `suspicious_path_outbound` (`BATCAVE-NET-002`)
- Trigger: `NetworkConnect` where image path contains:
  - `\appdata\roaming\`
  - `\appdata\local\temp\`
  - `\programdata\`
- Score:
  - base `50`
  - `+20` public destination IP
  - `+10` destination port `80` or `443`
  - clamped to `0..100`
- Route: `category=policy_violation`, `queue=soc_policy`, `confidence=medium`

### 8) Beacon-like outbound pattern (aggregate rule)

- Rule: `beacon_like_outbound` (`BATCAVE-NET-003`)
- Evaluated after per-event rules, using network context grouped by:
  - `(process_guid, destination_ip, destination_port)`
- Preconditions:
  - destination is public
  - destination is not in Microsoft prefix list
  - image not in default allowlist basenames
  - at least `3` connections
  - average interval between `10` and `900` seconds
  - jitter ratio <= `0.35`
- Score:
  - base `65 + 15`
  - `+10` if connections >= 5
  - `+5` if jitter <= 0.15
  - clamped to `0..100`
- Route: `category=c2_outbound`, `queue=soc_malware`, confidence:
  - `high` if connections >= 4
  - `medium` otherwise

### 9) Burst suspicious process fan-out (aggregate rule)

- Rule: `burst_suspicious_processes` (`BATCAVE-BEHAV-001`)
- Evaluated per host over sliding windows of `120s`.
- Candidate processes:
  - suspicious basenames (`powershell.exe`, `pwsh.exe`, `cmd.exe`, `schtasks.exe`, LOLBins), or
  - processes launched from user-writable markers:
    - `\appdata\roaming\`, `\appdata\local\temp\`, `\programdata\`, `\users\public\`, `\downloads\`
- Burst condition in window:
  - unique process GUIDs >= 6, or
  - unique process GUIDs >= 4 and >= 3 have outbound traffic
- Score:
  - `55 + (process_count * 5) + (min(network_backed, 5) * 4)`
  - clamped to `0..100`
- Route:
  - `category=malware_execution`
  - `queue=soc_malware`
  - confidence `high` when process_count >= 8 or network_backed >= 4, else `medium`

### 10) Executive hot-host risk accumulation (meta alert)

- Rule: `executive_hot_host` (`BATCAVE-META-001`)
- Evaluated after all other alerts.
- Grouping: by host label derived from process/network context.
- Preconditions per host:
  - at least 3 alerts
  - and either:
    - total score >= 180, or
    - at least 2 alerts with score >= 85
  - and either:
    - at least 2 unique alert types, or
    - at least 2 high-severity alerts
- Score:
  - `70 + (high_count * 10) + min(unique_types * 3, 15)`
  - clamped to `0..100`
- Route: `category=malware_execution`, `queue=soc_malware`, `confidence=high`

## Routing/escalation details

- Base routing is assigned per rule.
- PowerShell-specific escalators can override category/queue/confidence and raise score:
  - advanced injection combo: score floor `80`
  - obfuscation + risky outbound combo: score floor `90`, tag `escalator:critical_combo`
- Role-based dampening:
  - if tag `role:developer` and category `developer_tooling`: score capped at `15`, route stays `soc_dev`
  - if tag `role:developer` and category `policy_violation` without escalator tags: score reduced by `5`

## Tags and enrichment

- PowerShell alerts include base tags: `batcave`, `powershell`, `execution`, plus role tags.
- Destination tags are added when network context exists:
  - `dest:public`
  - `dest:microsoft_asn` (Microsoft prefix hit)
- Some alerts include escalation tags:
  - `escalator:advanced_combo`
  - `escalator:critical_combo`
- Network alerts enrich `command_line` and `parent_image` from matching process-create context when available.

## Suppressions and allowlists

### Default allowlist basenames

Default allowlist basenames are:

- `msmpeng.exe`
- `mpcmdrun.exe`
- `nissrv.exe`
- `mpdefendercoreservice.exe`
- `svchost.exe`
- `chrome.exe`
- `msedge.exe`
- `firefox.exe`

### Effective allowlist

- `allowlist_basenames` passed to `run_detection` are normalized and unioned with the defaults.
- If an event image basename is allowlisted:
  - event-level alerts from that event are dropped
  - suppression counters are incremented

### Suppression rule matching

Suppression rules can match on:

- `image_glob` (case-insensitive glob)
- `image_regex` (case-insensitive regex)
- `user` (exact case-insensitive match)
- `destination_ports` (exact integer membership)
- `destination_class` (`private` or `public`)

`enabled: false` rules are ignored.

### Precedence

For each event:

1. hard allowlist suppression by image basename
2. build candidate alerts for that event
3. check `allowlist_override_rules`
4. check suppression `rules`

`allowlist_override_rules` bypass suppression-rule drops, but do not bypass hard allowlist suppression.

## Dedup semantics

- PowerShell alert candidates are deduplicated by:
  - `alert_type`
  - `process_guid`
  - minute bucket (`utc_time` truncated to minute)
  - `destination_ip`
  - `destination_port`
- Highest-scored alert wins for duplicate keys.

## Notes for local use

- This model is intentionally local and deterministic.
- It does not require cloud services or external queues.
- Use this document as the source of truth for current in-repo detection behavior.
