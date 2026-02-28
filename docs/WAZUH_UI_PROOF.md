# Wazuh UI Proof (Phase 1.2)

## Goal

Approximate BATCAVE signal families in Wazuh Discover/Dashboards using a saved search:

- PowerShell suspicious execution
- LOLBins outbound
- `schtasks /Create` persistence

## Example KQL-like filter (adapt as needed)

```text
(
  data.win.system.eventID:(1 or "1") and
  data.win.eventdata.Image:("*\\powershell.exe" or "*\\pwsh.exe") and
  data.win.eventdata.CommandLine:("*-enc*" or "*-encodedcommand*" or "*IEX*" or "*Invoke-Expression*")
)
or
(
  data.win.system.eventID:(3 or "3") and
  data.win.eventdata.Image:("*\\mshta.exe" or "*\\rundll32.exe" or "*\\regsvr32.exe" or "*\\certutil.exe" or "*\\bitsadmin.exe")
)
or
(
  data.win.system.eventID:(1 or "1") and
  data.win.eventdata.Image:"*\\schtasks.exe" and
  data.win.eventdata.CommandLine:"*/Create*"
)
```

## Evidence image

- `docs/screenshots/wazuh_batcave_saved_search.png`

> If you have live lab access, replace the placeholder image with an actual screenshot from your Wazuh environment.
