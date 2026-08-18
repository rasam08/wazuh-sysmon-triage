from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, TypedDict

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import (
    DnsQueryEvent,
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessAccessEvent,
    ProcessCreateEvent,
    RegistryEvent,
)

DEFAULT_ALLOWLIST_BASENAMES = {
    "msmpeng.exe",
    "mpcmdrun.exe",
    "nissrv.exe",
    "mpdefendercoreservice.exe",
    "svchost.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
}

LOLBIN_BASENAMES = {
    "rundll32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

WEB_FETCH_RE = re.compile(r"\b(invoke-webrequest|iwr|wget|curl)\b", flags=re.IGNORECASE)
DEV_TOOLING_RE = re.compile(
    r"powershelleditorservices|start-editorservices|\\\.vscode\\|microsoft vs code|vscode",
    flags=re.IGNORECASE,
)
ENCODED_COMMAND_FLAG_RE = re.compile(
    r"(?<![a-z0-9])-(?:enc|encodedcommand)(?![a-z])",
    flags=re.IGNORECASE,
)
ADVANCED_INJECTION_RE = re.compile(
    r"definedynamicassembly|definepinvokemethod|reflection\.emit|pidgenx\.dll|pkeyhelper\.dll",
    flags=re.IGNORECASE,
)
SCRIPT_EXTENSIONS = (".ps1", ".bat", ".cmd", ".vbs", ".js", ".exe", ".dll")
TEMP_MARKERS = ("\\temp\\", "\\appdata\\local\\temp\\")
USER_WRITABLE_MARKERS = (
    "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\downloads\\",
)
BURST_WINDOW_SECONDS = 120
BURST_MIN_PROCESSES = 6
BEACON_MIN_CONNECTIONS = 3
BEACON_MAX_JITTER_RATIO = 0.35
BEACON_MIN_AVG_SECONDS = 10
BEACON_MAX_AVG_SECONDS = 900
BURST_SUSPICIOUS_BASENAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "schtasks.exe",
    *LOLBIN_BASENAMES,
}

AlertCategory = Literal[
    "process_behavior",
    "network_behavior",
    "persistence_behavior",
    "credential_access_behavior",
    "remote_activity_behavior",
    "policy_pattern",
    "developer_tooling",
    "aggregate_behavior",
    "unknown",
]
ProcessKey = tuple[str, str]


class RuleMetadata(TypedDict):
    rule_id: str
    rule_name: str
    primary_event_id: int


RULE_METADATA: dict[str, RuleMetadata] = {
    "powershell_dev_tooling": {
        "rule_id": "BATCAVE-PS-DEV-001",
        "rule_name": "PowerShell Developer Tooling",
        "primary_event_id": 1,
    },
    "powershell_policy_bypass": {
        "rule_id": "BATCAVE-PS-POLICY-001",
        "rule_name": "PowerShell Policy Bypass Pattern",
        "primary_event_id": 1,
    },
    "powershell_encoded_or_download_pattern": {
        "rule_id": "BATCAVE-PS-001",
        "rule_name": "PowerShell Encoded or Download Pattern",
        "primary_event_id": 1,
    },
    "powershell_reflection_or_native_api_pattern": {
        "rule_id": "BATCAVE-PS-ADV-001",
        "rule_name": "PowerShell Reflection or Native API Pattern",
        "primary_event_id": 1,
    },
    "lolbin_outbound": {
        "rule_id": "BATCAVE-NET-001",
        "rule_name": "LOLBins Outbound",
        "primary_event_id": 3,
    },
    "user_writable_path_outbound": {
        "rule_id": "BATCAVE-NET-002",
        "rule_name": "User-writable Path Outbound",
        "primary_event_id": 3,
    },
    "scheduled_task_create": {
        "rule_id": "BATCAVE-PERSIST-001",
        "rule_name": "Scheduled Task Creation",
        "primary_event_id": 1,
    },
    "periodic_outbound_pattern": {
        "rule_id": "BATCAVE-NET-003",
        "rule_name": "Periodic Outbound Pattern",
        "primary_event_id": 3,
    },
    "process_launch_burst": {
        "rule_id": "BATCAVE-BEHAV-001",
        "rule_name": "Process Launch Burst",
        "primary_event_id": 1,
    },
    "registry_persistence_location_modified": {
        "rule_id": "BATCAVE-PERSIST-REG-001",
        "rule_name": "Registry Persistence Location Modified",
        "primary_event_id": 13,
    },
    "lsass_process_access": {
        "rule_id": "BATCAVE-CRED-001",
        "rule_name": "LSASS Process Access",
        "primary_event_id": 10,
    },
    "remote_logon_followed_by_service_install": {
        "rule_id": "BATCAVE-REMOTE-001",
        "rule_name": "Remote Logon Followed by Service Installation",
        "primary_event_id": 4697,
    },
    "remote_logon_followed_by_scheduled_task": {
        "rule_id": "BATCAVE-REMOTE-002",
        "rule_name": "Remote Logon Followed by Scheduled Task Creation",
        "primary_event_id": 4698,
    },
}


@dataclass
class DetectionRunResult:
    alerts: list[Alert]
    suppressed_alerts: int = 0
    suppressed_events: int = 0
    suppression_hits: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionContexts:
    process_creates: dict[ProcessKey, list[ProcessCreateEvent]]
    network_by_process: dict[ProcessKey, list[NetworkConnectEvent]]
    files_by_process: dict[ProcessKey, list[FileCreateEvent]]
    registry_by_process: dict[ProcessKey, list[RegistryEvent]]
    dns_by_process: dict[ProcessKey, list[DnsQueryEvent]]
    process_access_by_source: dict[ProcessKey, list[ProcessAccessEvent]]
    children_by_parent: dict[ProcessKey, list[ProcessCreateEvent]]
