from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, TypedDict

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessCreateEvent,
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
POLICY_BYPASS_RE = re.compile(r"-noprofile|-nop|-executionpolicy\s+bypass", flags=re.IGNORECASE)

MICROSOFT_IP_PREFIXES = ("13.", "20.", "40.", "52.", "104.", "131.107.", "150.171.")
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
    "malware_execution",
    "c2_outbound",
    "persistence",
    "policy_violation",
    "developer_tooling",
    "unknown",
]
AlertQueue = Literal["soc_malware", "soc_policy", "soc_dev", "soc_info"]
AlertConfidence = Literal["low", "medium", "high"]


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
    "powershell_obfuscation": {
        "rule_id": "BATCAVE-PS-001",
        "rule_name": "PowerShell Obfuscation / Download",
        "primary_event_id": 1,
    },
    "powershell_advanced_injection": {
        "rule_id": "BATCAVE-PS-ADV-001",
        "rule_name": "PowerShell Advanced Injection",
        "primary_event_id": 1,
    },
    "lolbin_outbound": {
        "rule_id": "BATCAVE-NET-001",
        "rule_name": "LOLBins Outbound",
        "primary_event_id": 3,
    },
    "suspicious_path_outbound": {
        "rule_id": "BATCAVE-NET-002",
        "rule_name": "Suspicious Path Outbound",
        "primary_event_id": 3,
    },
    "persistence_schtasks_create": {
        "rule_id": "BATCAVE-PERSIST-001",
        "rule_name": "Persistence via schtasks /Create",
        "primary_event_id": 1,
    },
    "beacon_like_outbound": {
        "rule_id": "BATCAVE-NET-003",
        "rule_name": "Beacon-like Outbound Pattern",
        "primary_event_id": 3,
    },
    "burst_suspicious_processes": {
        "rule_id": "BATCAVE-BEHAV-001",
        "rule_name": "Burst Suspicious Process Fan-out",
        "primary_event_id": 1,
    },
    "executive_hot_host": {
        "rule_id": "BATCAVE-META-001",
        "rule_name": "Executive Hot Host Risk Accumulation",
        "primary_event_id": 1,
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
    process_creates: dict[str, list[ProcessCreateEvent]]
    network_by_guid: dict[str, list[NetworkConnectEvent]]
    files_by_guid: dict[str, list[FileCreateEvent]]
    children_by_parent: dict[str, list[ProcessCreateEvent]]

