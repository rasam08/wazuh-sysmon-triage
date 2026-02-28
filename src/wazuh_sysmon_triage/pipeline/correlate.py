from __future__ import annotations

import ipaddress
import os
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from importlib import resources
from typing import Any

import yaml

from wazuh_sysmon_triage.models.findings import Artifact, IncidentSummary, ProcessEdge, ProcessNode
from wazuh_sysmon_triage.models.sysmon import (
    FileCreateEvent,
    NetworkConnectEvent,
    ProcessCreateEvent,
    SysmonEvent,
)

SCRIPT_INTERPRETERS = {
    "powershell.exe",
    "pwsh.exe",
    "cscript.exe",
    "wscript.exe",
    "python.exe",
}

SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".bat", ".cmd", ".exe", ".dll"}

SUSPICIOUS_PATH_MARKERS = [
    "\\programdata\\",
    "\\users\\public\\",
    "\\appdata\\",
    "\\temp\\",
]

COMMON_PORTS = {80, 443, 53, 123, 445, 3389, 22, 25}

LOW_SIGNAL_DEFENDER_BASENAMES = {
    "msmpeng.exe",
    "mpcmdrun.exe",
    "nissrv.exe",
    "mpdefendercoreservice.exe",
}

GUID_EDGE_REASON = "SysmonEID1 parentProcessGuid -> processGuid"
HEURISTIC_EDGE_REASON = "Heuristic: pid/time proximity (no parentProcessGuid)"


def _load_sigma_rules() -> list[dict[str, Any]]:
    with (
        resources.files("wazuh_sysmon_triage.data")
        .joinpath("sigma_rules.yaml")
        .open("r", encoding="utf-8") as handle
    ):
        data = yaml.safe_load(handle) or {}
    rules = []
    for name, rule in data.items():
        rule["name"] = name
        rules.append(rule)
    return rules


def _match_sigma(rule: dict[str, Any], image: str | None, command_line: str | None) -> bool:
    match = rule.get("match", {})
    if "image" in match:
        if _basename(image) != str(match["image"]).lower():
            return False
    if "commandline_contains" in match:
        if (
            not command_line
            or str(match["commandline_contains"]).lower() not in command_line.lower()
        ):
            return False
    return True


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False


def _basename(path: str | None) -> str:
    if not path:
        return ""
    return os.path.basename(path).lower()


def _norm_path(path: str | None) -> str:
    if not path:
        return ""
    return path.lower()


def _is_defender_low_signal(image: str | None, destination_port: int) -> bool:
    return _basename(image) in LOW_SIGNAL_DEFENDER_BASENAMES and destination_port == 443


def _is_interpreter(image: str | None, command_line: str | None) -> bool:
    image_base = _basename(image)
    if image_base in SCRIPT_INTERPRETERS:
        return True
    if command_line:
        cmd = command_line.lower()
        if "-enc" in cmd or "iex" in cmd or ".ps1" in cmd:
            return True
    return False


def _is_script_write(target: str | None) -> bool:
    if not target:
        return False
    target_lower = target.lower()
    ext = os.path.splitext(target_lower)[1]
    if ext not in SCRIPT_EXTENSIONS:
        return False
    return any(marker in target_lower for marker in SUSPICIOUS_PATH_MARKERS)


def correlate_data(
    events: Iterable[SysmonEvent],
    *,
    destination_scoring_mode: str = "balanced",
) -> dict[str, Any]:
    """
    Build process graph, artifacts, and an incident summary from Sysmon events.
    """
    event_list = list(events)
    nodes_by_guid: dict[str, ProcessNode] = {}
    edges: list[ProcessEdge] = []
    artifacts: list[Artifact] = []
    network_activity: list[dict[str, Any]] = []
    out_degree: defaultdict[str, int] = defaultdict(int)
    artifact_links: defaultdict[str, int] = defaultdict(int)
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    narrative: list[str] = []
    sigma_rules = _load_sigma_rules()
    pending_guid_edges: list[tuple[str, str]] = []
    pending_pid_edges: list[tuple[str, str]] = []

    for event in event_list:
        if first_ts is None or event.timestamp < first_ts:
            first_ts = event.timestamp
        if last_ts is None or event.timestamp > last_ts:
            last_ts = event.timestamp

        if isinstance(event, ProcessCreateEvent):
            guid = event.process_guid
            synthetic = False
            if not guid:
                guid = f"pid:{event.process_id}|image:{_basename(event.image)}|ts:{event.timestamp.isoformat()}"
                synthetic = True

            node = nodes_by_guid.get(guid)
            if not node:
                node = ProcessNode(
                    guid=guid,
                    pid=event.process_id,
                    image=event.image,
                    cmdline=event.command_line,
                    user=event.user,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    synthetic=synthetic,
                )
                nodes_by_guid[guid] = node
            else:
                if event.timestamp < node.first_seen:
                    node.first_seen = event.timestamp
                if event.timestamp > node.last_seen:
                    node.last_seen = event.timestamp

            for rule in sigma_rules:
                if _match_sigma(rule, event.image, event.command_line):
                    for tag in rule.get("tags", []):
                        if tag not in node.tags:
                            node.tags.append(tag)

            if event.parent_process_guid:
                pending_guid_edges.append((event.parent_process_guid, guid))
            elif event.parent_process_id:
                pending_pid_edges.append((f"pid:{event.parent_process_id}", guid))

        if isinstance(event, FileCreateEvent):
            creator = nodes_by_guid.get(event.process_guid)
            confidence = Artifact.Confidence.LOW
            reason = "Missing process_guid"
            if event.process_guid:
                confidence = Artifact.Confidence.MEDIUM
                reason = "Linked by process_guid"
                if creator and _is_interpreter(creator.image, creator.cmdline):
                    confidence = Artifact.Confidence.HIGH
                    reason = "Interpreter process or encoded/scripted command"

            if event.process_guid:
                artifact_links[event.process_guid] += 1

            artifacts.append(
                Artifact(
                    path=_norm_path(event.target_filename),
                    created_at=event.creation_utc_time or event.timestamp,
                    creating_process_guid=event.process_guid or None,
                    creating_image=creator.image if creator else event.image,
                    confidence=confidence,
                    reason=reason,
                    tags=creator.tags if creator else [],
                )
            )

            if _is_script_write(event.target_filename):
                narrative.append(f"Suspicious script write: {event.target_filename}")

        if isinstance(event, NetworkConnectEvent):
            guid = event.process_guid
            node = nodes_by_guid.get(guid)
            if not node:
                node = ProcessNode(
                    guid=guid,
                    pid=event.process_id,
                    image=event.image,
                    cmdline=None,
                    user=None,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    synthetic=False,
                )
                nodes_by_guid[guid] = node
            else:
                if event.timestamp < node.first_seen:
                    node.first_seen = event.timestamp
                if event.timestamp > node.last_seen:
                    node.last_seen = event.timestamp

            suspicious = False
            reasons: list[str] = []
            is_public = _is_public_ip(event.destination_ip)
            uncommon_port = event.destination_port not in COMMON_PORTS
            defender_low_signal = _is_defender_low_signal(event.image, event.destination_port)

            if destination_scoring_mode == "lab":
                if is_public:
                    suspicious = True
                    reasons.append("public_ip")
                if uncommon_port:
                    suspicious = True
                    reasons.append("uncommon_port")
            elif destination_scoring_mode == "strict":
                if is_public and uncommon_port and not defender_low_signal:
                    suspicious = True
                    reasons.extend(["public_ip", "uncommon_port"])
            else:
                if is_public and uncommon_port and not defender_low_signal:
                    suspicious = True
                    reasons.extend(["public_ip", "uncommon_port"])
                elif (
                    is_public
                    and not defender_low_signal
                    and event.destination_port not in {80, 443}
                ):
                    suspicious = True
                    reasons.append("public_ip")

            network_activity.append(
                {
                    "ts": event.timestamp,
                    "process_guid": event.process_guid,
                    "image": event.image,
                    "destination_ip": event.destination_ip,
                    "destination_port": event.destination_port,
                    "protocol": event.protocol,
                    "destination_class": "public" if is_public else "private",
                    "suspicious": suspicious,
                    "reason": ",".join(reasons) if reasons else "",
                    "low_signal": defender_low_signal,
                }
            )

    edge_keys: set[tuple[str, str]] = set()
    for parent_guid, child_guid in pending_guid_edges:
        if parent_guid not in nodes_by_guid:
            continue
        edge_key = (parent_guid, child_guid)
        if edge_key in edge_keys:
            continue
        edges.append(
            ProcessEdge(
                parent_guid=parent_guid,
                child_guid=child_guid,
                reason=GUID_EDGE_REASON,
            )
        )
        edge_keys.add(edge_key)
        out_degree[parent_guid] += 1

    children_with_guid_parent = {
        edge.child_guid for edge in edges if edge.reason == GUID_EDGE_REASON
    }
    for parent_guid, child_guid in pending_pid_edges:
        if child_guid in children_with_guid_parent:
            continue
        edge_key = (parent_guid, child_guid)
        if edge_key in edge_keys:
            continue
        edges.append(
            ProcessEdge(
                parent_guid=parent_guid,
                child_guid=child_guid,
                reason=HEURISTIC_EDGE_REASON,
            )
        )
        edge_keys.add(edge_key)

    if first_ts and last_ts:
        narrative.insert(0, f"First event at {first_ts.isoformat()}")
        narrative.insert(1, f"Last event at {last_ts.isoformat()}")

    schtasks_chain = False
    for edge in edges:
        parent = nodes_by_guid.get(edge.parent_guid)
        child = nodes_by_guid.get(edge.child_guid)
        if (
            _basename(parent.image if parent else None) == "schtasks.exe"
            and _basename(child.image if child else None) == "powershell.exe"
        ):
            schtasks_chain = True
            break
    if schtasks_chain:
        narrative.append("Observed schtasks.exe -> powershell.exe chain")

    if schtasks_chain and any("\\programdata\\" in artifact.path for artifact in artifacts):
        narrative.append(
            "The scheduled task executed powershell.exe, which created a script under C:\\ProgramData. This location is commonly abused for persistence."
        )

    all_nodes = sorted(nodes_by_guid.values(), key=lambda node: (node.first_seen, node.guid))
    key_processes = sorted(
        all_nodes,
        key=lambda node: (
            out_degree.get(node.guid, 0) + (artifact_links.get(node.guid, 0) * 2),
            node.guid,
        ),
        reverse=True,
    )[:10]

    summary = IncidentSummary(
        time_range=(first_ts, last_ts)
        if first_ts and last_ts
        else (
            datetime.now(tz=UTC),
            datetime.now(tz=UTC),
        ),
        agent=event_list[0].agent_name if event_list else None,
        agent_id=event_list[0].agent_id if event_list else None,
        key_processes=key_processes,
        artifacts=artifacts,
        mitre=[],
        narrative_bullets=narrative,
    )

    return {
        "summary": summary,
        "nodes": all_nodes,
        "edges": sorted(edges, key=lambda edge: (edge.parent_guid, edge.child_guid)),
        "artifacts": artifacts,
        "network_activity": network_activity,
    }
