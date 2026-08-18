from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from wazuh_sysmon_triage.models.evidence import SourceRef
from wazuh_sysmon_triage.models.findings import (
    Artifact,
    EvidenceStrength,
    IncidentSummary,
    ProcessEdge,
    ProcessNode,
    RemoteActivityLead,
)
from wazuh_sysmon_triage.models.sysmon import (
    DnsQueryEvent,
    FileCreateEvent,
    FileDeleteEvent,
    NetworkConnectEvent,
    ProcessAccessEvent,
    ProcessCreateEvent,
    ProcessLinkedEvent,
    ProcessTerminateEvent,
    RegistryEvent,
    RemoteLogonEvent,
    ScheduledTaskCreatedEvent,
    ServiceInstallEvent,
    SysmonEvent,
)
from wazuh_sysmon_triage.pipeline.remote_activity import correlate_remote_activity
from wazuh_sysmon_triage.windows_paths import windows_basename, windows_suffix

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
GUID_EDGE_REASON = "Sysmon EID 1 ParentProcessGuid references ProcessGuid"
PID_EDGE_REASON = "Single same-host PID candidate within bounded creation window"
PID_FALLBACK_WINDOW = timedelta(hours=4)
ProcessKey = tuple[str, str]


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False


def _basename(path: str | None) -> str:
    return windows_basename(path)


def _is_defender_low_signal(image: str | None, destination_port: int) -> bool:
    return _basename(image) in LOW_SIGNAL_DEFENDER_BASENAMES and destination_port == 443


def _is_script_write(target: str | None) -> bool:
    if not target:
        return False
    target_lower = target.lower()
    if windows_suffix(target) not in SCRIPT_EXTENSIONS:
        return False
    return any(marker in target_lower for marker in SUSPICIOUS_PATH_MARKERS)


def _event_host_key(event: SysmonEvent) -> str:
    return event.host_key or "unknown:constructed"


def _process_key(host_key: str, guid: str) -> ProcessKey:
    return (host_key, guid)


def _append_source_ref(refs: list[SourceRef], source_ref: SourceRef) -> None:
    identity = (
        source_ref.source_type,
        source_ref.index,
        source_ref.document_id,
        source_ref.raw_digest,
    )
    if all(
        (
            item.source_type,
            item.index,
            item.document_id,
            item.raw_digest,
        )
        != identity
        for item in refs
    ):
        refs.append(source_ref)


def _upsert_node(
    nodes: dict[ProcessKey, ProcessNode],
    event: ProcessLinkedEvent,
) -> tuple[ProcessKey, ProcessNode]:
    host_key = _event_host_key(event)
    key = _process_key(host_key, event.process_guid)
    node = nodes.get(key)
    if node is None:
        node = ProcessNode(
            host_key=host_key,
            guid=event.process_guid,
            pid=event.process_id,
            image=event.image,
            cmdline=event.command_line if isinstance(event, ProcessCreateEvent) else None,
            user=getattr(event, "user", None),
            hashes=event.hashes if isinstance(event, ProcessCreateEvent) else None,
            integrity_level=(
                event.integrity_level if isinstance(event, ProcessCreateEvent) else None
            ),
            created_at=event.timestamp if isinstance(event, ProcessCreateEvent) else None,
            terminated_at=(event.timestamp if isinstance(event, ProcessTerminateEvent) else None),
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            synthetic=not isinstance(event, ProcessCreateEvent),
            source_refs=[event.source_ref],
        )
        nodes[key] = node
        return key, node

    node.first_seen = min(node.first_seen, event.timestamp)
    node.last_seen = max(node.last_seen, event.timestamp)
    _append_source_ref(node.source_refs, event.source_ref)

    if isinstance(event, ProcessCreateEvent):
        node.synthetic = False
        node.pid = event.process_id
        node.image = event.image
        if event.command_line is not None:
            node.cmdline = event.command_line
        if event.user is not None:
            node.user = event.user
        if event.hashes is not None:
            node.hashes = event.hashes
        if event.integrity_level is not None:
            node.integrity_level = event.integrity_level
        node.created_at = (
            min(node.created_at, event.timestamp) if node.created_at else event.timestamp
        )
    elif isinstance(event, ProcessTerminateEvent):
        node.terminated_at = (
            min(node.terminated_at, event.timestamp) if node.terminated_at else event.timestamp
        )
    elif not node.image:
        node.image = event.image

    return key, node


def correlate_data(
    events: Iterable[SysmonEvent],
) -> dict[str, Any]:
    """Build a host-scoped process graph and evidence relationships."""
    event_list = list(events)
    nodes: dict[ProcessKey, ProcessNode] = {}
    edges: list[ProcessEdge] = []
    artifacts: list[Artifact] = []
    file_delete_activity: list[dict[str, Any]] = []
    network_activity: list[dict[str, Any]] = []
    registry_activity: list[dict[str, Any]] = []
    dns_activity: list[dict[str, Any]] = []
    process_access_activity: list[dict[str, Any]] = []
    process_termination_activity: list[dict[str, Any]] = []
    authentication_activity: list[dict[str, Any]] = []
    service_install_activity: list[dict[str, Any]] = []
    scheduled_task_activity: list[dict[str, Any]] = []
    unresolved_relationships: list[dict[str, Any]] = []
    out_degree: defaultdict[ProcessKey, int] = defaultdict(int)
    artifact_links: defaultdict[ProcessKey, int] = defaultdict(int)
    narrative: list[str] = []

    pending_guid_edges: list[tuple[str, str, str, SourceRef]] = []
    pending_pid_edges: list[tuple[str, int, str, datetime, SourceRef]] = []

    first_ts = min((event.timestamp for event in event_list), default=None)
    last_ts = max((event.timestamp for event in event_list), default=None)

    for event in event_list:
        host_key = _event_host_key(event)

        if isinstance(event, ProcessCreateEvent):
            _upsert_node(nodes, event)

            if event.parent_process_guid:
                pending_guid_edges.append(
                    (
                        host_key,
                        event.parent_process_guid,
                        event.process_guid,
                        event.source_ref,
                    )
                )
            elif event.parent_process_id is not None:
                pending_pid_edges.append(
                    (
                        host_key,
                        event.parent_process_id,
                        event.process_guid,
                        event.timestamp,
                        event.source_ref,
                    )
                )

        elif isinstance(event, ProcessTerminateEvent):
            _key, process = _upsert_node(nodes, event)
            process_termination_activity.append(
                {
                    "ts": event.timestamp,
                    "host_key": host_key,
                    "process_guid": event.process_guid,
                    "process_id": event.process_id,
                    "image": event.image,
                    "user": event.user,
                    "relationship_strength": EvidenceStrength.DETERMINISTIC.value,
                    "reason": "Sysmon EID 5 ProcessGuid identifies the terminated process",
                    "source_ref": event.source_ref.model_dump(mode="json"),
                }
            )

        elif isinstance(event, FileCreateEvent):
            key, creator = _upsert_node(nodes, event)
            artifact_links[key] += 1
            artifacts.append(
                Artifact(
                    host_key=host_key,
                    path=event.target_filename,
                    created_at=event.creation_utc_time or event.timestamp,
                    creating_process_guid=event.process_guid,
                    creating_image=creator.image,
                    relationship_strength=EvidenceStrength.DETERMINISTIC,
                    reason="Sysmon EID 11 ProcessGuid identifies the creating process",
                    tags=list(creator.tags),
                    evidence_refs=[event.source_ref],
                )
            )
            if _is_script_write(event.target_filename):
                narrative.append(
                    f"Script-like file created in a user-writable path: {event.target_filename}"
                )

        elif isinstance(event, FileDeleteEvent):
            _upsert_node(nodes, event)
            file_delete_activity.append(
                {
                    "ts": event.timestamp,
                    "host_key": host_key,
                    "process_guid": event.process_guid,
                    "process_id": event.process_id,
                    "image": event.image,
                    "user": event.user,
                    "event_id": event.event_id,
                    "target_filename": event.target_filename,
                    "hashes": event.hashes,
                    "is_executable": event.is_executable,
                    "archived": event.archived,
                    "relationship_strength": EvidenceStrength.DETERMINISTIC.value,
                    "reason": (
                        f"Sysmon EID {event.event_id} ProcessGuid identifies the process "
                        "that deleted the file"
                    ),
                    "source_ref": event.source_ref.model_dump(mode="json"),
                }
            )

        elif isinstance(event, NetworkConnectEvent):
            _upsert_node(nodes, event)
            is_public = _is_public_ip(event.destination_ip)
            uncommon_port = event.destination_port not in COMMON_PORTS
            defender_low_signal = _is_defender_low_signal(event.image, event.destination_port)
            observations: list[str] = []
            if is_public:
                observations.append("public_destination")
            if uncommon_port:
                observations.append("uncommon_destination_port")
            if defender_low_signal:
                observations.append("defender_process_https")

            network_activity.append(
                {
                    "ts": event.timestamp,
                    "host_key": host_key,
                    "process_guid": event.process_guid,
                    "image": event.image,
                    "source_ip": event.source_ip,
                    "source_port": event.source_port,
                    "source_hostname": event.source_hostname,
                    "destination_ip": event.destination_ip,
                    "destination_port": event.destination_port,
                    "destination_hostname": event.destination_hostname,
                    "protocol": event.protocol,
                    "initiated": event.initiated,
                    "user": event.user,
                    "destination_class": "public" if is_public else "non_public",
                    "observations": observations,
                    "low_signal": defender_low_signal,
                    "source_ref": event.source_ref.model_dump(mode="json"),
                }
            )

        elif isinstance(event, RegistryEvent):
            _upsert_node(nodes, event)
            registry_activity.append(
                {
                    "ts": event.timestamp,
                    "host_key": host_key,
                    "process_guid": event.process_guid,
                    "process_id": event.process_id,
                    "image": event.image,
                    "user": event.user,
                    "event_id": event.event_id,
                    "registry_event_type": event.registry_event_type,
                    "target_object": event.target_object,
                    "details": event.details,
                    "new_name": event.new_name,
                    "relationship_strength": EvidenceStrength.DETERMINISTIC.value,
                    "reason": (
                        f"Sysmon EID {event.event_id} ProcessGuid identifies the process "
                        "that changed the registry"
                    ),
                    "source_ref": event.source_ref.model_dump(mode="json"),
                }
            )

        elif isinstance(event, DnsQueryEvent):
            _upsert_node(nodes, event)
            dns_activity.append(
                {
                    "ts": event.timestamp,
                    "host_key": host_key,
                    "process_guid": event.process_guid,
                    "process_id": event.process_id,
                    "image": event.image,
                    "user": event.user,
                    "query_name": event.query_name,
                    "query_status": event.query_status,
                    "query_results": event.query_results,
                    "relationship_strength": EvidenceStrength.DETERMINISTIC.value,
                    "reason": "Sysmon EID 22 ProcessGuid identifies the querying process",
                    "source_ref": event.source_ref.model_dump(mode="json"),
                }
            )

        elif isinstance(event, ProcessAccessEvent):
            _upsert_node(nodes, event)
            target_key = _process_key(host_key, event.target_process_guid)
            target_node = nodes.get(target_key)
            if target_node is None:
                nodes[target_key] = ProcessNode(
                    host_key=host_key,
                    guid=event.target_process_guid,
                    pid=event.target_process_id,
                    image=event.target_image,
                    user=event.target_user,
                    created_at=None,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    synthetic=True,
                    source_refs=[event.source_ref],
                )
            else:
                target_node.first_seen = min(target_node.first_seen, event.timestamp)
                target_node.last_seen = max(target_node.last_seen, event.timestamp)
                _append_source_ref(target_node.source_refs, event.source_ref)
                if not target_node.image:
                    target_node.image = event.target_image
                if target_node.user is None and event.target_user is not None:
                    target_node.user = event.target_user

            process_access_activity.append(
                {
                    "ts": event.timestamp,
                    "host_key": host_key,
                    "source_process_guid": event.process_guid,
                    "source_process_id": event.process_id,
                    "source_image": event.image,
                    "source_user": event.user,
                    "target_process_guid": event.target_process_guid,
                    "target_process_id": event.target_process_id,
                    "target_image": event.target_image,
                    "target_user": event.target_user,
                    "granted_access": event.granted_access,
                    "source_thread_id": event.source_thread_id,
                    "call_trace": event.call_trace,
                    "relationship_strength": EvidenceStrength.DETERMINISTIC.value,
                    "reason": (
                        "Sysmon EID 10 directly records the source and target ProcessGuid values"
                    ),
                    "source_ref": event.source_ref.model_dump(mode="json"),
                }
            )

        elif isinstance(event, RemoteLogonEvent):
            authentication_activity.append(
                {
                    "ts": event.timestamp,
                    "host_key": host_key,
                    "event_id": event.event_id,
                    "logon_type": event.logon_type,
                    "remote_logon": event.logon_type in {3, 10},
                    "target_user_name": event.target_user_name,
                    "target_domain_name": event.target_domain_name,
                    "target_user_sid": event.target_user_sid,
                    "target_logon_id": event.target_logon_id,
                    "user": event.user,
                    "source_ip": event.source_ip,
                    "source_port": event.source_port,
                    "workstation_name": event.workstation_name,
                    "process_id": event.process_id,
                    "process_name": event.process_name,
                    "logon_process_name": event.logon_process_name,
                    "authentication_package_name": event.authentication_package_name,
                    "elevated_token": event.elevated_token,
                    "restricted_admin_mode": event.restricted_admin_mode,
                    "relationship_strength": EvidenceStrength.DETERMINISTIC.value,
                    "reason": "Security EID 4624 records a successful logon on this host",
                    "source_ref": event.source_ref.model_dump(mode="json"),
                }
            )

        elif isinstance(event, ServiceInstallEvent):
            service_install_activity.append(
                {
                    "ts": event.timestamp,
                    "host_key": host_key,
                    "event_id": event.event_id,
                    "subject_user_name": event.subject_user_name,
                    "subject_domain_name": event.subject_domain_name,
                    "subject_user_sid": event.subject_user_sid,
                    "subject_logon_id": event.subject_logon_id,
                    "user": event.user,
                    "service_name": event.service_name,
                    "service_file_name": event.service_file_name,
                    "service_type": event.service_type,
                    "service_start_type": event.service_start_type,
                    "service_account": event.service_account,
                    "relationship_strength": EvidenceStrength.DETERMINISTIC.value,
                    "reason": "Security EID 4697 records installation of this service",
                    "source_ref": event.source_ref.model_dump(mode="json"),
                }
            )

        elif isinstance(event, ScheduledTaskCreatedEvent):
            scheduled_task_activity.append(
                {
                    "ts": event.timestamp,
                    "host_key": host_key,
                    "event_id": event.event_id,
                    "subject_user_name": event.subject_user_name,
                    "subject_domain_name": event.subject_domain_name,
                    "subject_user_sid": event.subject_user_sid,
                    "subject_logon_id": event.subject_logon_id,
                    "user": event.user,
                    "task_name": event.task_name,
                    "task_content": event.task_content,
                    "client_process_id": event.client_process_id,
                    "parent_process_id": event.parent_process_id,
                    "relationship_strength": EvidenceStrength.DETERMINISTIC.value,
                    "reason": "Security EID 4698 records creation of this scheduled task",
                    "source_ref": event.source_ref.model_dump(mode="json"),
                }
            )

    remote_activity_leads: list[RemoteActivityLead] = correlate_remote_activity(event_list)
    for lead in remote_activity_leads:
        narrative.append(lead.reason)

    edge_keys: set[tuple[str, str, str]] = set()
    exact_parent_children: set[ProcessKey] = set()
    for host_key, parent_guid, child_guid, source_ref in pending_guid_edges:
        parent_key = _process_key(host_key, parent_guid)
        child_key = _process_key(host_key, child_guid)
        if parent_key not in nodes or child_key not in nodes:
            unresolved_relationships.append(
                {
                    "host_key": host_key,
                    "child_guid": child_guid,
                    "parent_guid": parent_guid,
                    "relationship_strength": EvidenceStrength.UNRESOLVED.value,
                    "reason": "ParentProcessGuid was not present in collected evidence",
                    "evidence_refs": [source_ref.model_dump(mode="json")],
                }
            )
            continue
        edge_key = (host_key, parent_guid, child_guid)
        if edge_key in edge_keys:
            continue
        edges.append(
            ProcessEdge(
                host_key=host_key,
                parent_guid=parent_guid,
                child_guid=child_guid,
                relationship_strength=EvidenceStrength.DETERMINISTIC,
                reason=GUID_EDGE_REASON,
                evidence_refs=[source_ref],
            )
        )
        edge_keys.add(edge_key)
        exact_parent_children.add(child_key)
        out_degree[parent_key] += 1

    for host_key, parent_pid, child_guid, child_ts, source_ref in pending_pid_edges:
        child_key = _process_key(host_key, child_guid)
        if child_key in exact_parent_children:
            continue
        candidates = [
            (key, node)
            for key, node in nodes.items()
            if key[0] == host_key
            and node.pid == parent_pid
            and node.guid != child_guid
            and node.created_at is not None
            and timedelta(0) <= child_ts - node.created_at <= PID_FALLBACK_WINDOW
        ]
        if len(candidates) != 1:
            unresolved_relationships.append(
                {
                    "host_key": host_key,
                    "child_guid": child_guid,
                    "parent_pid": parent_pid,
                    "candidate_parent_guids": sorted(node.guid for _, node in candidates),
                    "relationship_strength": EvidenceStrength.UNRESOLVED.value,
                    "reason": (
                        "No bounded same-host PID candidate"
                        if not candidates
                        else "Multiple bounded same-host PID candidates"
                    ),
                    "evidence_refs": [source_ref.model_dump(mode="json")],
                }
            )
            continue

        parent_key, parent = candidates[0]
        edge_key = (host_key, parent.guid, child_guid)
        if edge_key in edge_keys or child_key not in nodes:
            continue
        edges.append(
            ProcessEdge(
                host_key=host_key,
                parent_guid=parent.guid,
                child_guid=child_guid,
                relationship_strength=EvidenceStrength.CIRCUMSTANTIAL,
                reason=PID_EDGE_REASON,
                evidence_refs=[source_ref],
            )
        )
        edge_keys.add(edge_key)
        out_degree[parent_key] += 1

    if first_ts and last_ts:
        narrative.insert(0, f"First event at {first_ts.isoformat()}")
        narrative.insert(1, f"Last event at {last_ts.isoformat()}")

    for edge in edges:
        parent_node = nodes.get(_process_key(edge.host_key, edge.parent_guid))
        child_node = nodes.get(_process_key(edge.host_key, edge.child_guid))
        if (
            parent_node
            and child_node
            and _basename(parent_node.image) == "schtasks.exe"
            and _basename(child_node.image) == "powershell.exe"
        ):
            narrative.append(
                f"Observed schtasks.exe -> powershell.exe relationship on {edge.host_key}"
            )

    all_nodes = sorted(
        nodes.values(),
        key=lambda node: (node.host_key, node.first_seen, node.guid),
    )
    key_processes = sorted(
        all_nodes,
        key=lambda node: (
            out_degree.get(_process_key(node.host_key, node.guid), 0)
            + artifact_links.get(_process_key(node.host_key, node.guid), 0) * 2,
            node.host_key,
            node.guid,
        ),
        reverse=True,
    )[:10]

    host_keys = sorted({_event_host_key(event) for event in event_list})
    agent_names = {event.agent_name for event in event_list if event.agent_name}
    agent_ids = {event.agent_id for event in event_list if event.agent_id}
    mitre = sorted({technique for event in event_list for technique in event.mitre_techniques})
    now = datetime.now(tz=UTC)
    summary = IncidentSummary(
        time_range=(first_ts, last_ts) if first_ts and last_ts else (now, now),
        agent=next(iter(agent_names)) if len(agent_names) == 1 else None,
        agent_id=next(iter(agent_ids)) if len(agent_ids) == 1 else None,
        host_keys=host_keys,
        key_processes=key_processes,
        artifacts=artifacts,
        mitre=mitre,
        narrative_bullets=list(dict.fromkeys(narrative)),
    )

    return {
        "summary": summary,
        "nodes": all_nodes,
        "edges": sorted(
            edges,
            key=lambda edge: (edge.host_key, edge.parent_guid, edge.child_guid),
        ),
        "artifacts": sorted(
            artifacts,
            key=lambda artifact: (artifact.host_key, artifact.created_at, artifact.path),
        ),
        "file_delete_activity": sorted(
            file_delete_activity,
            key=lambda entry: (
                entry["ts"],
                entry["host_key"],
                entry["process_guid"],
                entry["target_filename"],
            ),
        ),
        "network_activity": sorted(
            network_activity,
            key=lambda entry: (
                entry["ts"],
                entry["host_key"],
                entry["process_guid"],
                entry["destination_ip"],
                entry["destination_port"],
            ),
        ),
        "registry_activity": sorted(
            registry_activity,
            key=lambda entry: (
                entry["ts"],
                entry["host_key"],
                entry["process_guid"],
                entry["target_object"],
            ),
        ),
        "dns_activity": sorted(
            dns_activity,
            key=lambda entry: (
                entry["ts"],
                entry["host_key"],
                entry["process_guid"],
                entry["query_name"],
            ),
        ),
        "process_access_activity": sorted(
            process_access_activity,
            key=lambda entry: (
                entry["ts"],
                entry["host_key"],
                entry["source_process_guid"],
                entry["target_process_guid"],
            ),
        ),
        "process_termination_activity": sorted(
            process_termination_activity,
            key=lambda entry: (
                entry["ts"],
                entry["host_key"],
                entry["process_guid"],
            ),
        ),
        "authentication_activity": sorted(
            authentication_activity,
            key=lambda entry: (
                entry["ts"],
                entry["host_key"],
                entry["target_logon_id"],
            ),
        ),
        "service_install_activity": sorted(
            service_install_activity,
            key=lambda entry: (
                entry["ts"],
                entry["host_key"],
                entry["service_name"],
            ),
        ),
        "scheduled_task_activity": sorted(
            scheduled_task_activity,
            key=lambda entry: (
                entry["ts"],
                entry["host_key"],
                entry["task_name"],
            ),
        ),
        "remote_activity_leads": remote_activity_leads,
        "unresolved_relationships": unresolved_relationships,
    }
