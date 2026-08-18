from __future__ import annotations

import csv
import json
import os
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.findings import (
    Artifact,
    IncidentSummary,
    ProcessEdge,
    ProcessNode,
    RemoteActivityLead,
)
from wazuh_sysmon_triage.models.sysmon import SysmonEvent
from wazuh_sysmon_triage.output_schema import OUTPUT_SCHEMA_VERSION
from wazuh_sysmon_triage.sanitize import OutputSanitizer
from wazuh_sysmon_triage.windows_paths import windows_basename


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _iso_z(value: datetime | None) -> str:
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(UTC)
    return value.isoformat().replace("+00:00", "Z")


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return _iso_z(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _maybe_sanitize(value: Any, sanitizer: OutputSanitizer | None) -> Any:
    if sanitizer is None:
        return value
    if isinstance(value, str):
        return sanitizer.sanitize_text(value)
    return value


def _md_cell(value: Any, sanitizer: OutputSanitizer | None = None) -> str:
    if value is None:
        return ""
    text = str(_maybe_sanitize(value, sanitizer))
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def render_timeline(
    data: Sequence[SysmonEvent],
    output_dir: str,
    *,
    sanitizer: OutputSanitizer | None = None,
) -> None:
    """
    Renders the timeline data to a CSV file.

    Args:
        data (list): The timeline data to render.
        output_dir (str): The directory where the output file will be saved.
    """
    _ensure_dir(output_dir)
    path = os.path.join(output_dir, "timeline.csv")

    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "ts",
                "wazuh_timestamp",
                "indexed_at",
                "event_id",
                "host_key",
                "process_guid",
                "process_id",
                "image",
                "command_line",
                "parent_process_guid",
                "parent_image",
                "target_filename",
                "user",
                "source_ip",
                "source_port",
                "destination_ip",
                "destination_port",
                "rule_id",
                "rule_level",
                "agent_name",
                "agent_id",
                "source_index",
                "source_document_id",
                "record_id",
                "raw_digest",
                "parse_warnings",
                "registry_event_type",
                "target_object",
                "details",
                "new_name",
                "query_name",
                "query_status",
                "query_results",
                "target_process_guid",
                "target_process_id",
                "target_image",
                "granted_access",
                "call_trace",
                "event_type",
                "hashes",
                "is_executable",
                "archived",
                "logon_type",
                "target_user_name",
                "target_domain_name",
                "target_logon_id",
                "workstation_name",
                "process_name",
                "logon_process_name",
                "authentication_package_name",
                "elevated_token",
                "restricted_admin_mode",
                "subject_user_name",
                "subject_domain_name",
                "subject_logon_id",
                "service_name",
                "service_file_name",
                "service_type",
                "service_start_type",
                "service_account",
                "task_name",
                "task_content",
                "client_process_id",
                "parent_process_id",
            ]
        )
        for event in data:
            source_ref = event.source_ref
            writer.writerow(
                [
                    _iso_z(event.timestamp),
                    _iso_z(event.wazuh_timestamp),
                    _iso_z(event.indexed_at),
                    event.event_id,
                    _maybe_sanitize(event.host_key or "", sanitizer),
                    _maybe_sanitize(getattr(event, "process_guid", "") or "", sanitizer),
                    getattr(event, "process_id", "") or "",
                    _maybe_sanitize(getattr(event, "image", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "command_line", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "parent_process_guid", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "parent_image", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "target_filename", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "user", "") or "", sanitizer),
                    sanitizer.sanitize_ip(getattr(event, "source_ip", None))
                    if sanitizer
                    else (getattr(event, "source_ip", "") or ""),
                    getattr(event, "source_port", "") or "",
                    sanitizer.sanitize_ip(getattr(event, "destination_ip", None))
                    if sanitizer
                    else (getattr(event, "destination_ip", "") or ""),
                    getattr(event, "destination_port", "") or "",
                    _maybe_sanitize(getattr(event, "rule_id", "") or "", sanitizer),
                    getattr(event, "rule_level", "") or "",
                    _maybe_sanitize(getattr(event, "agent_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "agent_id", "") or "", sanitizer),
                    _maybe_sanitize(source_ref.index or "", sanitizer),
                    _maybe_sanitize(source_ref.document_id or "", sanitizer),
                    _maybe_sanitize(source_ref.record_id or "", sanitizer),
                    source_ref.raw_digest or "",
                    _maybe_sanitize(";".join(event.parse_warnings), sanitizer),
                    _maybe_sanitize(getattr(event, "registry_event_type", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "target_object", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "details", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "new_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "query_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "query_status", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "query_results", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "target_process_guid", "") or "", sanitizer),
                    getattr(event, "target_process_id", "") or "",
                    _maybe_sanitize(getattr(event, "target_image", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "granted_access", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "call_trace", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "event_type", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "hashes", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "is_executable", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "archived", "") or "", sanitizer),
                    getattr(event, "logon_type", "") or "",
                    _maybe_sanitize(getattr(event, "target_user_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "target_domain_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "target_logon_id", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "workstation_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "process_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "logon_process_name", "") or "", sanitizer),
                    _maybe_sanitize(
                        getattr(event, "authentication_package_name", "") or "", sanitizer
                    ),
                    _maybe_sanitize(getattr(event, "elevated_token", "") or "", sanitizer),
                    _maybe_sanitize(
                        getattr(event, "restricted_admin_mode", "") or "", sanitizer
                    ),
                    _maybe_sanitize(getattr(event, "subject_user_name", "") or "", sanitizer),
                    _maybe_sanitize(
                        getattr(event, "subject_domain_name", "") or "", sanitizer
                    ),
                    _maybe_sanitize(getattr(event, "subject_logon_id", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "service_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "service_file_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "service_type", "") or "", sanitizer),
                    _maybe_sanitize(
                        getattr(event, "service_start_type", "") or "", sanitizer
                    ),
                    _maybe_sanitize(getattr(event, "service_account", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "task_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "task_content", "") or "", sanitizer),
                    getattr(event, "client_process_id", "") or "",
                    getattr(event, "parent_process_id", "") or "",
                ]
            )


def render_process_tree(
    data: dict[str, Any],
    output_dir: str,
    *,
    sanitizer: OutputSanitizer | None = None,
) -> None:
    """
    Renders the process tree data to a JSON file.

    Args:
        data (dict): The process tree data to render.
        output_dir (str): The directory where the output file will be saved.
    """
    _ensure_dir(output_dir)
    path = os.path.join(output_dir, "process_tree.json")

    summary: IncidentSummary | None = data.get("summary")
    nodes: Iterable[ProcessNode] = data.get("nodes", [])
    edges: Iterable[ProcessEdge] = data.get("edges", [])
    artifacts: Iterable[Artifact] = data.get("artifacts", [])
    unresolved_relationships: Iterable[dict[str, Any]] = data.get("unresolved_relationships", [])
    remote_activity_leads: Iterable[RemoteActivityLead] = data.get(
        "remote_activity_leads", []
    )

    nodes_sorted = sorted(nodes, key=lambda node: (node.host_key, node.first_seen, node.guid))
    edges_sorted = sorted(
        edges, key=lambda edge: (edge.host_key, edge.parent_guid, edge.child_guid)
    )
    artifacts_sorted = sorted(artifacts, key=lambda art: (art.host_key, art.created_at, art.path))

    payload = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "agent": {
            "name": summary.agent if summary else None,
            "id": summary.agent_id if summary else None,
        },
        "host_keys": summary.host_keys if summary else [],
        "time_range": {
            "start": _iso_z(summary.time_range[0]) if summary else "",
            "end": _iso_z(summary.time_range[1]) if summary else "",
        },
        "nodes": [node.model_dump(mode="json") for node in nodes_sorted],
        "edges": [edge.model_dump(mode="json") for edge in edges_sorted],
        "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts_sorted],
        "file_delete_activity": data.get("file_delete_activity", []),
        "unresolved_relationships": list(unresolved_relationships),
        "network_activity": data.get("network_activity", []),
        "registry_activity": data.get("registry_activity", []),
        "dns_activity": data.get("dns_activity", []),
        "process_access_activity": data.get("process_access_activity", []),
        "process_termination_activity": data.get("process_termination_activity", []),
        "authentication_activity": data.get("authentication_activity", []),
        "service_install_activity": data.get("service_install_activity", []),
        "scheduled_task_activity": data.get("scheduled_task_activity", []),
        "remote_activity_leads": [
            lead.model_dump(mode="json") for lead in remote_activity_leads
        ],
    }
    if sanitizer:
        payload = sanitizer.sanitize_obj(payload)

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=_json_default)


def render_alerts_csv(
    alerts: Sequence[Alert],
    output_dir: str,
    *,
    sanitizer: OutputSanitizer | None = None,
) -> None:
    _ensure_dir(output_dir)
    path = os.path.join(output_dir, "alerts.csv")

    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "alert_id",
                "utc_time",
                "alert_type",
                "category",
                "finding_kind",
                "evidence_strength",
                "reason",
                "host_key",
                "image",
                "command_line",
                "parent_image",
                "destination_ip",
                "destination_port",
                "process_guid",
                "evidence_refs",
                "tags",
                "source_host_key",
                "source_ip",
                "source_port",
            ]
        )
        for alert in alerts:
            writer.writerow(
                [
                    _maybe_sanitize(alert.alert_id, sanitizer),
                    _iso_z(alert.utc_time),
                    _maybe_sanitize(alert.alert_type, sanitizer),
                    _maybe_sanitize(alert.category, sanitizer),
                    _maybe_sanitize(alert.finding_kind, sanitizer),
                    _maybe_sanitize(alert.evidence_strength.value, sanitizer),
                    _maybe_sanitize(alert.reason, sanitizer),
                    _maybe_sanitize(alert.host_key, sanitizer),
                    _maybe_sanitize(alert.image, sanitizer),
                    _maybe_sanitize(alert.command_line or "", sanitizer),
                    _maybe_sanitize(alert.parent_image or "", sanitizer),
                    sanitizer.sanitize_ip(alert.destination_ip)
                    if sanitizer
                    else (alert.destination_ip or ""),
                    alert.destination_port if alert.destination_port is not None else "",
                    _maybe_sanitize(alert.process_guid, sanitizer),
                    _maybe_sanitize(
                        ";".join(ref.locator for ref in alert.evidence_refs), sanitizer
                    ),
                    _maybe_sanitize(";".join(alert.tags), sanitizer),
                    _maybe_sanitize(alert.source_host_key or "", sanitizer),
                    sanitizer.sanitize_ip(alert.source_ip)
                    if sanitizer
                    else (alert.source_ip or ""),
                    alert.source_port if alert.source_port is not None else "",
                ]
            )


def render_alert_bundles(
    pivot_bundles: Sequence[dict[str, Any]],
    output_dir: str,
    *,
    sanitizer: OutputSanitizer | None = None,
) -> None:
    _ensure_dir(output_dir)
    for bundle in pivot_bundles:
        payload = dict(bundle)
        payload.setdefault("schema_version", OUTPUT_SCHEMA_VERSION)
        if sanitizer:
            payload = sanitizer.sanitize_obj(payload)
        alert = payload.get("alert", {})
        alert_id = alert.get("alert_id") or "A000"
        path = os.path.join(output_dir, f"alert_{alert_id}_bundle.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)


def render_investigation_anchor(
    anchor: dict[str, Any],
    output_dir: str,
    *,
    sanitizer: OutputSanitizer | None = None,
) -> None:
    _ensure_dir(output_dir)
    payload: dict[str, Any] = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        **anchor,
    }
    if sanitizer:
        payload = sanitizer.sanitize_obj(payload)
    with open(
        os.path.join(output_dir, "investigation_anchor.json"), "w", encoding="utf-8"
    ) as handle:
        json.dump(payload, handle, indent=2)


def _wazuh_queries(alert: Alert, sanitizer: OutputSanitizer | None = None) -> list[str]:
    process_guid = _maybe_sanitize(alert.process_guid, sanitizer)
    destination_ip = (
        sanitizer.sanitize_ip(alert.destination_ip) if sanitizer else alert.destination_ip
    )
    source_ip = sanitizer.sanitize_ip(alert.source_ip) if sanitizer else alert.source_ip
    image = _maybe_sanitize(alert.image, sanitizer)

    queries: list[str] = []
    if process_guid:
        queries.append(
            f'data.win.eventdata.processGuid:"{process_guid}" AND data.win.system.eventID:("1" OR "3" OR "5" OR "11" OR "12" OR "13" OR "14" OR "22" OR "23" OR "26")'
        )
        queries.append(
            f'data.win.eventdata.parentProcessGuid:"{process_guid}" AND data.win.system.eventID:"1"'
        )
        queries.append(
            f'data.win.eventdata.sourceProcessGUID:"{process_guid}" AND data.win.system.eventID:"10"'
        )
    if destination_ip:
        queries.append(
            f'data.win.system.eventID:"3" AND data.win.eventdata.destinationIp:"{destination_ip}" AND data.win.eventdata.image:"*{windows_basename(image)}"'
        )
    if source_ip:
        queries.append(
            f'data.win.system.eventID:"4624" AND data.win.eventdata.ipAddress:"{source_ip}"'
        )
    if alert.primary_event_id in {4697, 4698}:
        queries.append('data.win.system.eventID:("4624" OR "4697" OR "4698")')
    if image and alert.primary_event_id == 4697:
        queries.append(
            f'data.win.system.eventID:"4697" AND data.win.eventdata.serviceName:"{image}"'
        )
    elif image and alert.primary_event_id == 4698:
        queries.append(
            f'data.win.system.eventID:"4698" AND data.win.eventdata.taskName:"{image}"'
        )
    elif image:
        queries.append(
            f'data.win.eventdata.image:"*{windows_basename(image)}" AND data.win.system.eventID:("1" OR "3")'
        )
    return queries[:5]


def render_report(
    data: dict[str, Any],
    output_dir: str,
    *,
    sanitizer: OutputSanitizer | None = None,
) -> None:
    """
    Renders the report data to a Markdown file.

    Args:
        data (dict): The report data to render.
        output_dir (str): The directory where the output file will be saved.
    """
    _ensure_dir(output_dir)
    path = os.path.join(output_dir, "report.md")

    summary: IncidentSummary | None = data.get("summary")
    nodes: Iterable[ProcessNode] = data.get("nodes", [])
    edges: Iterable[ProcessEdge] = data.get("edges", [])
    artifacts: Iterable[Artifact] = data.get("artifacts", [])
    events: Sequence[SysmonEvent] = data.get("events", [])
    query_params: dict[str, Any] = data.get("query", {})
    case_id: str | None = data.get("case_id")
    truncation: dict[str, Any] | None = data.get("truncation")
    network_activity: list[dict[str, Any]] = data.get("network_activity", [])
    registry_activity: list[dict[str, Any]] = data.get("registry_activity", [])
    dns_activity: list[dict[str, Any]] = data.get("dns_activity", [])
    process_access_activity: list[dict[str, Any]] = data.get("process_access_activity", [])
    file_delete_activity: list[dict[str, Any]] = data.get("file_delete_activity", [])
    process_termination_activity: list[dict[str, Any]] = data.get(
        "process_termination_activity", []
    )
    authentication_activity: list[dict[str, Any]] = data.get("authentication_activity", [])
    service_install_activity: list[dict[str, Any]] = data.get("service_install_activity", [])
    scheduled_task_activity: list[dict[str, Any]] = data.get("scheduled_task_activity", [])
    remote_activity_leads: list[RemoteActivityLead] = data.get("remote_activity_leads", [])
    alerts: list[Alert] = data.get("alerts", [])
    investigation_anchor: dict[str, Any] | None = data.get("investigation_anchor")
    input_quality: dict[str, Any] | None = data.get("input_quality")

    time_range = summary.time_range if summary else (None, None)
    agent_name = summary.agent if summary else None
    if sanitizer:
        agent_name = sanitizer.sanitize_text(agent_name)
        case_id = sanitizer.sanitize_text(case_id)
        query_params = sanitizer.sanitize_obj(query_params)

    mitre_set = set(summary.mitre if summary else [])
    rule_ids = set()
    for event in events:
        for technique in getattr(event, "mitre_techniques", []) or []:
            mitre_set.add(str(technique))
        if event.rule_id:
            rule_ids.add(str(event.rule_id))

    nodes_list = list(nodes)
    edges_list = list(edges)
    artifacts_list = list(artifacts)

    exec_bullets = list(summary.narrative_bullets) if summary else []
    if not exec_bullets:
        exec_bullets = [
            f"Observed {len(nodes_list)} processes and {len(artifacts_list)} artifacts.",
            "Timeline constructed from supported high-value Sysmon evidence.",
            "No additional narrative available.",
        ]

    exec_bullets = exec_bullets[:6]

    node_by_key = {(node.host_key, node.guid): node for node in nodes_list}
    chains: list[str] = []
    for edge in edges_list:
        parent = node_by_key.get((edge.host_key, edge.parent_guid))
        child = node_by_key.get((edge.host_key, edge.child_guid))
        if parent and child:
            chains.append(
                f"[{edge.host_key}] [{edge.relationship_strength.value}] "
                f"{windows_basename(parent.image)} -> {windows_basename(child.image)}"
            )

    artifacts_rows = [
        "| Host | Path | Created At | Creator Image | Relationship |",
        "| --- | --- | --- | --- | --- |",
    ]
    for artifact in artifacts_list:
        artifacts_rows.append(
            f"| {_md_cell(artifact.host_key, sanitizer)} | {_md_cell(artifact.path, sanitizer)} | {_iso_z(artifact.created_at)} | {_md_cell(artifact.creating_image or '', sanitizer)} | {_md_cell(artifact.relationship_strength.value, sanitizer)} |"
        )

    mitre_list = sorted(mitre_set)
    mitre_section = ", ".join(mitre_list) if mitre_list else "None"

    query_lines = [f"- {key}: {value}" for key, value in query_params.items()]
    if not query_lines:
        query_lines = ["- n/a"]

    rule_notes = ", ".join(sorted(rule_ids)) if rule_ids else "None"

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("# Incident Summary\n\n")
        handle.write(f"**Agent:** {agent_name or 'Unknown'}\n")
        if case_id:
            handle.write(f"**Case ID:** {case_id}\n")
        handle.write(f"**Schema version:** {OUTPUT_SCHEMA_VERSION}\n")
        handle.write("\n")
        handle.write(f"**Timeframe:** {_iso_z(time_range[0])} to {_iso_z(time_range[1])}\n\n")
        handle.write("**Query Parameters:**\n")
        handle.write("\n".join(query_lines) + "\n\n")

        if investigation_anchor:
            anchor_rule = investigation_anchor.get("rule") or {}
            anchor_agent = investigation_anchor.get("agent") or {}
            handle.write("## Investigation anchor\n")
            handle.write(
                f"- Document: {_md_cell(investigation_anchor.get('document_id'), sanitizer)}\n"
            )
            handle.write(f"- Time: {_md_cell(investigation_anchor.get('timestamp'), sanitizer)}\n")
            handle.write(
                f"- Host: {_md_cell(investigation_anchor.get('computer') or anchor_agent.get('name'), sanitizer)}\n"
            )
            handle.write(
                f"- Wazuh rule: {_md_cell(anchor_rule.get('id'), sanitizer)} {_md_cell(anchor_rule.get('description'), sanitizer)}\n\n"
            )

        if truncation and truncation.get("truncated"):
            handle.write(
                "WARNING: Results truncated due to max-events guardrail; expand time range filtering or increase limits.\n\n"
                if truncation.get("reason") == "max-events"
                else "WARNING: Results truncated due to max-pages guardrail; increase paging limits or narrow time range.\n\n"
            )

        if input_quality:
            handle.write("## Input quality\n")
            handle.write(f"- Integrity: {_md_cell(input_quality.get('integrity'), sanitizer)}\n")
            handle.write(
                f"- Accepted records: {int(input_quality.get('accepted_records') or 0)}\n"
            )
            handle.write(
                f"- Rejected records: {int(input_quality.get('rejected_records') or 0)}\n"
            )
            handle.write(f"- Blank lines: {int(input_quality.get('blank_lines') or 0)}\n")
            rejected_by_reason = input_quality.get("rejected_by_reason") or {}
            if rejected_by_reason:
                reasons = ", ".join(
                    f"{reason}={count}"
                    for reason, count in sorted(rejected_by_reason.items())
                )
                handle.write(f"- Rejections by reason: {_md_cell(reasons, sanitizer)}\n")
            handle.write("\n")
            if input_quality.get("integrity") == "degraded":
                handle.write(
                    "WARNING: Input integrity is degraded; review quarantine.ndjson and "
                    "treat conclusions as bounded by the accepted evidence.\n\n"
                )

        handle.write("## Observed evidence summary\n")
        for bullet in exec_bullets:
            handle.write(f"- {_md_cell(bullet, sanitizer)}\n")
        handle.write("\n")

        handle.write("## Behavior findings\n")
        if alerts:
            handle.write(
                "| Time | Type | Category | Kind | Evidence strength | Reason | Host | Image / resource | Command / details | Network context | Process GUID | Evidence | Tags |\n"
            )
            handle.write(
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
            )
            for alert in alerts[:20]:
                destination = ""
                if alert.destination_ip:
                    destination = f"{alert.destination_ip}:{alert.destination_port or ''}".rstrip(
                        ":"
                    )
                elif alert.source_ip:
                    source = f"{alert.source_ip}:{alert.source_port or ''}".rstrip(":")
                    destination = f"source={source}"
                handle.write(
                    f"| {_iso_z(alert.utc_time)} | {_md_cell(alert.alert_type, sanitizer)} | {_md_cell(alert.category, sanitizer)} | {_md_cell(alert.finding_kind, sanitizer)} | {_md_cell(alert.evidence_strength.value, sanitizer)} | {_md_cell(alert.reason, sanitizer)} | {_md_cell(alert.host_key, sanitizer)} | {_md_cell(alert.image, sanitizer)} | {_md_cell(alert.command_line or '', sanitizer)} | {_md_cell(destination, sanitizer)} | {_md_cell(alert.process_guid, sanitizer)} | {_md_cell(';'.join(ref.locator for ref in alert.evidence_refs), sanitizer)} | {_md_cell(';'.join(alert.tags), sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write("No local behavior rules matched.\n\n")

        handle.write("## Wazuh Pivot Queries\n")
        if alerts:
            for alert in alerts[:3]:
                handle.write(
                    f"- {_md_cell(alert.alert_id or '', sanitizer)} {_md_cell(alert.alert_type, sanitizer)}\n"
                )
                for query in _wazuh_queries(alert, sanitizer):
                    handle.write(f"  - `{query}`\n")
            handle.write("\n")
        else:
            handle.write("No alert-driven pivot queries available.\n\n")

        handle.write("## Observed process chains\n")
        if chains:
            for chain in chains:
                handle.write(f"- {_md_cell(chain, sanitizer)}\n")
        else:
            handle.write("- No process chains available.\n")
        handle.write("\n")

        handle.write("## Observed file activity\n")
        handle.write("\n".join(artifacts_rows) + "\n\n")

        handle.write("## File deletion activity\n")
        if file_delete_activity:
            handle.write("| Time | Path | Process | Event ID | Hashes | Host |\n")
            handle.write("| --- | --- | --- | --- | --- | --- |\n")
            for entry in file_delete_activity[:20]:
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {_md_cell(entry.get('target_filename'), sanitizer)} | {_md_cell(entry.get('image'), sanitizer)} | {_md_cell(entry.get('event_id'), sanitizer)} | {_md_cell(entry.get('hashes') or '', sanitizer)} | {_md_cell(entry.get('host_key'), sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write(
                "No file deletion events were present in the collected evidence; this is not proof that no files were deleted.\n\n"
            )

        handle.write("## Process termination activity\n")
        if process_termination_activity:
            handle.write("| Time | Process | PID | User | Host |\n")
            handle.write("| --- | --- | --- | --- | --- |\n")
            for entry in process_termination_activity[:20]:
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {_md_cell(entry.get('image'), sanitizer)} | {_md_cell(entry.get('process_id'), sanitizer)} | {_md_cell(entry.get('user') or '', sanitizer)} | {_md_cell(entry.get('host_key'), sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write(
                "No process termination events were present in the collected evidence; process end times remain unknown.\n\n"
            )

        handle.write("## Remote authentication activity\n")
        remote_logons = [entry for entry in authentication_activity if entry.get("remote_logon")]
        if remote_logons:
            handle.write("| Time | Type | Account | Source | Workstation | Target host |\n")
            handle.write("| --- | --- | --- | --- | --- | --- |\n")
            for entry in remote_logons[:20]:
                source = entry.get("source_ip") or ""
                if source and entry.get("source_port") is not None:
                    source = f"{source}:{entry['source_port']}"
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {_md_cell(entry.get('logon_type'), sanitizer)} | {_md_cell(entry.get('user'), sanitizer)} | {_md_cell(source, sanitizer)} | {_md_cell(entry.get('workstation_name') or '', sanitizer)} | {_md_cell(entry.get('host_key'), sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write(
                "No Security 4624 network or remote-interactive logons were present in the collected evidence.\n\n"
            )

        handle.write("## Service installation activity\n")
        if service_install_activity:
            handle.write("| Time | Service | Executable / command | Account | Creator | Host |\n")
            handle.write("| --- | --- | --- | --- | --- | --- |\n")
            for entry in service_install_activity[:20]:
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {_md_cell(entry.get('service_name'), sanitizer)} | {_md_cell(entry.get('service_file_name'), sanitizer)} | {_md_cell(entry.get('service_account') or '', sanitizer)} | {_md_cell(entry.get('user'), sanitizer)} | {_md_cell(entry.get('host_key'), sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write("No Security 4697 service-install events observed.\n\n")

        handle.write("## Scheduled-task creation activity\n")
        if scheduled_task_activity:
            handle.write("| Time | Task | Creator | Host | Task definition |\n")
            handle.write("| --- | --- | --- | --- | --- |\n")
            for entry in scheduled_task_activity[:20]:
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {_md_cell(entry.get('task_name'), sanitizer)} | {_md_cell(entry.get('user'), sanitizer)} | {_md_cell(entry.get('host_key'), sanitizer)} | {_md_cell(entry.get('task_content') or '', sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write("No Security 4698 scheduled-task creation events observed.\n\n")

        handle.write("## Remote-activity leads\n")
        if remote_activity_leads:
            handle.write(
                "These are bounded hypotheses for analyst follow-up, not lateral-movement or maliciousness verdicts.\n\n"
            )
            handle.write("| Action time | Source host | Target host | Account | Action | Strength | Reason |\n")
            handle.write("| --- | --- | --- | --- | --- | --- | --- |\n")
            for lead in remote_activity_leads[:20]:
                handle.write(
                    f"| {_iso_z(lead.action_at)} | {_md_cell(lead.source_host_key or lead.source_ip or 'unresolved', sanitizer)} | {_md_cell(lead.target_host_key, sanitizer)} | {_md_cell(lead.account, sanitizer)} | {_md_cell(f'{lead.action_type}: {lead.action_resource}', sanitizer)} | {_md_cell(lead.evidence_strength.value, sanitizer)} | {_md_cell(lead.reason, sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write(
                "No qualifying same-host remote-logon-to-service/task sequence was reconstructed.\n\n"
            )

        handle.write("## ATT&CK metadata from source rules\n")
        handle.write(
            f"{_md_cell(mitre_section, sanitizer)}\n\n"
            "These mappings are source metadata, not independent evidence.\n\n"
        )

        handle.write("## Network activity\n")
        if network_activity:
            handle.write("| Time | Destination | Port | Protocol | Image | Observations |\n")
            handle.write("| --- | --- | --- | --- | --- | --- |\n")
            for entry in network_activity[:10]:
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {_md_cell(entry.get('destination_ip'), sanitizer)} | {_md_cell(entry.get('destination_port'), sanitizer)} | {_md_cell(entry.get('protocol') or '', sanitizer)} | {_md_cell(entry.get('image'), sanitizer)} | {_md_cell(','.join(entry.get('observations') or []), sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write("No network activity observed.\n\n")

        handle.write("## DNS activity\n")
        if dns_activity:
            handle.write("| Time | Query | Results | Status | Process | Host |\n")
            handle.write("| --- | --- | --- | --- | --- | --- |\n")
            for entry in dns_activity[:20]:
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {_md_cell(entry.get('query_name'), sanitizer)} | {_md_cell(entry.get('query_results') or '', sanitizer)} | {_md_cell(entry.get('query_status') or '', sanitizer)} | {_md_cell(entry.get('image'), sanitizer)} | {_md_cell(entry.get('host_key'), sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write("No DNS query activity observed.\n\n")

        handle.write("## Registry activity\n")
        if registry_activity:
            handle.write("| Time | Event | Target | Details / New name | Process | Host |\n")
            handle.write("| --- | --- | --- | --- | --- | --- |\n")
            for entry in registry_activity[:20]:
                value = entry.get("details") or entry.get("new_name") or ""
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {_md_cell(entry.get('registry_event_type'), sanitizer)} | {_md_cell(entry.get('target_object'), sanitizer)} | {_md_cell(value, sanitizer)} | {_md_cell(entry.get('image'), sanitizer)} | {_md_cell(entry.get('host_key'), sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write("No registry activity observed.\n\n")

        handle.write("## Process access activity\n")
        if process_access_activity:
            handle.write("| Time | Source | Target | Granted access | Host | Evidence |\n")
            handle.write("| --- | --- | --- | --- | --- | --- |\n")
            for entry in process_access_activity[:20]:
                source_ref = entry.get("source_ref") or {}
                evidence = source_ref.get("raw_digest") or source_ref.get("document_id") or ""
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {_md_cell(entry.get('source_image'), sanitizer)} | {_md_cell(entry.get('target_image'), sanitizer)} | {_md_cell(entry.get('granted_access'), sanitizer)} | {_md_cell(entry.get('host_key'), sanitizer)} | {_md_cell(evidence, sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write("No process-access activity observed.\n\n")

        handle.write("## Notes\n")
        handle.write(f"Rule IDs: {_md_cell(rule_notes, sanitizer)}\n")
