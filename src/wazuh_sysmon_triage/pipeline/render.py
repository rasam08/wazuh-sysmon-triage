from __future__ import annotations

import csv
import json
import os
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from wazuh_sysmon_triage.models.alerts import Alert
from wazuh_sysmon_triage.models.findings import Artifact, IncidentSummary, ProcessEdge, ProcessNode
from wazuh_sysmon_triage.models.sysmon import SysmonEvent
from wazuh_sysmon_triage.output_schema import OUTPUT_SCHEMA_VERSION
from wazuh_sysmon_triage.sanitize import OutputSanitizer


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _iso_z(value: datetime | None) -> str:
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(UTC)
    return value.isoformat().replace("+00:00", "Z")


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
                "event_id",
                "image",
                "command_line",
                "parent_image",
                "target_filename",
                "user",
                "rule_id",
                "agent_name",
                "agent_id",
            ]
        )
        for event in data:
            writer.writerow(
                [
                    _iso_z(event.timestamp),
                    event.event_id,
                    _maybe_sanitize(getattr(event, "image", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "command_line", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "parent_image", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "target_filename", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "user", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "rule_id", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "agent_name", "") or "", sanitizer),
                    _maybe_sanitize(getattr(event, "agent_id", "") or "", sanitizer),
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

    nodes_sorted = sorted(nodes, key=lambda node: (node.first_seen, node.guid))
    edges_sorted = sorted(edges, key=lambda edge: (edge.parent_guid, edge.child_guid))
    artifacts_sorted = sorted(artifacts, key=lambda art: (art.created_at, art.path))

    payload = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "agent": {
            "name": summary.agent if summary else None,
            "id": summary.agent_id if summary else None,
        },
        "time_range": {
            "start": _iso_z(summary.time_range[0]) if summary else "",
            "end": _iso_z(summary.time_range[1]) if summary else "",
        },
        "nodes": [node.model_dump(mode="json") for node in nodes_sorted],
        "edges": [edge.model_dump(mode="json") for edge in edges_sorted],
        "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts_sorted],
    }
    if sanitizer:
        payload = sanitizer.sanitize_obj(payload)

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


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
                "score",
                "alert_type",
                "category",
                "queue",
                "confidence",
                "reason",
                "routing_why",
                "image",
                "command_line",
                "parent_image",
                "destination_ip",
                "destination_port",
                "process_guid",
                "tags",
            ]
        )
        for alert in alerts:
            writer.writerow(
                [
                    _maybe_sanitize(alert.alert_id, sanitizer),
                    _iso_z(alert.utc_time),
                    alert.score,
                    _maybe_sanitize(alert.alert_type, sanitizer),
                    _maybe_sanitize(alert.category, sanitizer),
                    _maybe_sanitize(alert.queue, sanitizer),
                    _maybe_sanitize(alert.confidence, sanitizer),
                    _maybe_sanitize(alert.reason, sanitizer),
                    _maybe_sanitize(alert.routing_why or "", sanitizer),
                    _maybe_sanitize(alert.image, sanitizer),
                    _maybe_sanitize(alert.command_line or "", sanitizer),
                    _maybe_sanitize(alert.parent_image or "", sanitizer),
                    sanitizer.sanitize_ip(alert.destination_ip)
                    if sanitizer
                    else (alert.destination_ip or ""),
                    alert.destination_port if alert.destination_port is not None else "",
                    _maybe_sanitize(alert.process_guid, sanitizer),
                    _maybe_sanitize(";".join(alert.tags), sanitizer),
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


def _wazuh_queries(alert: Alert, sanitizer: OutputSanitizer | None = None) -> list[str]:
    process_guid = _maybe_sanitize(alert.process_guid, sanitizer)
    destination_ip = (
        sanitizer.sanitize_ip(alert.destination_ip) if sanitizer else alert.destination_ip
    )
    image = _maybe_sanitize(alert.image, sanitizer)

    queries: list[str] = []
    if process_guid:
        queries.append(
            f'data.win.eventdata.processGuid:"{process_guid}" AND data.win.system.eventID:"1"'
        )
        queries.append(
            f'data.win.eventdata.processGuid:"{process_guid}" AND data.win.system.eventID:"3"'
        )
        queries.append(
            f'data.win.eventdata.parentProcessGuid:"{process_guid}" AND data.win.system.eventID:"1"'
        )
    if destination_ip:
        queries.append(
            f'data.win.system.eventID:"3" AND data.win.eventdata.destinationIp:"{destination_ip}" AND data.win.eventdata.image:"*{os.path.basename(image or "")}"'
        )
    if image:
        queries.append(
            f'data.win.eventdata.image:"*{os.path.basename(image)}" AND data.win.system.eventID:("1" OR "3")'
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
    alerts: list[Alert] = data.get("alerts", [])

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
            "Timeline constructed from Sysmon EID 1 and 11.",
            "No additional narrative available.",
        ]

    exec_bullets = exec_bullets[:6]

    node_by_guid = {node.guid: node for node in nodes_list}
    artifacts_by_creator = {
        artifact.creating_process_guid
        for artifact in artifacts_list
        if artifact.creating_process_guid
    }

    chain_scores: list[tuple[int, str]] = []
    for edge in edges_list:
        parent = node_by_guid.get(edge.parent_guid)
        child = node_by_guid.get(edge.child_guid)
        if parent and child:
            score = 0
            if parent.guid in artifacts_by_creator or child.guid in artifacts_by_creator:
                score += 2
            if os.path.basename(parent.image).lower() in {
                "powershell.exe",
                "pwsh.exe",
                "cscript.exe",
                "wscript.exe",
                "python.exe",
            }:
                score += 1
            if os.path.basename(child.image).lower() in {
                "powershell.exe",
                "pwsh.exe",
                "cscript.exe",
                "wscript.exe",
                "python.exe",
            }:
                score += 1
            chain_scores.append(
                (score, f"{os.path.basename(parent.image)} -> {os.path.basename(child.image)}")
            )

    chains = [chain for _, chain in sorted(chain_scores, key=lambda item: item[0], reverse=True)][
        :3
    ]

    artifacts_rows = [
        "| Path | Created At | Creator Image | Confidence |",
        "| --- | --- | --- | --- |",
    ]
    for artifact in artifacts_list:
        artifacts_rows.append(
            f"| {_md_cell(artifact.path, sanitizer)} | {_iso_z(artifact.created_at)} | {_md_cell(artifact.creating_image or '', sanitizer)} | {_md_cell(artifact.confidence.value, sanitizer)} |"
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

        if truncation and truncation.get("truncated"):
            handle.write(
                "WARNING: Results truncated due to max-events guardrail; expand time range filtering or increase limits.\n\n"
                if truncation.get("reason") == "max-events"
                else "WARNING: Results truncated due to max-pages guardrail; increase paging limits or narrow time range.\n\n"
            )

        handle.write("## Executive summary\n")
        for bullet in exec_bullets:
            handle.write(f"- {_md_cell(bullet, sanitizer)}\n")
        handle.write("\n")

        handle.write("## Alerts\n")
        if alerts:
            queue_counts: dict[str, int] = {}
            for alert in alerts:
                queue_counts[alert.queue] = queue_counts.get(alert.queue, 0) + 1

            handle.write("### Queue summary\n")
            handle.write("| Queue | Count |\n")
            handle.write("| --- | --- |\n")
            for queue_name in sorted(queue_counts):
                handle.write(
                    f"| {_md_cell(queue_name, sanitizer)} | {queue_counts[queue_name]} |\n"
                )
            handle.write("\n")

            handle.write(
                "| Score | Time | Type | Category | Queue | Confidence | Reason | Routing Why | Image | Command | Destination | Process GUID | Tags |\n"
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
                handle.write(
                    f"| {alert.score} | {_iso_z(alert.utc_time)} | {_md_cell(alert.alert_type, sanitizer)} | {_md_cell(alert.category, sanitizer)} | {_md_cell(alert.queue, sanitizer)} | {_md_cell(alert.confidence, sanitizer)} | {_md_cell(alert.reason, sanitizer)} | {_md_cell(alert.routing_why or '', sanitizer)} | {_md_cell(alert.image, sanitizer)} | {_md_cell(alert.command_line or '', sanitizer)} | {_md_cell(destination, sanitizer)} | {_md_cell(alert.process_guid, sanitizer)} | {_md_cell(';'.join(alert.tags), sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write("No alerts at the configured threshold.\n\n")

        handle.write("## Wazuh Pivot Queries\n")
        if alerts:
            for alert in alerts[:3]:
                handle.write(
                    f"- {_md_cell(alert.alert_id or '', sanitizer)} {_md_cell(alert.alert_type, sanitizer)} ({alert.score})\n"
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

        handle.write("## Artifacts & IOCs\n")
        handle.write("\n".join(artifacts_rows) + "\n\n")

        handle.write("## Detections\n")
        handle.write(f"{_md_cell(mitre_section, sanitizer)}\n\n")

        handle.write("## Network activity\n")
        if network_activity:
            handle.write("| Time | Destination | Port | Protocol | Image | Suspicious | Reason |\n")
            handle.write("| --- | --- | --- | --- | --- | --- | --- |\n")
            for entry in network_activity[:10]:
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {_md_cell(entry.get('destination_ip'), sanitizer)} | {_md_cell(entry.get('destination_port'), sanitizer)} | {_md_cell(entry.get('protocol') or '', sanitizer)} | {_md_cell(entry.get('image'), sanitizer)} | {_md_cell(entry.get('suspicious'), sanitizer)} | {_md_cell(entry.get('reason') or '', sanitizer)} |\n"
                )
            handle.write("\n")
        else:
            handle.write("No network activity observed.\n\n")

        handle.write("## Notes\n")
        handle.write(f"Rule IDs: {_md_cell(rule_notes, sanitizer)}\n")
