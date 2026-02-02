from __future__ import annotations

import csv
import json
import os
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from wazuh_sysmon_triage.models.findings import Artifact, IncidentSummary, ProcessEdge, ProcessNode
from wazuh_sysmon_triage.models.sysmon import SysmonEvent


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _iso_z(value: datetime | None) -> str:
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(UTC)
    return value.isoformat().replace("+00:00", "Z")


def render_timeline(data: Sequence[SysmonEvent], output_dir: str) -> None:
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
                    getattr(event, "image", "") or "",
                    getattr(event, "command_line", "") or "",
                    getattr(event, "parent_image", "") or "",
                    getattr(event, "target_filename", "") or "",
                    getattr(event, "user", "") or "",
                    getattr(event, "rule_id", "") or "",
                    getattr(event, "agent_name", "") or "",
                    getattr(event, "agent_id", "") or "",
                ]
            )


def render_process_tree(data: dict, output_dir: str) -> None:
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

    nodes_sorted = sorted(nodes, key=lambda node: node.first_seen)
    edges_sorted = sorted(edges, key=lambda edge: (edge.parent_guid, edge.child_guid))
    artifacts_sorted = sorted(artifacts, key=lambda art: art.created_at)

    payload = {
        "agent": {
            "name": summary.agent if summary else None,
        },
        "time_range": {
            "start": _iso_z(summary.time_range[0]) if summary else "",
            "end": _iso_z(summary.time_range[1]) if summary else "",
        },
        "nodes": [node.model_dump(mode="json") for node in nodes_sorted],
        "edges": [edge.model_dump(mode="json") for edge in edges_sorted],
        "artifacts": [artifact.model_dump(mode="json") for artifact in artifacts_sorted],
    }

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def render_report(data: dict, output_dir: str) -> None:
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
    truncation: dict | None = data.get("truncation")
    network_activity: list[dict] = data.get("network_activity", [])

    time_range = summary.time_range if summary else (None, None)
    agent_name = summary.agent if summary else None

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
            f"| {artifact.path} | {_iso_z(artifact.created_at)} | {artifact.creating_image or ''} | {artifact.confidence.value} |"
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
        handle.write("\n")
        handle.write(f"**Timeframe:** {_iso_z(time_range[0])} → {_iso_z(time_range[1])}\n\n")
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
            handle.write(f"- {bullet}\n")
        handle.write("\n")

        handle.write("## Observed process chains\n")
        if chains:
            for chain in chains:
                handle.write(f"- {chain}\n")
        else:
            handle.write("- No process chains available.\n")
        handle.write("\n")

        handle.write("## Artifacts & IOCs\n")
        handle.write("\n".join(artifacts_rows) + "\n\n")

        handle.write("## Detections\n")
        handle.write(f"{mitre_section}\n\n")

        handle.write("## Network activity\n")
        if network_activity:
            handle.write("| Time | Destination | Port | Protocol | Image | Suspicious | Reason |\n")
            handle.write("| --- | --- | --- | --- | --- | --- | --- |\n")
            for entry in network_activity[:10]:
                handle.write(
                    f"| {_iso_z(entry.get('ts'))} | {entry.get('destination_ip')} | {entry.get('destination_port')} | {entry.get('protocol') or ''} | {entry.get('image')} | {entry.get('suspicious')} | {entry.get('reason') or ''} |\n"
                )
            handle.write("\n")
        else:
            handle.write("No network activity observed.\n\n")

        handle.write("## Notes\n")
        handle.write(f"Rule IDs: {rule_notes}\n")
