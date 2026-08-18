from __future__ import annotations

import csv
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wazuh_sysmon_triage.output_schema import OUTPUT_SCHEMA_VERSION
from wazuh_sysmon_triage.windows_paths import windows_basename


class CaseViewError(ValueError):
    """Raised when saved case evidence cannot be inspected safely."""


@dataclass(frozen=True)
class CaseArtifacts:
    case_dir: Path
    process_tree: dict[str, Any]
    timeline: list[dict[str, str]]
    alerts: list[dict[str, str]]
    stats: dict[str, Any]
    metadata: dict[str, Any]


def _schema_major(value: Any) -> int | None:
    try:
        return int(str(value).split(".", maxsplit=1)[0])
    except (TypeError, ValueError):
        return None


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CaseViewError(f"Required case artifact is missing: {path.name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CaseViewError(f"Could not read {path.name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CaseViewError(f"{path.name} must contain a JSON object")
    expected_major = _schema_major(OUTPUT_SCHEMA_VERSION)
    actual_major = _schema_major(payload.get("schema_version"))
    if actual_major is None:
        raise CaseViewError(f"{path.name} does not declare a valid schema_version")
    if actual_major != expected_major:
        raise CaseViewError(
            f"{path.name} schema {payload.get('schema_version')} is not compatible with "
            f"reader schema {OUTPUT_SCHEMA_VERSION}"
        )
    return payload


def _load_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise CaseViewError(f"Required case artifact is missing: {path.name}")
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    except (OSError, UnicodeError, csv.Error) as exc:
        raise CaseViewError(f"Could not read {path.name}: {exc}") from exc


def load_case_artifacts(case_dir: str | Path) -> CaseArtifacts:
    root = Path(case_dir).expanduser()
    if not root.is_dir():
        raise CaseViewError(f"Case directory does not exist: {root}")
    return CaseArtifacts(
        case_dir=root,
        process_tree=_load_json_object(root / "process_tree.json"),
        timeline=_load_csv_rows(root / "timeline.csv"),
        alerts=_load_csv_rows(root / "alerts.csv"),
        stats=_load_json_object(root / "stats.json"),
        metadata=_load_json_object(root / "run_metadata.json"),
    )


def _split_csv_list(value: str | None) -> list[str]:
    return [item for item in (value or "").split(";") if item]


def _optional_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _finding_payload(row: dict[str, str]) -> dict[str, Any]:
    return {
        "alert_id": row.get("alert_id") or "",
        "utc_time": row.get("utc_time") or "",
        "alert_type": row.get("alert_type") or "",
        "category": row.get("category") or "",
        "finding_kind": row.get("finding_kind") or "",
        "evidence_strength": row.get("evidence_strength") or "",
        "reason": row.get("reason") or "",
        "host_key": row.get("host_key") or "",
        "image": row.get("image") or "",
        "command_line": row.get("command_line") or None,
        "parent_image": row.get("parent_image") or None,
        "source_host_key": row.get("source_host_key") or None,
        "source_ip": row.get("source_ip") or None,
        "source_port": _optional_int(row.get("source_port")),
        "destination_ip": row.get("destination_ip") or None,
        "destination_port": _optional_int(row.get("destination_port")),
        "process_guid": row.get("process_guid") or "",
        "evidence_refs": _split_csv_list(row.get("evidence_refs")),
        "tags": _split_csv_list(row.get("tags")),
    }


def _node_key(node: dict[str, Any]) -> tuple[str, str]:
    return (str(node.get("host_key") or ""), str(node.get("guid") or ""))


def _cross_host_observables(tree: dict[str, Any]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    sources = (
        ("destination_ip", tree.get("network_activity") or [], "destination_ip", "ts"),
        ("dns_query", tree.get("dns_activity") or [], "query_name", "ts"),
        ("process_hashes", tree.get("nodes") or [], "hashes", "first_seen"),
    )
    for observable_type, rows, value_field, time_field in sources:
        for row in rows:
            value = str(row.get(value_field) or "").strip()
            host = str(row.get("host_key") or "").strip()
            if not value or not host:
                continue
            buckets[(observable_type, value.casefold())].append(
                {
                    "value": value,
                    "host_key": host,
                    "time": str(row.get(time_field) or ""),
                }
            )

    results: list[dict[str, Any]] = []
    for (observable_type, _normalized), evidence in sorted(buckets.items()):
        hosts = sorted({row["host_key"] for row in evidence})
        if len(hosts) < 2:
            continue
        results.append(
            {
                "observable_type": observable_type,
                "value": evidence[0]["value"],
                "hosts": hosts,
                "evidence_count": len(evidence),
                "first_seen": min((row["time"] for row in evidence if row["time"]), default=""),
                "last_seen": max((row["time"] for row in evidence if row["time"]), default=""),
                "interpretation": (
                    "Exact observable reuse across hosts is a scoping lead, not proof of "
                    "lateral movement. Validate authentication and remote-execution evidence."
                ),
            }
        )
    return results


def _source_scope(artifacts: CaseArtifacts) -> tuple[str, list[dict[str, Any]]]:
    metadata = artifacts.metadata
    anchor = metadata.get("investigation_anchor") or {}
    patterns = [
        anchor.get("context_index_pattern"),
        metadata.get("index_pattern"),
    ]
    indexes: set[str] = set()
    for node in artifacts.process_tree.get("nodes") or []:
        for ref in node.get("source_refs") or []:
            if ref.get("index"):
                indexes.add(str(ref["index"]))
    values = [str(item).lower() for item in patterns if item]
    values.extend(item.lower() for item in indexes)
    if any("wazuh-archives" in value for value in values):
        scope = "wazuh_archives"
    elif any("wazuh-alerts" in value for value in values):
        scope = "wazuh_alerts"
    elif metadata.get("query", {}).get("input_ndjson"):
        scope = "offline_unknown"
    else:
        scope = "unknown"

    caveats: list[dict[str, Any]] = []
    if scope == "wazuh_alerts":
        caveats.append(
            {
                "code": "alert_index_scope",
                "message": (
                    "Context came from Wazuh alert documents. Events that did not trigger a "
                    "Wazuh rule may be absent; absence is not proof that activity did not occur."
                ),
            }
        )
    elif scope in {"offline_unknown", "unknown"}:
        caveats.append(
            {
                "code": "source_scope_unknown",
                "message": (
                    "The saved case does not prove whether its input contains raw/archive events "
                    "or only Wazuh alerts. Interpret negative findings cautiously."
                ),
            }
        )
    return scope, caveats


def _collection_state(artifacts: CaseArtifacts) -> dict[str, Any]:
    stats = artifacts.stats
    metadata = artifacts.metadata
    truncation = metadata.get("truncation") or stats.get("truncation") or {}
    integrity_issues: list[dict[str, Any]] = []
    checks = (
        (
            "truncated",
            bool(truncation.get("truncated")),
            f"Collection was truncated: {truncation.get('reason') or 'unknown reason'}",
        ),
        (
            "dropped_events",
            int(metadata.get("dropped_count") or stats.get("dropped_count") or 0) > 0,
            "Some input events were dropped during normalization.",
        ),
        (
            "invalid_timestamps",
            int(
                metadata.get("invalid_timestamp_count") or stats.get("invalid_timestamp_count") or 0
            )
            > 0,
            "Some events had invalid timestamps and could not be placed reliably.",
        ),
        (
            "unsupported_events",
            int(metadata.get("unsupported_count") or stats.get("unsupported_count") or 0) > 0,
            "Some collected event types were unsupported and are absent from analysis.",
        ),
    )
    for code, failed, message in checks:
        if failed:
            integrity_issues.append({"code": code, "message": message})
    source_scope, coverage_caveats = _source_scope(artifacts)
    return {
        "integrity": "incomplete" if integrity_issues else "complete_within_query",
        "source_scope": source_scope,
        "integrity_issues": integrity_issues,
        "coverage_caveats": coverage_caveats,
    }


def build_case_overview(artifacts: CaseArtifacts) -> dict[str, Any]:
    tree = artifacts.process_tree
    findings = [_finding_payload(row) for row in artifacts.alerts]
    findings.sort(
        key=lambda row: (
            row["utc_time"],
            row["host_key"],
            row["alert_id"],
        )
    )
    nodes = tree.get("nodes") or []
    node_lookup = {_node_key(node): node for node in nodes}
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        key = (finding["host_key"], finding["process_guid"])
        if key[1]:
            grouped[key].append(finding)

    process_pivots: list[dict[str, Any]] = []
    for (host_key, process_guid), rows in sorted(grouped.items()):
        node = node_lookup.get((host_key, process_guid), {})
        process_pivots.append(
            {
                "host_key": host_key,
                "process_guid": process_guid,
                "image": node.get("image") or rows[0].get("image") or "",
                "finding_ids": [row["alert_id"] for row in rows],
                "finding_types": sorted({row["alert_type"] for row in rows}),
                "pivot_basis": "finding_linked_process",
                "command_args": [
                    "triage",
                    "process",
                    process_guid,
                    "--case-dir",
                    str(artifacts.case_dir),
                    "--host-key",
                    host_key,
                ],
            }
        )

    if not process_pivots:
        collected_nodes = sorted(
            (node for node in nodes if node.get("guid")),
            key=lambda node: (
                bool(node.get("synthetic")),
                str(node.get("first_seen") or ""),
                str(node.get("host_key") or ""),
                str(node.get("guid") or ""),
            ),
        )
        for node in collected_nodes[:20]:
            host_key = str(node.get("host_key") or "")
            process_guid = str(node.get("guid") or "")
            process_pivots.append(
                {
                    "host_key": host_key,
                    "process_guid": process_guid,
                    "image": node.get("image") or "",
                    "finding_ids": [],
                    "finding_types": [],
                    "pivot_basis": "collected_process_no_local_finding",
                    "command_args": [
                        "triage",
                        "process",
                        process_guid,
                        "--case-dir",
                        str(artifacts.case_dir),
                        "--host-key",
                        host_key,
                    ],
                }
            )

    stats = artifacts.stats
    unresolved = tree.get("unresolved_relationships") or []
    remote_activity_leads = tree.get("remote_activity_leads") or []
    return {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "view_type": "case_overview",
        "case_dir": str(artifacts.case_dir),
        "case_id": artifacts.metadata.get("case_id") or artifacts.case_dir.name,
        "collection": _collection_state(artifacts),
        "time_range": tree.get("time_range") or {},
        "hosts": tree.get("host_keys") or sorted({_node_key(node)[0] for node in nodes}),
        "counts": {
            "timeline_events": len(artifacts.timeline),
            "processes": len(nodes),
            "process_edges": len(tree.get("edges") or []),
            "unresolved_relationships": len(unresolved),
            "findings": len(findings),
            "remote_activity_leads": len(remote_activity_leads),
            "events_by_type": stats.get("events_by_type") or {},
        },
        "findings": findings,
        "process_pivots": process_pivots,
        "cross_host_observables": _cross_host_observables(tree),
        "remote_activity_leads": remote_activity_leads,
        "unresolved_relationships": unresolved,
    }


def _matches_host(value: Any, host_key: str) -> bool:
    return str(value or "").casefold() == host_key.casefold()


def _matches_guid(value: Any, process_guid: str) -> bool:
    return str(value or "").casefold() == process_guid.casefold()


def _related_activity(
    rows: list[dict[str, Any]],
    *,
    host_key: str,
    scope_guids: set[str],
    guid_fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    normalized_scope = {value.casefold() for value in scope_guids}
    selected: list[dict[str, Any]] = []
    for row in rows:
        if not _matches_host(row.get("host_key"), host_key):
            continue
        matched_fields = [
            field
            for field in guid_fields
            if str(row.get(field) or "").casefold() in normalized_scope
        ]
        if not matched_fields:
            continue
        payload = dict(row)
        payload["matched_guid_fields"] = matched_fields
        selected.append(payload)
    selected.sort(
        key=lambda row: (
            str(row.get("ts") or row.get("created_at") or ""),
            json.dumps(row, sort_keys=True),
        )
    )
    return selected


def _focused_timeline(
    rows: list[dict[str, str]],
    *,
    host_key: str,
    scope_guids: set[str],
    max_events: int,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    normalized_scope = {value.casefold() for value in scope_guids}
    matched: list[dict[str, Any]] = []
    for row in rows:
        if not _matches_host(row.get("host_key"), host_key):
            continue
        reasons: list[str] = []
        for field in ("process_guid", "parent_process_guid", "target_process_guid"):
            if str(row.get(field) or "").casefold() in normalized_scope:
                reasons.append(field)
        if not reasons:
            continue
        payload: dict[str, Any] = dict(row)
        payload["selection_reasons"] = reasons
        matched.append(payload)
    matched.sort(
        key=lambda row: (
            str(row.get("ts") or ""),
            str(row.get("event_id") or ""),
            str(row.get("source_document_id") or ""),
        )
    )
    returned = matched[:max_events]
    return returned, {
        "total_case_events": len(rows),
        "matched_process_scope": len(matched),
        "returned": len(returned),
        "omitted_by_limit": max(0, len(matched) - len(returned)),
        "excluded_as_unrelated": max(0, len(rows) - len(matched)),
    }


def _process_queries(
    node: dict[str, Any],
    *,
    unresolved: list[dict[str, Any]],
    network: list[dict[str, Any]],
) -> list[dict[str, str]]:
    process_guid = str(node.get("guid") or "")
    queries = [
        {
            "reason": "Retrieve supported activity recorded directly against this process GUID.",
            "query": (
                f'data.win.eventdata.processGuid:"{process_guid}" AND '
                'data.win.system.eventID:("1" OR "3" OR "5" OR "11" OR "12" OR "13" OR "14" OR "22" OR "23" OR "26")'
            ),
        },
        {
            "reason": "Find child processes whose recorded parent is this process.",
            "query": (
                f'data.win.eventdata.parentProcessGuid:"{process_guid}" AND '
                'data.win.system.eventID:"1"'
            ),
        },
        {
            "reason": "Find process-access events initiated by this process.",
            "query": (
                f'data.win.eventdata.sourceProcessGUID:"{process_guid}" AND '
                'data.win.system.eventID:"10"'
            ),
        },
    ]
    parent_guids = sorted(
        {str(row.get("parent_guid")) for row in unresolved if row.get("parent_guid")}
    )
    if parent_guids:
        queries.append(
            {
                "reason": "Retrieve the missing parent process-create evidence.",
                "query": f'data.win.eventdata.processGuid:"{parent_guids[0]}" AND data.win.system.eventID:"1"',
            }
        )
    destinations = sorted(
        {str(row.get("destination_ip")) for row in network if row.get("destination_ip")}
    )
    if destinations:
        queries.append(
            {
                "reason": "Check whether other processes or hosts contacted the same destination.",
                "query": f'data.win.system.eventID:"3" AND data.win.eventdata.destinationIp:"{destinations[0]}"',
            }
        )
    hashes = str(node.get("hashes") or "").strip()
    if hashes:
        queries.append(
            {
                "reason": "Search for the same recorded process hash elsewhere.",
                "query": f'data.win.eventdata.hashes:"{hashes}"',
            }
        )
    return queries[:6]


def build_process_view(
    artifacts: CaseArtifacts,
    process_guid: str,
    *,
    host_key: str | None = None,
    include_descendants: bool = True,
    max_depth: int = 5,
    max_events: int = 200,
) -> dict[str, Any]:
    if max_depth < 0:
        raise CaseViewError("max_depth must be zero or greater")
    if max_events <= 0:
        raise CaseViewError("max_events must be greater than zero")
    tree = artifacts.process_tree
    nodes = tree.get("nodes") or []
    candidates = [node for node in nodes if _matches_guid(node.get("guid"), process_guid)]
    if host_key:
        candidates = [node for node in candidates if _matches_host(node.get("host_key"), host_key)]
    if not candidates:
        suffix = f" on host {host_key}" if host_key else ""
        raise CaseViewError(f"Process GUID {process_guid} was not found{suffix}")
    if len(candidates) > 1:
        hosts = sorted({str(node.get("host_key") or "") for node in candidates})
        raise CaseViewError(
            f"Process GUID {process_guid} exists on multiple hosts; pass --host-key with one of: "
            + ", ".join(hosts)
        )
    node = candidates[0]
    selected_host = str(node.get("host_key") or "")
    selected_guid = str(node.get("guid") or "")
    nodes_by_key = {_node_key(item): item for item in nodes}
    parent_by_child: dict[tuple[str, str], str] = {}
    children_by_parent: dict[tuple[str, str], list[str]] = defaultdict(list)
    for edge in tree.get("edges") or []:
        edge_host = str(edge.get("host_key") or "")
        parent_guid = str(edge.get("parent_guid") or "")
        child_guid = str(edge.get("child_guid") or "")
        if not _matches_host(edge_host, selected_host):
            continue
        parent_by_child[(edge_host, child_guid)] = parent_guid
        children_by_parent[(edge_host, parent_guid)].append(child_guid)

    ancestry: list[dict[str, Any]] = []
    current_guid = selected_guid
    seen = {selected_guid.casefold()}
    for depth in range(1, max_depth + 1):
        linked_parent_guid = parent_by_child.get((selected_host, current_guid))
        if not linked_parent_guid or linked_parent_guid.casefold() in seen:
            break
        resolved_parent_guid = str(linked_parent_guid)
        parent = nodes_by_key.get((selected_host, resolved_parent_guid))
        if not parent:
            break
        ancestry.append({"depth": depth, **parent})
        seen.add(resolved_parent_guid.casefold())
        current_guid = resolved_parent_guid

    descendants: list[dict[str, Any]] = []
    if include_descendants and max_depth > 0:
        queue: deque[tuple[str, int]] = deque([(selected_guid, 0)])
        seen_descendants = {selected_guid.casefold()}
        while queue:
            parent_guid, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for child_guid in sorted(children_by_parent.get((selected_host, parent_guid), [])):
                if child_guid.casefold() in seen_descendants:
                    continue
                seen_descendants.add(child_guid.casefold())
                child = nodes_by_key.get((selected_host, child_guid))
                if not child:
                    continue
                descendants.append({"depth": depth + 1, **child})
                queue.append((child_guid, depth + 1))

    scope_guids = {selected_guid, *(str(item.get("guid") or "") for item in descendants)}
    artifacts_rows = _related_activity(
        tree.get("artifacts") or [],
        host_key=selected_host,
        scope_guids=scope_guids,
        guid_fields=("creating_process_guid",),
    )
    file_deletions = _related_activity(
        tree.get("file_delete_activity") or [],
        host_key=selected_host,
        scope_guids=scope_guids,
        guid_fields=("process_guid",),
    )
    network = _related_activity(
        tree.get("network_activity") or [],
        host_key=selected_host,
        scope_guids=scope_guids,
        guid_fields=("process_guid",),
    )
    registry = _related_activity(
        tree.get("registry_activity") or [],
        host_key=selected_host,
        scope_guids=scope_guids,
        guid_fields=("process_guid",),
    )
    dns = _related_activity(
        tree.get("dns_activity") or [],
        host_key=selected_host,
        scope_guids=scope_guids,
        guid_fields=("process_guid",),
    )
    process_access = _related_activity(
        tree.get("process_access_activity") or [],
        host_key=selected_host,
        scope_guids=scope_guids,
        guid_fields=("source_process_guid", "target_process_guid"),
    )
    process_terminations = _related_activity(
        tree.get("process_termination_activity") or [],
        host_key=selected_host,
        scope_guids=scope_guids,
        guid_fields=("process_guid",),
    )
    focused_timeline, selection = _focused_timeline(
        artifacts.timeline,
        host_key=selected_host,
        scope_guids=scope_guids,
        max_events=max_events,
    )
    normalized_scope = {value.casefold() for value in scope_guids}
    findings = [
        _finding_payload(row)
        for row in artifacts.alerts
        if _matches_host(row.get("host_key"), selected_host)
        and str(row.get("process_guid") or "").casefold() in normalized_scope
    ]
    findings.sort(key=lambda row: (row["utc_time"], row["alert_id"]))
    unresolved = [
        row
        for row in tree.get("unresolved_relationships") or []
        if _matches_host(row.get("host_key"), selected_host)
        and (
            str(row.get("child_guid") or "").casefold() in normalized_scope
            or str(row.get("parent_guid") or "").casefold() in normalized_scope
        )
    ]

    unknowns: list[dict[str, str]] = []
    collection = _collection_state(artifacts)
    unknowns.extend(collection["integrity_issues"])
    unknowns.extend(collection["coverage_caveats"])
    if node.get("synthetic"):
        unknowns.append(
            {
                "code": "missing_process_create",
                "message": "This process node is synthetic because no process-create event was collected.",
            }
        )
    if not node.get("terminated_at"):
        unknowns.append(
            {
                "code": "missing_process_termination",
                "message": (
                    "No process-termination event is present for this process; its end time is unknown."
                ),
            }
        )
    if unresolved:
        unknowns.append(
            {
                "code": "unresolved_process_relationship",
                "message": "At least one parent/child relationship in this process scope is unresolved.",
            }
        )
    for field, label in (
        ("cmdline", "recorded command line"),
        ("user", "recorded user"),
        ("hashes", "recorded process hash"),
        ("integrity_level", "recorded integrity level"),
    ):
        if not node.get(field):
            unknowns.append(
                {
                    "code": f"missing_{field}",
                    "message": f"The collected process evidence does not contain the {label}.",
                }
            )
    if selection["omitted_by_limit"]:
        unknowns.append(
            {
                "code": "focused_timeline_limited",
                "message": f"{selection['omitted_by_limit']} matching timeline events were omitted by --max-events.",
            }
        )

    return {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "view_type": "process_investigation",
        "case_dir": str(artifacts.case_dir),
        "case_id": artifacts.metadata.get("case_id") or artifacts.case_dir.name,
        "collection": collection,
        "process": node,
        "scope": {
            "host_key": selected_host,
            "process_guid": selected_guid,
            "include_descendants": include_descendants,
            "max_depth": max_depth,
            "process_guids": sorted(scope_guids),
        },
        "ancestry": ancestry,
        "descendants": descendants,
        "findings": findings,
        "activity": {
            "files": artifacts_rows,
            "file_deletions": file_deletions,
            "network": network,
            "registry": registry,
            "dns": dns,
            "process_access": process_access,
            "process_terminations": process_terminations,
        },
        "focused_timeline": focused_timeline,
        "selection": selection,
        "unresolved_relationships": unresolved,
        "unknowns": unknowns,
        "recommended_pivots": _process_queries(
            node,
            unresolved=unresolved,
            network=network,
        ),
    }


def render_case_overview_text(view: dict[str, Any]) -> str:
    collection = view["collection"]
    counts = view["counts"]
    lines = [
        f"Case: {view['case_id']}",
        f"Evidence scope: {collection['source_scope']}",
        f"Collection integrity: {collection['integrity']}",
        f"Hosts: {len(view['hosts'])}",
        f"Timeline events: {counts['timeline_events']}",
        f"Processes: {counts['processes']} ({counts['unresolved_relationships']} unresolved relationships)",
        f"Behavior findings: {counts['findings']}",
        f"Remote-activity leads: {counts.get('remote_activity_leads', 0)}",
    ]
    warnings = collection["integrity_issues"] + collection["coverage_caveats"]
    if warnings:
        lines.append("Evidence caveats:")
        lines.extend(f"  - {item['message']}" for item in warnings)
    lines.append("Findings:")
    if view["findings"]:
        for finding in view["findings"]:
            lines.append(
                f"  - {finding['alert_id']} [{finding['evidence_strength']}] "
                f"{finding['alert_type']} {windows_basename(finding['image'])}"
            )
    else:
        lines.append("  - No local behavior rules matched.")

    lines.append("")
    lines.append("Remote-activity leads")
    if view.get("remote_activity_leads"):
        for lead in view["remote_activity_leads"]:
            source = lead.get("source_host_key") or lead.get("source_ip") or "unresolved"
            lines.append(
                f"- [{lead.get('evidence_strength', 'unresolved')}] "
                f"{source} -> {lead.get('target_host_key', 'unknown')} "
                f"{lead.get('action_type', 'action')}={lead.get('action_resource', '')}"
            )
            lines.append(f"  {lead.get('reason', '')}")
    else:
        lines.append("- none reconstructed")
    lines.append("Process pivots:")
    if view["process_pivots"]:
        for pivot in view["process_pivots"]:
            findings = ",".join(pivot["finding_ids"]) or "none"
            lines.append(
                f"  - {pivot['process_guid']} host={pivot['host_key']} "
                f"image={windows_basename(pivot['image'])} findings={findings} "
                f"basis={pivot['pivot_basis']}"
            )
    else:
        lines.append("  - No finding-linked process pivots are available.")
    lines.append("Cross-host observable leads:")
    if view["cross_host_observables"]:
        for lead in view["cross_host_observables"]:
            lines.append(
                f"  - {lead['observable_type']}={lead['value']} "
                f"hosts={','.join(lead['hosts'])} (scoping lead; not proof of lateral movement)"
            )
    else:
        lines.append("  - No exact domain, destination, or process-hash reuse across hosts.")
    return "\n".join(lines)


def render_process_view_text(view: dict[str, Any]) -> str:
    node = view["process"]
    selection = view["selection"]
    activity = view["activity"]
    lines = [
        f"Process: {node.get('image') or 'unknown'}",
        f"GUID: {node.get('guid') or 'unknown'}",
        f"Host: {node.get('host_key') or 'unknown'}",
        f"PID: {node.get('pid') if node.get('pid') is not None else 'unknown'}",
        f"User: {node.get('user') or 'unknown'}",
        f"Command: {node.get('cmdline') or 'unknown'}",
        "Ancestry:",
    ]
    if view["ancestry"]:
        for ancestor in reversed(view["ancestry"]):
            lines.append(
                f"  - depth={ancestor['depth']} {windows_basename(ancestor.get('image'))} "
                f"{ancestor.get('guid')}"
            )
    else:
        lines.append("  - No resolved ancestor is present in the case.")
    lines.append(f"Descendants: {len(view['descendants'])}")
    lines.append(
        "Activity: "
        f"files={len(activity['files'])} file_deletions={len(activity['file_deletions'])} "
        f"network={len(activity['network'])} "
        f"registry={len(activity['registry'])} dns={len(activity['dns'])} "
        f"process_access={len(activity['process_access'])} "
        f"terminations={len(activity['process_terminations'])}"
    )
    lines.append(f"Findings: {len(view['findings'])}")
    for finding in view["findings"]:
        lines.append(
            f"  - {finding['alert_id']} [{finding['evidence_strength']}] "
            f"{finding['alert_type']}: {finding['reason']}"
        )
    lines.append(
        "Focused timeline: "
        f"returned={selection['returned']} matched={selection['matched_process_scope']} "
        f"excluded_unrelated={selection['excluded_as_unrelated']}"
    )
    for event in view["focused_timeline"]:
        subject = (
            event.get("target_filename")
            or event.get("target_object")
            or event.get("query_name")
            or event.get("destination_ip")
            or event.get("target_image")
            or event.get("image")
            or ""
        )
        lines.append(
            f"  - {event.get('ts')} EID {event.get('event_id')} "
            f"{windows_basename(event.get('image'))} {subject}"
        )
    if view["unknowns"]:
        lines.append("Unknowns and caveats:")
        lines.extend(f"  - {item['message']}" for item in view["unknowns"])
    lines.append("Recommended Wazuh pivots:")
    lines.extend(
        f"  - {item['reason']}\n    {item['query']}" for item in view["recommended_pivots"]
    )
    return "\n".join(lines)
