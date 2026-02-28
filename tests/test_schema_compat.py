from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from wazuh_sysmon_triage import cli

runner = CliRunner()


def _to_int(value: Any, fallback: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return fallback
    return parsed


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _infer_category(alert_type: str) -> str:
    normalized = alert_type.lower()
    if "powershell" in normalized or "malware" in normalized:
        return "malware_execution"
    if "outbound" in normalized or "network" in normalized or "c2" in normalized:
        return "c2_outbound"
    if "schtasks" in normalized or "persist" in normalized:
        return "persistence"
    if "policy" in normalized or "allowlist" in normalized:
        return "policy_violation"
    if "dev" in normalized:
        return "developer_tooling"
    return "unknown"


def _infer_queue(category: str) -> str:
    if category in {"malware_execution", "c2_outbound"}:
        return "soc_malware"
    if category == "developer_tooling":
        return "soc_dev"
    if category == "policy_violation":
        return "soc_policy"
    return "soc_policy"


def _infer_confidence(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def test_legacy_derivation_truth_table() -> None:
    truth_table = [
        {
            "alert_type": "powershell_obfuscation",
            "score": 95,
            "category": "malware_execution",
            "queue": "soc_malware",
            "confidence": "high",
        },
        {
            "alert_type": "outbound_public_connection",
            "score": 70,
            "category": "c2_outbound",
            "queue": "soc_malware",
            "confidence": "medium",
        },
        {
            "alert_type": "schtasks_persistence",
            "score": 49,
            "category": "persistence",
            "queue": "soc_policy",
            "confidence": "low",
        },
        {
            "alert_type": "policy_allowlist_violation",
            "score": 80,
            "category": "policy_violation",
            "queue": "soc_policy",
            "confidence": "high",
        },
        {
            "alert_type": "dev_tool_spawn",
            "score": 50,
            "category": "developer_tooling",
            "queue": "soc_dev",
            "confidence": "medium",
        },
        {
            "alert_type": "totally_unknown_signal",
            "score": 10,
            "category": "unknown",
            "queue": "soc_policy",
            "confidence": "low",
        },
    ]

    for row in truth_table:
        category = _infer_category(row["alert_type"])
        queue = _infer_queue(category)
        confidence = _infer_confidence(int(row["score"]))
        assert category == row["category"]
        assert queue == row["queue"]
        assert confidence == row["confidence"]


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    return list(csv.DictReader(text.splitlines()))


def _load_case_for_ui(case_dir: Path) -> dict[str, Any]:
    metadata = _read_json(case_dir / "run_metadata.json")
    stats_raw = _read_json(case_dir / "stats.json")
    query_raw = _read_json(case_dir / "query.json")
    process_tree_raw = _read_json(case_dir / "process_tree.json")
    alerts_raw = _read_csv(case_dir / "alerts.csv")
    timeline_raw = _read_csv(case_dir / "timeline.csv")

    alerts = []
    for idx, row in enumerate(alerts_raw, start=1):
        score = _to_int(row.get("score"), 0)
        alert_type = _safe_text(row.get("alert_type"))
        category = _safe_text(row.get("category")) or _infer_category(alert_type)
        alert = {
            "alert_id": _safe_text(row.get("alert_id")) or f"A{idx:03d}",
            "utc_time": _safe_text(row.get("utc_time")),
            "score": score,
            "alert_type": alert_type,
            "category": category,
            "queue": _safe_text(row.get("queue")) or _infer_queue(category),
            "confidence": _safe_text(row.get("confidence")) or _infer_confidence(score),
            "reason": _safe_text(row.get("reason")),
            "routing_why": _safe_text(row.get("routing_why")),
            "image": _safe_text(row.get("image")),
            "command_line": _safe_text(row.get("command_line")),
            "parent_image": _safe_text(row.get("parent_image")),
            "destination_ip": _safe_text(row.get("destination_ip")),
            "destination_port": _to_int(row.get("destination_port"), 0) if row.get("destination_port") else None,
            "process_guid": _safe_text(row.get("process_guid")),
            "tags": [t for t in _safe_text(row.get("tags")).split(";") if t],
        }
        alerts.append(alert)

    process_tree = {
        "schema_version": _safe_text(process_tree_raw.get("schema_version")) or "1.1.0",
        "agent": process_tree_raw.get("agent") or {"name": "", "id": ""},
        "time_range": process_tree_raw.get("time_range") or {"start": "", "end": ""},
        "nodes": process_tree_raw.get("nodes") or [],
        "edges": process_tree_raw.get("edges") or [],
        "artifacts": process_tree_raw.get("artifacts") or [],
    }

    query = {
        "index": _safe_text(query_raw.get("index")) or _safe_text(metadata.get("index_pattern")) or "wazuh-alerts-*",
        "start": _safe_text(metadata.get("start")),
        "end": _safe_text(metadata.get("end")),
        "event_ids": [1, 3, 11],
        "size": _to_int(query_raw.get("size"), 10000),
    }

    stats = {
        "total_events": _to_int(stats_raw.get("total_events"), _to_int(metadata.get("counts", {}).get("normalized_events"), len(timeline_raw))),
        "alerts_generated": _to_int(metadata.get("counts", {}).get("alerts"), len(alerts)),
        "alerts_suppressed": _to_int(stats_raw.get("suppressed_alerts"), _to_int(metadata.get("counts", {}).get("suppressed_alerts"), 0)),
        "suppression_hits": stats_raw.get("suppression_hits") or {},
        "dropped_events": _to_int(stats_raw.get("dropped_count"), 0),
        "dropped_by_reason": stats_raw.get("dropped_by_reason") or {},
        "network_connections": _to_int((stats_raw.get("events_by_type") or {}).get("network_connect"), 0),
    }

    return {
        "case_id": _safe_text(metadata.get("case_id")) or case_dir.name,
        "schema_version": _safe_text(metadata.get("schema_version")) or process_tree["schema_version"] or "1.1.0",
        "alerts": alerts,
        "timeline": timeline_raw,
        "process_tree": process_tree,
        "query": query,
        "stats": stats,
    }


def _write_legacy_case(case_dir: Path) -> None:
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "run_metadata.json").write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "case_id": case_dir.name,
                "profile": "soc",
                "start": "2026-02-18T19:15:54Z",
                "end": "2026-02-19T19:15:54Z",
                "counts": {"normalized_events": 2, "alerts": 1, "suppressed_alerts": 1},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (case_dir / "stats.json").write_text(
        json.dumps(
            {
                "hits": 2,
                "events_by_type": {"process_create": 1, "file_create": 1},
                "suppression_hits": {"allowlist:chrome.exe": 1},
                "truncation": {"truncated": False, "reason": None},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (case_dir / "query.json").write_text(
        json.dumps(
            {
                "size": 1000,
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": "2026-02-18T19:15:54Z",
                                        "lte": "2026-02-19T19:15:54Z",
                                    }
                                }
                            }
                        ]
                    }
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (case_dir / "process_tree.json").write_text(
        json.dumps(
            {
                "agent": {"name": "anon"},
                "time_range": {"start": "2026-02-18T19:15:54Z", "end": "2026-02-19T19:15:54Z"},
                "nodes": [],
                "edges": [],
                "artifacts": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (case_dir / "alerts.csv").write_text(
        "\n".join(
            [
                "utc_time,score,alert_type,reason,image,command_line,parent_image,destination_ip,destination_port,process_guid,tags",
                "2026-02-18T20:03:55Z,25,powershell_suspicious_execution,No-profile flag,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,powershell.exe -NoProfile,C:\\Windows\\explorer.exe,,,{LEG-PS},batcave;powershell",
            ]
        ),
        encoding="utf-8",
    )
    (case_dir / "timeline.csv").write_text(
        "\n".join(
            [
                "ts,event_id,image,command_line,parent_image,target_filename,user,rule_id,agent_name,agent_id",
                "2026-02-18T20:03:55Z,1,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,powershell.exe -NoProfile,C:\\Windows\\explorer.exe,,HOST\\legacy,92203,anon,010",
            ]
        ),
        encoding="utf-8",
    )
    (case_dir / "report.md").write_text("# Legacy report\n", encoding="utf-8")


def test_schema_compat_current_and_legacy_case_folders(tmp_path: Path) -> None:
    out_root = tmp_path / "out"
    out_root.mkdir()
    current_case_id = "schema-current-001"

    sample_path = (
        Path(__file__).resolve().parents[1] / "samples" / "scenario_gym" / "encoded_powershell.ndjson"
    )
    result = runner.invoke(
        cli.app,
        [
            "offline",
            "--input-ndjson",
            str(sample_path),
            "--out-dir",
            str(out_root),
            "--case-id",
            current_case_id,
        ],
    )
    assert result.exit_code == 0

    legacy_case_id = "incident-live-online-alert"
    _write_legacy_case(out_root / legacy_case_id)

    for case_id in [current_case_id, legacy_case_id]:
        payload = _load_case_for_ui(out_root / case_id)
        assert payload["schema_version"]
        assert isinstance(payload["alerts"], list)
        assert isinstance(payload["timeline"], list)
        assert isinstance(payload["process_tree"], dict)
        assert isinstance(payload["query"], dict)
        assert isinstance(payload["stats"], dict)

        for alert in payload["alerts"]:
            assert "category" in alert and alert["category"]
            assert "queue" in alert and alert["queue"]
            assert "confidence" in alert and alert["confidence"]
            assert "routing_why" in alert
            assert "tags" in alert and isinstance(alert["tags"], list)
