from __future__ import annotations

import csv
import json
from pathlib import Path

from typer.testing import CliRunner

from wazuh_sysmon_triage import cli

runner = CliRunner()

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
SCENARIOS = {
    "encoded_powershell": "encoded_powershell.ndjson",
    "schtasks_persistence": "schtasks_persistence.ndjson",
    "suppression_proof": "suppression_proof.ndjson",
}


def _snapshot_case(case_dir: Path) -> dict:
    stats = json.loads((case_dir / "stats.json").read_text(encoding="utf-8"))
    process_tree = json.loads((case_dir / "process_tree.json").read_text(encoding="utf-8"))
    alerts_rows: list[dict[str, str]] = []
    alerts_path = case_dir / "alerts.csv"
    if alerts_path.exists():
        text = alerts_path.read_text(encoding="utf-8").strip()
        if text:
            alerts_rows = list(csv.DictReader(text.splitlines()))

    alert_digest = [
        {
            "alert_type": row.get("alert_type", ""),
            "queue": row.get("queue", ""),
            "confidence": row.get("confidence", ""),
            "score": int(row.get("score") or 0),
        }
        for row in alerts_rows
    ]

    return {
        "schema_version": stats.get("schema_version"),
        "stats_keys": sorted(list(stats.keys())),
        "process_tree_keys": sorted(list(process_tree.keys())),
        "total_events": int(stats.get("total_events", 0)),
        "events_by_type": {
            "process_create": int((stats.get("events_by_type") or {}).get("process_create", 0)),
            "network_connect": int((stats.get("events_by_type") or {}).get("network_connect", 0)),
            "file_create": int((stats.get("events_by_type") or {}).get("file_create", 0)),
        },
        "counts": {
            "nodes": len(process_tree.get("nodes") or []),
            "edges": len(process_tree.get("edges") or []),
            "artifacts": len(process_tree.get("artifacts") or []),
            "alerts": len(alert_digest),
        },
        "alert_digest": alert_digest,
    }


def test_offline_outputs_match_golden_snapshots(tmp_path: Path) -> None:
    sample_root = Path(__file__).resolve().parents[1] / "samples" / "scenario_gym"
    out_root = tmp_path / "out"

    for snapshot_name, scenario_name in SCENARIOS.items():
        case_id = f"golden-{snapshot_name}"
        result = runner.invoke(
            cli.app,
            [
                "offline",
                "--input-ndjson",
                str(sample_root / scenario_name),
                "--out-dir",
                str(out_root),
                "--case-id",
                case_id,
            ],
        )
        assert result.exit_code == 0

        actual_snapshot = _snapshot_case(out_root / case_id)
        expected_snapshot = json.loads(
            (GOLDEN_DIR / f"{snapshot_name}.snapshot.json").read_text(encoding="utf-8")
        )
        assert actual_snapshot == expected_snapshot
