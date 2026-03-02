from __future__ import annotations

import json
import shutil
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

TELEMETRY_HISTORY_FILE = "telemetry_history.ndjson"
TELEMETRY_SUMMARY_FILE = "telemetry_summary.json"
_TELEMETRY_LOCKS: dict[str, threading.Lock] = {}
_TELEMETRY_LOCKS_GUARD = threading.Lock()


def parse_optional_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def _to_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed


def _percentile(values: list[int], percentile: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    interpolated = ordered[lower] + (ordered[upper] - ordered[lower]) * weight
    return int(round(interpolated))


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


def _write_text_atomic(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    tmp_path.write_text(payload, encoding="utf-8")
    tmp_path.replace(path)


def _get_telemetry_lock(root: Path) -> threading.Lock:
    lock_key = str(root.resolve())
    with _TELEMETRY_LOCKS_GUARD:
        lock = _TELEMETRY_LOCKS.get(lock_key)
        if lock is None:
            lock = threading.Lock()
            _TELEMETRY_LOCKS[lock_key] = lock
        return lock


def _read_json_lines(path: Path, max_entries: int = 5000) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    if len(rows) > max_entries:
        rows = rows[-max_entries:]
        _write_text_atomic(path, "\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n")
    return rows


def build_telemetry_summary(history: list[dict[str, Any]]) -> dict[str, Any]:
    total_runs = len(history)
    successful = [row for row in history if bool(row.get("success"))]
    failed = [row for row in history if not bool(row.get("success"))]

    stage_keys = ("fetch", "normalize", "correlate", "detect", "render")
    stage_latency_percentiles: dict[str, dict[str, int]] = {}
    for stage in stage_keys:
        samples = [
            _to_int((row.get("stage_durations") or {}).get(stage), 0)
            for row in successful
            if _to_int((row.get("stage_durations") or {}).get(stage), 0) >= 0
        ]
        stage_latency_percentiles[stage] = {
            "p50_ms": _percentile(samples, 0.50),
            "p95_ms": _percentile(samples, 0.95),
        }

    failure_reasons: dict[str, int] = {}
    for row in failed:
        reason = str(row.get("failure_reason") or "unknown_failure").strip() or "unknown_failure"
        failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
    top_failure_reasons = [
        {"reason": reason, "count": count}
        for reason, count in sorted(failure_reasons.items(), key=lambda item: (-item[1], item[0]))[:5]
    ]

    successful_live_runs = [
        row
        for row in successful
        if str(row.get("mode") or "").lower() == "live"
    ]
    last_successful_live_fetch_at = None
    if successful_live_runs:
        last_successful_live_fetch_at = max(str(row.get("ts") or "") for row in successful_live_runs)

    return {
        "generated_at": _now_iso(),
        "total_runs": total_runs,
        "successful_runs": len(successful),
        "failed_runs": len(failed),
        "success_rate": round((len(successful) / total_runs), 4) if total_runs else 0.0,
        "stage_latency_percentiles": stage_latency_percentiles,
        "top_failure_reasons": top_failure_reasons,
        "last_successful_live_fetch_at": last_successful_live_fetch_at,
    }


def record_run_telemetry(
    *,
    out_root: str | Path,
    run_id: str,
    case_id: str | None,
    mode: str,
    profile: str | None,
    success: bool,
    stage_durations: dict[str, int],
    total_duration_ms: int,
    failure_reason: str | None = None,
) -> dict[str, Any]:
    root = Path(out_root)
    root.mkdir(parents=True, exist_ok=True)
    lock = _get_telemetry_lock(root)

    history_path = root / TELEMETRY_HISTORY_FILE
    summary_path = root / TELEMETRY_SUMMARY_FILE
    record = {
        "ts": _now_iso(),
        "run_id": run_id,
        "case_id": case_id,
        "mode": mode,
        "profile": profile,
        "success": success,
        "stage_durations": {key: _to_int(value, 0) for key, value in stage_durations.items()},
        "total_duration_ms": max(_to_int(total_duration_ms, 0), 0),
        "failure_reason": failure_reason if failure_reason else None,
    }

    with lock:
        with history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")

        history = _read_json_lines(history_path)
        summary = build_telemetry_summary(history)
        _write_text_atomic(summary_path, json.dumps(summary, indent=2))
        return summary


def _directory_size_bytes(directory: Path) -> int:
    total = 0
    for path in directory.rglob("*"):
        if path.is_file():
            try:
                total += path.stat().st_size
            except OSError:
                continue
    return total


@dataclass
class _CaseDirInfo:
    case_id: str
    path: Path
    mtime: datetime
    size_bytes: int


def _collect_case_dirs(out_root: Path, current_case_id: str | None) -> list[_CaseDirInfo]:
    if not out_root.exists():
        return []
    items: list[_CaseDirInfo] = []
    for entry in out_root.iterdir():
        if not entry.is_dir():
            continue
        if entry.is_symlink():
            continue
        if entry.name.startswith("."):
            continue
        if current_case_id and entry.name == current_case_id:
            continue
        if not (entry / "run_metadata.json").exists():
            continue
        try:
            mtime = datetime.fromtimestamp(entry.stat().st_mtime, tz=UTC)
        except OSError:
            continue
        items.append(
            _CaseDirInfo(
                case_id=entry.name,
                path=entry,
                mtime=mtime,
                size_bytes=_directory_size_bytes(entry),
            )
        )
    return items


def apply_artifact_retention(
    *,
    out_root: str | Path,
    current_case_id: str | None,
    policy: dict[str, Any] | None,
) -> dict[str, Any]:
    policy = policy or {}
    enabled = bool(policy.get("enabled", False))
    if not enabled:
        return {
            "enabled": False,
            "removed_cases": [],
            "removed_bytes": 0,
            "remaining_case_count": 0,
            "reason": "disabled",
        }

    max_age_days_raw = policy.get("max_age_days")
    max_total_size_mb_raw = policy.get("max_total_size_mb")
    max_age_days = _to_int(max_age_days_raw, 0) if max_age_days_raw is not None else 0
    max_total_size_mb = _to_int(max_total_size_mb_raw, 0) if max_total_size_mb_raw is not None else 0
    min_keep_runs = max(_to_int(policy.get("min_keep_runs"), 5), 0)

    root = Path(out_root)
    entries = _collect_case_dirs(root, current_case_id=current_case_id)
    if not entries:
        return {
            "enabled": True,
            "removed_cases": [],
            "removed_bytes": 0,
            "remaining_case_count": 0,
            "reason": "no_case_dirs",
        }

    newest_first = sorted(entries, key=lambda item: item.mtime, reverse=True)
    protected = {item.case_id for item in newest_first[:min_keep_runs]}
    remove_ids: set[str] = set()

    if max_age_days > 0:
        cutoff = datetime.now(tz=UTC) - timedelta(days=max_age_days)
        for item in sorted(entries, key=lambda case: case.mtime):
            if item.case_id in protected:
                continue
            if item.mtime < cutoff:
                remove_ids.add(item.case_id)

    size_limit_bytes = max_total_size_mb * 1024 * 1024 if max_total_size_mb > 0 else 0
    if size_limit_bytes > 0:
        remaining = [item for item in entries if item.case_id not in remove_ids]
        total_size = sum(item.size_bytes for item in remaining)
        if total_size > size_limit_bytes:
            for item in sorted(remaining, key=lambda case: case.mtime):
                if total_size <= size_limit_bytes:
                    break
                if item.case_id in protected:
                    continue
                remove_ids.add(item.case_id)
                total_size -= item.size_bytes

    removed_cases: list[str] = []
    removed_bytes = 0
    by_case_id = {item.case_id: item for item in entries}
    for case_id in sorted(remove_ids):
        case_info = by_case_id.get(case_id)
        if case_info is None:
            continue
        try:
            shutil.rmtree(case_info.path)
        except OSError:
            continue
        removed_cases.append(case_id)
        removed_bytes += case_info.size_bytes

    remaining_count = max(len(entries) - len(removed_cases), 0)
    return {
        "enabled": True,
        "removed_cases": removed_cases,
        "removed_bytes": removed_bytes,
        "remaining_case_count": remaining_count,
        "reason": "applied",
        "policy": {
            "max_age_days": max_age_days if max_age_days > 0 else None,
            "max_total_size_mb": max_total_size_mb if max_total_size_mb > 0 else None,
            "min_keep_runs": min_keep_runs,
        },
    }
