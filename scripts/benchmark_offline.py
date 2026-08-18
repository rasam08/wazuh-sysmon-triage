from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from wazuh_sysmon_triage.corpus import ACCEPTANCE_SEED, iter_mixed_hits  # noqa: E402

_STABLE_ARTIFACTS = {"timeline.csv", "process_tree.json", "alerts.csv"}


def _write_source(
    path: Path,
    *,
    source_events: int,
    selected_events: int,
    seed: int,
) -> int:
    """Write selected realistic records plus a compact deterministic uninspected tail."""
    realistic_count = min(source_events, selected_events + 1)
    written = 0
    with path.open("wb") as handle:
        for hit in iter_mixed_hits(realistic_count, seed=seed):
            handle.write(
                json.dumps(hit, sort_keys=True, separators=(",", ":")).encode("utf-8")
                + b"\n"
            )
            written += 1
        for index in range(realistic_count, source_events):
            handle.write(f'{{"_id":"bounded-tail-{index}"}}\n'.encode("ascii"))
            written += 1
    return written


def _windows_rss_bytes(pid: int) -> int | None:
    if os.name != "nt":
        return None

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    query = 0x1000
    vm_read = 0x0010
    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    handle = kernel32.OpenProcess(query | vm_read, False, pid)
    if not handle:
        return None
    try:
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(
            handle,
            ctypes.byref(counters),
            counters.cb,
        ):
            return None
        return int(counters.WorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def _linux_rss_bytes(pid: int) -> int | None:
    status = Path(f"/proc/{pid}/status")
    if not status.exists():
        return None
    try:
        for line in status.read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _rss_bytes(pid: int) -> int | None:
    return _windows_rss_bytes(pid) if os.name == "nt" else _linux_rss_bytes(pid)


def _stable_digest(case_dir: Path) -> str:
    digest = hashlib.sha256()
    paths = [
        path
        for path in case_dir.rglob("*")
        if path.is_file()
        and (path.name in _STABLE_ARTIFACTS or "alerts" in path.relative_to(case_dir).parts)
    ]
    for path in sorted(paths, key=lambda item: item.as_posix()):
        digest.update(path.relative_to(case_dir).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _artifact_sizes(case_dir: Path) -> dict[str, int]:
    return {
        path.relative_to(case_dir).as_posix(): path.stat().st_size
        for path in sorted(case_dir.rglob("*"), key=lambda item: item.as_posix())
        if path.is_file()
    }


def _run_once(
    *,
    input_path: Path,
    out_root: Path,
    case_id: str,
    selected_events: int,
    max_seconds: float,
) -> dict[str, Any]:
    stdout_path = out_root / f"{case_id}.stdout.log"
    stderr_path = out_root / f"{case_id}.stderr.log"
    command = [
        sys.executable,
        "-m",
        "wazuh_sysmon_triage",
        "offline",
        "--input-ndjson",
        str(input_path),
        "--out-dir",
        str(out_root),
        "--case-id",
        case_id,
        "--max-events",
        str(selected_events),
        "--no-print-stats",
        "--no-alerts-only",
    ]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "src")
    started = time.perf_counter()
    peak_rss = 0
    timed_out = False
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr:
        process = subprocess.Popen(
            command,
            cwd=REPO_ROOT,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            text=True,
        )
        while process.poll() is None:
            rss = _rss_bytes(process.pid)
            if rss is not None:
                peak_rss = max(peak_rss, rss)
            if time.perf_counter() - started > max_seconds + 30:
                process.terminate()
                timed_out = True
                break
            time.sleep(0.02)
        try:
            exit_code = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            exit_code = process.wait()
            timed_out = True
    wall_seconds = time.perf_counter() - started

    case_dir = out_root / case_id
    stats_path = case_dir / "stats.json"
    stats = json.loads(stats_path.read_text(encoding="utf-8")) if stats_path.exists() else {}
    alerts_path = case_dir / "alerts.csv"
    alert_rows = (
        max(0, len(alerts_path.read_text(encoding="utf-8").splitlines()) - 1)
        if alerts_path.exists()
        else None
    )
    return {
        "case_id": case_id,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "wall_seconds": round(wall_seconds, 3),
        "peak_rss_mib": round(peak_rss / (1024 * 1024), 3) if peak_rss else None,
        "stage_durations_ms": {
            key: stats.get(f"{key}_duration_ms")
            for key in ("fetch", "normalize", "correlate", "detect", "render")
        },
        "counts": {
            "hits": stats.get("hits"),
            "total_events": stats.get("total_events"),
            "nodes": stats.get("nodes"),
            "edges": stats.get("edges"),
            "dropped": stats.get("dropped_count"),
            "unsupported": stats.get("unsupported_count"),
            "alerts": alert_rows,
        },
        "truncation": stats.get("truncation"),
        "input_quality": stats.get("input_quality"),
        "stable_digest": _stable_digest(case_dir) if stats else None,
        "artifact_sizes_bytes": _artifact_sizes(case_dir) if stats else {},
        "stdout_log": str(stdout_path),
        "stderr_log": str(stderr_path),
    }


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    selected_events = args.selected_events or args.source_events
    if selected_events > args.source_events:
        raise ValueError("selected events cannot exceed source events")

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.work_dir:
        work_dir = args.work_dir.resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
    elif args.keep_work_dir:
        work_dir = Path(tempfile.mkdtemp(prefix="wazuh-triage-benchmark-"))
    else:
        temporary = tempfile.TemporaryDirectory(prefix="wazuh-triage-benchmark-")
        work_dir = Path(temporary.name)
    input_path = work_dir / "benchmark.ndjson"
    out_root = work_dir / "out"
    out_root.mkdir(parents=True, exist_ok=True)

    generation_started = time.perf_counter()
    source_lines = _write_source(
        input_path,
        source_events=args.source_events,
        selected_events=selected_events,
        seed=args.seed,
    )
    generation_seconds = time.perf_counter() - generation_started
    runs = [
        _run_once(
            input_path=input_path,
            out_root=out_root,
            case_id=f"benchmark-{index + 1}",
            selected_events=selected_events,
            max_seconds=args.max_seconds,
        )
        for index in range(args.repeat)
    ]

    expects_truncation = args.source_events > selected_events
    digests = {run["stable_digest"] for run in runs}
    checks = {
        "source_line_count": source_lines == args.source_events,
        "exit_codes": all(run["exit_code"] == 0 for run in runs),
        "selected_count": all(run["counts"]["hits"] == selected_events for run in runs),
        "truncation": all(
            bool((run["truncation"] or {}).get("truncated")) == expects_truncation
            for run in runs
        ),
        "wall_time": all(run["wall_seconds"] <= args.max_seconds for run in runs),
        "peak_rss_available": all(run["peak_rss_mib"] is not None for run in runs),
        "peak_rss": all(
            run["peak_rss_mib"] is not None and run["peak_rss_mib"] <= args.max_rss_mib
            for run in runs
        ),
        "stable_digest": len(digests) == 1 and None not in digests,
        "suspicious_chain_recovered": all(
            (run["counts"].get("alerts") or 0) > 0 for run in runs
        ),
    }
    report = {
        "schema_version": 1,
        "seed": args.seed,
        "source_events": args.source_events,
        "selected_events": selected_events,
        "source_size_bytes": input_path.stat().st_size,
        "source_generation_seconds": round(generation_seconds, 3),
        "thresholds": {
            "max_seconds": args.max_seconds,
            "max_rss_mib": args.max_rss_mib,
        },
        "runs": runs,
        "checks": checks,
        "passed": all(checks.values()),
        "work_dir": str(work_dir) if args.keep_work_dir or args.work_dir else None,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if temporary is not None:
        temporary.cleanup()
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Qualify bounded offline triage performance.")
    parser.add_argument("--source-events", type=int, default=10_000)
    parser.add_argument("--selected-events", type=int)
    parser.add_argument("--seed", type=int, default=ACCEPTANCE_SEED)
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--max-seconds", type=float, default=30.0)
    parser.add_argument("--max-rss-mib", type=float, default=512.0)
    parser.add_argument("--report", type=Path, default=Path("benchmark-report.json"))
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--keep-work-dir", action="store_true")
    return parser


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    if args.source_events < 5:
        parser.error("--source-events must be at least 5")
    if args.selected_events is not None and args.selected_events < 5:
        parser.error("--selected-events must be at least 5")
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    report = run_benchmark(args)
    print(json.dumps({"passed": report["passed"], "checks": report["checks"]}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
