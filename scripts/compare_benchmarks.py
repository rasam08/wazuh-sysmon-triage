from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


def _maximum(report: dict[str, Any], field: str) -> float:
    values = [run.get(field) for run in report["runs"]]
    numeric = [float(value) for value in values if value is not None]
    if not numeric:
        raise ValueError(f"benchmark report has no {field} measurements")
    return max(numeric)


def _growth_exponent(
    smaller_count: int,
    smaller_value: float,
    larger_count: int,
    larger_value: float,
) -> float:
    if smaller_value <= 0 or larger_value <= 0:
        raise ValueError("growth measurements must be positive")
    return math.log(larger_value / smaller_value) / math.log(larger_count / smaller_count)


def compare(paths: list[Path]) -> dict[str, Any]:
    reports = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    reports.sort(key=lambda item: int(item["selected_events"]))
    if len(reports) < 3:
        raise ValueError("at least three benchmark reports are required")
    if not all(report.get("passed") for report in reports):
        raise ValueError("every benchmark must pass its absolute thresholds before comparison")

    points = [
        {
            "selected_events": int(report["selected_events"]),
            "wall_seconds": _maximum(report, "wall_seconds"),
            "peak_rss_mib": _maximum(report, "peak_rss_mib"),
        }
        for report in reports
    ]
    checks: list[dict[str, Any]] = []
    for smaller, larger in zip(points, points[1:], strict=False):
        time_exponent = _growth_exponent(
            smaller["selected_events"],
            smaller["wall_seconds"],
            larger["selected_events"],
            larger["wall_seconds"],
        )
        memory_exponent = _growth_exponent(
            smaller["selected_events"],
            smaller["peak_rss_mib"],
            larger["selected_events"],
            larger["peak_rss_mib"],
        )
        checks.append(
            {
                "from_events": smaller["selected_events"],
                "to_events": larger["selected_events"],
                "wall_growth_exponent": round(time_exponent, 3),
                "memory_growth_exponent": round(memory_exponent, 3),
                "subquadratic_wall": time_exponent < 1.5,
                "subquadratic_memory": memory_exponent < 1.5,
            }
        )
    return {
        "schema_version": 1,
        "points": points,
        "comparisons": checks,
        "passed": all(
            item["subquadratic_wall"] and item["subquadratic_memory"] for item in checks
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check benchmark scaling for nonlinear growth.")
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, default=Path("benchmark-scaling-report.json"))
    args = parser.parse_args()
    try:
        result = compare(args.reports)
    except (KeyError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
