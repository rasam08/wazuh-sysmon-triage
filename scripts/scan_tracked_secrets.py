#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

DEFAULT_EXCLUDE_REGEX = r"(^ui/node_modules/|^\.git/)"
DEFAULT_CHUNK_SIZE = 200


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan tracked git files for secrets with detect-secrets."
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root directory. Defaults to current directory.",
    )
    parser.add_argument(
        "--exclude-regex",
        default=DEFAULT_EXCLUDE_REGEX,
        help=f"Regex passed to detect-secrets --exclude-files (default: {DEFAULT_EXCLUDE_REGEX!r}).",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help="Max tracked files per detect-secrets invocation.",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional path to write merged detect-secrets JSON payload.",
    )
    return parser.parse_args()


def batched(items: Sequence[str], size: int) -> Iterable[Sequence[str]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


def list_tracked_files(repo_root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )
    return [path for path in result.stdout.decode("utf-8", "surrogateescape").split("\0") if path]


def normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def filter_files(paths: Sequence[str], exclude_regex: str) -> list[str]:
    matcher = re.compile(exclude_regex)
    filtered: list[str] = []
    for path in paths:
        if matcher.search(normalize_path(path)):
            continue
        filtered.append(path)
    return filtered


def scan_chunk(repo_root: Path, chunk: Sequence[str], exclude_regex: str) -> dict[str, object]:
    command = [
        sys.executable,
        "-m",
        "detect_secrets",
        "scan",
        "--exclude-files",
        exclude_regex,
        *chunk,
    ]
    result = subprocess.run(
        command,
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        raise RuntimeError(
            f"detect-secrets scan failed (exit={result.returncode}):\n"
            f"{stderr or stdout or '<no output>'}"
        )
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"detect-secrets returned invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("detect-secrets returned non-object JSON payload.")
    return payload


def merge_payloads(payloads: Sequence[dict[str, object]]) -> dict[str, object]:
    merged: dict[str, object] = {
        "version": "1.5.0",
        "plugins_used": [],
        "filters_used": [],
        "results": {},
    }
    merged_results: dict[str, list[object]] = {}

    for payload in payloads:
        plugins = payload.get("plugins_used")
        filters = payload.get("filters_used")
        version = payload.get("version")
        if isinstance(version, str):
            merged["version"] = version
        if isinstance(plugins, list) and not merged["plugins_used"]:
            merged["plugins_used"] = plugins
        if isinstance(filters, list) and not merged["filters_used"]:
            merged["filters_used"] = filters

        results = payload.get("results")
        if not isinstance(results, dict):
            continue
        for file_name, findings in results.items():
            if not isinstance(file_name, str) or not isinstance(findings, list):
                continue
            if not findings:
                continue
            merged_results.setdefault(file_name, []).extend(findings)

    merged["results"] = merged_results
    return merged


def main() -> int:
    args = parse_args()
    if args.chunk_size <= 0:
        print("--chunk-size must be a positive integer.", file=sys.stderr)
        return 2

    repo_root = Path(args.repo_root).resolve()
    tracked_files = list_tracked_files(repo_root)
    scan_files = filter_files(tracked_files, args.exclude_regex)

    payloads: list[dict[str, object]] = []
    for chunk in batched(scan_files, args.chunk_size):
        payloads.append(scan_chunk(repo_root, chunk, args.exclude_regex))

    merged_payload = merge_payloads(payloads)

    if args.json_out:
        output_path = Path(args.json_out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(merged_payload, indent=2, sort_keys=True), encoding="utf-8")

    findings = merged_payload.get("results", {})
    if not isinstance(findings, dict):
        print("detect-secrets payload missing results dictionary.", file=sys.stderr)
        return 2

    active = {name: rows for name, rows in findings.items() if isinstance(rows, list) and rows}
    if active:
        print("Secret scan findings:")
        for file_name, rows in sorted(active.items()):
            print(f"- {file_name}: {len(rows)} finding(s)")
        return 1

    print("No secrets found by detect-secrets scan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
