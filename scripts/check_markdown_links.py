#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
IGNORED_SCHEMES = {"http", "https", "mailto"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check local links in repository Markdown files.")
    parser.add_argument("--repo-root", default=".", help="Repository root (default: current directory).")
    return parser.parse_args()


def markdown_files(repo_root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "--", "*.md"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode == 0:
        candidates = (repo_root / line for line in result.stdout.splitlines() if line)
        return sorted(path for path in candidates if path.is_file())
    return sorted(repo_root.rglob("*.md"))


def link_target(raw_target: str) -> str:
    target = raw_target.strip()
    if target.startswith("<") and ">" in target:
        return target[1 : target.index(">")]
    return target.split(maxsplit=1)[0]


def missing_links(repo_root: Path, markdown_path: Path) -> list[tuple[int, str]]:
    failures: list[tuple[int, str]] = []
    text = markdown_path.read_text(encoding="utf-8")
    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in LINK_RE.finditer(line):
            target = link_target(match.group(1))
            if not target or target.startswith("#"):
                continue
            parsed = urlsplit(target)
            if parsed.scheme.lower() in IGNORED_SCHEMES:
                continue
            if parsed.scheme:
                failures.append((line_number, target))
                continue
            local_part = unquote(target.split("#", 1)[0])
            if not local_part:
                continue
            if local_part.startswith("/"):
                resolved = repo_root / local_part.lstrip("/")
            else:
                resolved = markdown_path.parent / local_part
            if not resolved.exists():
                failures.append((line_number, target))
    return failures


def main() -> int:
    repo_root = Path(parse_args().repo_root).resolve()
    failures: list[tuple[Path, int, str]] = []
    for markdown_path in markdown_files(repo_root):
        for line_number, target in missing_links(repo_root, markdown_path):
            failures.append((markdown_path.relative_to(repo_root), line_number, target))

    if failures:
        print("Broken or unsupported local Markdown links:", file=sys.stderr)
        for path, line_number, target in failures:
            print(f"- {path}:{line_number}: {target}", file=sys.stderr)
        return 1

    print("All local Markdown links resolve.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
