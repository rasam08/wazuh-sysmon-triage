from __future__ import annotations

from pathlib import PureWindowsPath


def windows_basename(path: str | None) -> str:
    if not path:
        return ""
    return PureWindowsPath(path).name.lower()


def windows_suffix(path: str | None) -> str:
    if not path:
        return ""
    return PureWindowsPath(path).suffix.lower()
