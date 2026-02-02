from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(record, "event", None),
            "message": record.getMessage(),
            "stage": getattr(record, "stage", None),
            "run_id": getattr(record, "run_id", None),
            "case_id": getattr(record, "case_id", None),
            "counts": getattr(record, "counts", None),
            "duration_ms": getattr(record, "duration_ms", None),
            "error": getattr(record, "error", None),
        }

        extras = getattr(record, "extra", None)
        if isinstance(extras, dict):
            payload.update(_redact_sensitive(extras))

        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def _redact_sensitive(data: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in {"authorization", "password", "pass"}:
            redacted[key] = "[REDACTED]"
        elif isinstance(value, dict):
            nested = {}
            for nested_key, nested_value in value.items():
                if nested_key.lower() == "authorization":
                    nested[nested_key] = "[REDACTED]"
                else:
                    nested[nested_key] = nested_value
            redacted[key] = nested
        else:
            redacted[key] = value
    return redacted


def setup_logging(level: str = "INFO", json: bool = True, out_path: Path | None = None) -> None:
    """
    Set up structured NDJSON logging.

    Args:
        level (str): Logging level.
        json (bool): Emit JSON lines when True.
        out_path (Path | None): Optional file sink path (append).
    """
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    if json:
        formatter: logging.Formatter = JsonLineFormatter()
    else:
        formatter = logging.Formatter("%(levelname)s %(name)s %(message)s")

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    root.addHandler(stdout_handler)

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(out_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
