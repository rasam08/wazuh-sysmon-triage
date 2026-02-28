from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SENSITIVE_KEYS = {"authorization", "password", "pass", "token", "api_key", "apikey", "secret"}


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


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return _redact_sensitive(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _redact_sensitive(data: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in SENSITIVE_KEYS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = _redact_value(value)
    return redacted


def setup_logging(
    level: str = "INFO", json_format: bool = True, out_path: Path | None = None
) -> None:
    """
    Set up structured NDJSON logging.

    Args:
        level (str): Logging level.
        json_format (bool): Emit JSON lines when True.
        out_path (Path | None): Optional file sink path (append).
    """
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    if json_format:
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
