from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, cast

from wazuh_sysmon_triage.models.raw import RawHit

DEFAULT_MAX_RECORD_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_REJECTED_RECORDS = 10_000
DEFAULT_RAW_PREVIEW_BYTES = 4 * 1024
_READ_CHUNK_BYTES = 64 * 1024

RejectionWriter = Callable[[dict[str, Any]], None]


@dataclass
class InputQualityReport:
    total_lines: int = 0
    blank_lines: int = 0
    accepted_records: int = 0
    rejected_records: int = 0
    rejected_by_reason: dict[str, int] = field(default_factory=dict)
    truncated: bool = False
    truncation_reason: str | None = None
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES
    max_rejected_records: int = DEFAULT_MAX_REJECTED_RECORDS

    @property
    def integrity(self) -> str:
        if self.rejected_records or self.truncated:
            return "degraded"
        return "complete"

    def to_payload(self) -> dict[str, Any]:
        return {"integrity": self.integrity, **asdict(self)}


@dataclass
class NDJSONReadResult:
    hits: list[RawHit]
    report: InputQualityReport


@dataclass(frozen=True)
class _BoundedLine:
    byte_offset: int
    byte_length: int
    raw_sha256: str
    raw: bytes | None
    prefix: bytes
    oversized: bool


def _read_bounded_line(handle: BinaryIO, *, max_record_bytes: int) -> _BoundedLine | None:
    """Read and hash one physical line without retaining an oversized record."""
    byte_offset = handle.tell()
    first = handle.readline(max_record_bytes + 3)
    if not first:
        return None

    hasher = hashlib.sha256()
    hasher.update(first)
    byte_length = len(first)
    complete = first.endswith(b"\n") or len(first) < max_record_bytes + 3
    prefix = first[:max_record_bytes]

    while not complete:
        chunk = handle.readline(_READ_CHUNK_BYTES)
        if not chunk:
            complete = True
            continue
        hasher.update(chunk)
        byte_length += len(chunk)
        complete = chunk.endswith(b"\n")

    content_length = byte_length
    if first.endswith(b"\n") and byte_length == len(first):
        content_length -= 1
        if first.endswith(b"\r\n"):
            content_length -= 1
    elif byte_length <= len(first):
        content_length = len(first.rstrip(b"\r\n"))

    oversized = content_length > max_record_bytes or byte_length > len(first)
    return _BoundedLine(
        byte_offset=byte_offset,
        byte_length=byte_length,
        raw_sha256=hasher.hexdigest(),
        raw=None if oversized else first,
        prefix=prefix,
        oversized=oversized,
    )


def _safe_raw_text(line: _BoundedLine) -> tuple[str, bool]:
    raw = line.raw if line.raw is not None else line.prefix
    content = raw.rstrip(b"\r\n")
    truncated = line.oversized or len(content) > DEFAULT_RAW_PREVIEW_BYTES
    return (
        content[:DEFAULT_RAW_PREVIEW_BYTES].decode("utf-8", errors="replace"),
        truncated,
    )


def _rejection_payload(
    *,
    line: _BoundedLine,
    line_number: int,
    reason: str,
    error: str,
    include_raw_line: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "stage": "input",
        "reason": reason,
        "line_number": line_number,
        "byte_offset": line.byte_offset,
        "record_size_bytes": line.byte_length,
        "raw_sha256": line.raw_sha256,
        "error": error,
    }
    if include_raw_line:
        raw_text, raw_truncated = _safe_raw_text(line)
        payload["raw_line"] = raw_text
        if raw_truncated:
            payload["raw_truncated"] = True
    return payload


def read_ndjson(
    path: str | Path,
    *,
    max_events: int,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
    max_rejected_records: int = DEFAULT_MAX_REJECTED_RECORDS,
    on_rejection: RejectionWriter | None = None,
    include_raw_line: bool = False,
) -> NDJSONReadResult:
    """Read accepted JSON objects while isolating individual malformed records.

    ``max_events`` counts accepted objects. At most one additional accepted object is
    inspected to prove truncation. Rejections are sent to ``on_rejection`` as they are
    observed and are never accumulated in memory.
    """
    if max_events < 1:
        raise ValueError("max_events must be at least 1")
    if max_record_bytes < 1:
        raise ValueError("max_record_bytes must be at least 1")
    if max_rejected_records < 1:
        raise ValueError("max_rejected_records must be at least 1")

    hits: list[RawHit] = []
    report = InputQualityReport(
        max_record_bytes=max_record_bytes,
        max_rejected_records=max_rejected_records,
    )

    with Path(path).open("rb") as handle:
        while True:
            bounded = _read_bounded_line(handle, max_record_bytes=max_record_bytes)
            if bounded is None:
                break
            report.total_lines += 1
            line_number = report.total_lines

            if bounded.oversized:
                reason = "record_too_large"
                error = f"record exceeds maximum size of {max_record_bytes} bytes"
                payload = _rejection_payload(
                    line=bounded,
                    line_number=line_number,
                    reason=reason,
                    error=error,
                    include_raw_line=include_raw_line,
                )
            else:
                assert bounded.raw is not None
                raw_content = bounded.raw.rstrip(b"\r\n")
                if not raw_content.strip():
                    report.blank_lines += 1
                    continue
                try:
                    text = raw_content.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    reason = "invalid_utf8"
                    error = f"invalid UTF-8 at byte {exc.start}"
                    payload = _rejection_payload(
                        line=bounded,
                        line_number=line_number,
                        reason=reason,
                        error=error,
                        include_raw_line=include_raw_line,
                    )
                else:
                    try:
                        decoded = json.loads(text)
                    except json.JSONDecodeError as exc:
                        reason = "malformed_json"
                        error = f"JSON decode error at line {exc.lineno}, column {exc.colno}: {exc.msg}"
                        payload = _rejection_payload(
                            line=bounded,
                            line_number=line_number,
                            reason=reason,
                            error=error,
                            include_raw_line=include_raw_line,
                        )
                    else:
                        if not isinstance(decoded, dict):
                            reason = "non_object_json"
                            error = "top-level JSON value must be an object"
                            payload = _rejection_payload(
                                line=bounded,
                                line_number=line_number,
                                reason=reason,
                                error=error,
                                include_raw_line=include_raw_line,
                            )
                        elif len(hits) >= max_events:
                            report.truncated = True
                            report.truncation_reason = "max-events"
                            break
                        else:
                            hits.append(cast(RawHit, decoded))
                            report.accepted_records += 1
                            continue

            report.rejected_records += 1
            report.rejected_by_reason[reason] = report.rejected_by_reason.get(reason, 0) + 1
            if on_rejection is not None:
                on_rejection(payload)
            if report.rejected_records >= max_rejected_records:
                report.truncated = True
                report.truncation_reason = "max-input-rejections"
                break

    return NDJSONReadResult(hits=hits, report=report)
