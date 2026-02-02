from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4


@dataclass
class RunContext:
    run_id: str = field(default_factory=lambda: str(uuid4()))
    case_id: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    params: dict = field(default_factory=dict)


@contextmanager
def timed(
    stage: str, logger: logging.Logger, ctx: RunContext, extra: dict | None = None
) -> Iterator[dict]:
    payload = dict(extra or {})
    logger.info(
        "Stage started",
        extra={
            **payload,
            "event": "stage_started",
            "stage": stage,
            "run_id": ctx.run_id,
            "case_id": ctx.case_id,
        },
    )
    start = perf_counter()
    timer = {"duration_ms": 0}
    try:
        yield timer
    finally:
        duration_ms = int((perf_counter() - start) * 1000)
        timer["duration_ms"] = duration_ms
        logger.info(
            "Stage completed",
            extra={
                **payload,
                "event": "stage_completed",
                "stage": stage,
                "run_id": ctx.run_id,
                "case_id": ctx.case_id,
                "duration_ms": duration_ms,
            },
        )
