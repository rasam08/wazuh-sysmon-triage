from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import typer

from wazuh_sysmon_triage.models.raw import RawHit

DEFAULT_PROFILE_PRESETS: dict[str, dict[str, Any]] = {
    "soc": {
        "event_ids": [1, 3, 11],
        "min_alert_score": 70,
        "alerts_only": True,
        "print_stats": True,
        "agent_name": "anon",
        "destination_scoring_mode": "balanced",
        "alert_queues": ["soc_malware", "soc_policy"],
        "include_dev_queue": False,
    },
    "lab": {
        "event_ids": [1, 3, 11],
        "min_alert_score": 60,
        "alerts_only": True,
        "print_stats": True,
        "destination_scoring_mode": "lab",
        "verify_tls": False,
    },
    "dev": {
        "event_ids": [1, 3, 11],
        "min_alert_score": 70,
        "alerts_only": False,
        "print_stats": True,
        "destination_scoring_mode": "balanced",
    },
}

VALID_ALERT_QUEUES = {"soc_malware", "soc_policy", "soc_dev", "soc_info"}
LAST_RE = re.compile(r"^(\d+)([mhd])$", flags=re.IGNORECASE)


def _ensure_out_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _process_line(stage: str, message: str) -> None:
    typer.echo(f"[process] {stage}: {message}")


def _resolve_default_config_path(config: str | None) -> str | None:
    if config:
        return config
    default_path = "config.local.yaml"
    if os.path.exists(default_path):
        _process_line("config", f"using {default_path} (override with --config)")
        return default_path
    return None


def _safe_case_id(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip())
    normalized = re.sub(r"-+", "-", normalized).strip("-._")
    return normalized or "incident"


def _generate_case_id(now: datetime | None = None) -> str:
    ts = (now or datetime.now(tz=UTC)).strftime("%Y%m%d-%H%M%S")
    return f"incident-{ts}"


def _parse_last_duration(value: str) -> timedelta:
    match = LAST_RE.match(value.strip())
    if not match:
        raise typer.BadParameter("--last must look like 15m, 2h, or 7d")
    amount = int(match.group(1))
    unit = match.group(2).lower()
    if amount <= 0:
        raise typer.BadParameter("--last value must be greater than zero")
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    return timedelta(days=amount)


def _iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_iso_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _shift_known_timestamp_fields(payload: Any, delta: timedelta) -> int:
    shifted = 0
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_lower = key.lower()
            if isinstance(value, str) and key_lower in {"@timestamp", "utctime", "creationutctime"}:
                parsed = _parse_iso_ts(value)
                if parsed is not None:
                    payload[key] = _iso_z(parsed + delta)
                    shifted += 1
                    continue
            shifted += _shift_known_timestamp_fields(value, delta)
    elif isinstance(payload, list):
        for item in payload:
            shifted += _shift_known_timestamp_fields(item, delta)
    return shifted


def _is_scenario_gym_path(input_ndjson: str) -> bool:
    normalized = input_ndjson.replace("\\", "/").lower()
    return "scenario_gym" in normalized and normalized.endswith(".ndjson")


def _rebase_scenario_gym_hits_to_now(hits: list[RawHit]) -> tuple[bool, int]:
    source_times: list[datetime] = []
    for hit in hits:
        source = hit.get("_source") or {}
        ts = _parse_iso_ts(source.get("@timestamp"))
        if ts is not None:
            source_times.append(ts)

    if not source_times:
        return False, 0

    anchor = min(source_times)
    delta = datetime.now(tz=UTC) - anchor
    shifted_fields = 0
    for hit in hits:
        shifted_fields += _shift_known_timestamp_fields(hit, delta)
    return True, shifted_fields


def _resolve_time_window(
    start: str | None,
    end: str | None,
    last: str | None,
    today: bool,
    yesterday: bool,
    now: datetime | None = None,
) -> tuple[str | None, str | None]:
    if start or end:
        if not start or not end:
            raise typer.BadParameter("--start and --end must be provided together")
        return start, end

    selected = int(bool(last)) + int(today) + int(yesterday)
    if selected > 1:
        raise typer.BadParameter("Use only one of --last, --today, or --yesterday")

    current = (now or datetime.now(tz=UTC)).astimezone(UTC)
    if last:
        delta = _parse_last_duration(last)
        return _iso_z(current - delta), _iso_z(current)

    if today:
        day_start = current.replace(hour=0, minute=0, second=0, microsecond=0)
        return _iso_z(day_start), _iso_z(current)

    if yesterday:
        today_start = current.replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday_start = today_start - timedelta(days=1)
        return _iso_z(yesterday_start), _iso_z(today_start)

    return start, end


def _alert_contributors(alert: Any) -> list[str]:
    contributors: list[str] = []
    if getattr(alert, "rule_name", None):
        contributors.append(f"primary_rule:{alert.rule_name}")
    elif getattr(alert, "rule_id", None):
        contributors.append(f"primary_rule:{alert.rule_id}")
    else:
        contributors.append(f"primary_rule:{getattr(alert, 'alert_type', 'unknown')}")

    tags = set(getattr(alert, "tags", []) or [])
    for tag in sorted(tags):
        if str(tag).startswith("escalator:"):
            contributors.append(f"escalator:{tag.split(':', 1)[1]}")
    if "role:developer" in tags:
        contributors.append("context:developer")
    return contributors


def _normalize_alert_queues(value: list[str] | None) -> list[str] | None:
    if not value:
        return None
    normalized: list[str] = []
    for queue in value:
        item = str(queue).strip().lower()
        if item not in VALID_ALERT_QUEUES:
            raise typer.BadParameter(
                f"Invalid queue '{queue}'. Use one of: {', '.join(sorted(VALID_ALERT_QUEUES))}"
            )
        if item not in normalized:
            normalized.append(item)
    return normalized


def _filter_alerts_by_queue(
    alerts: list[Any],
    *,
    alert_queues: list[str] | None,
    include_dev_queue: bool,
) -> list[Any]:
    queues = _normalize_alert_queues(alert_queues)
    if queues is None:
        return alerts
    effective = set(queues)
    if include_dev_queue:
        effective.add("soc_dev")
    return [alert for alert in alerts if getattr(alert, "queue", "") in effective]

