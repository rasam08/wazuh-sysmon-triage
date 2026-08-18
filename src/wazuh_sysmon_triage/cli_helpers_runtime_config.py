from __future__ import annotations

import os
from typing import Any

import typer

from wazuh_sysmon_triage.config import config_has_inline_password, load_config
from wazuh_sysmon_triage.operations import parse_optional_bool

from .cli_helpers_runtime_utils import DEFAULT_PROFILE_PRESETS


def _validate_required(
    start: str | None, end: str | None, agent_id: str | None, agent_name: str | None
) -> None:
    if not start or not end:
        raise typer.BadParameter("--start and --end are required")
    if not agent_id and not agent_name:
        raise typer.BadParameter("--agent-id or --agent-name is required")


def _validate_opensearch(host: str | None, user: str | None, password: str | None) -> None:
    if not host or not user or not password:
        raise typer.BadParameter("--host, --user, and --password are required")


def _profile_default_verify_tls(profile: str | None) -> bool:
    # Lab defaults should be forgiving for common self-signed/local-indexer setups.
    return str(profile or "").strip().lower() != "lab"


def _resolve_verify_tls_setting(
    *,
    cli_value: bool | None,
    profile_value: Any,
    config_value: Any,
    env_value: str | None,
    active_profile: str | None,
) -> bool:
    if cli_value is not None:
        result = bool(cli_value)
    elif (env_parsed := parse_optional_bool(env_value)) is not None:
        result = env_parsed
    elif profile_value is not None:
        result = bool(profile_value)
    elif config_value is not None:
        result = bool(config_value)
    else:
        result = _profile_default_verify_tls(active_profile)

    if not result:
        typer.echo(
            "[warn] TLS certificate verification is DISABLED. "
            "Connections are vulnerable to MITM attacks. "
            "Set verify_tls=true or --verify-tls for production use."
        )
    return result


def _warn_inline_password_in_config(config_path: str | None) -> None:
    if not config_path:
        return
    if not config_has_inline_password(config_path):
        return
    typer.echo(
        "[warn] Inline password detected in config; use WAZUH_OS_PASSWORD instead. "
        "Config passwords are ignored."
    )


def _resolve_config(
    config_path: str | None,
    profile: str | None,
    start: str | None,
    end: str | None,
    agent_id: str | None,
    agent_name: str | None,
    out_dir: str | None,
    host: str | None,
    user: str | None,
    password: str | None,
    verify_tls: bool | None,
    index_pattern: str | None,
    event_ids: list[int] | None,
    allowlist_image: list[str] | None,
    print_stats: bool | None = None,
    alerts_only: bool | None = None,
) -> dict[str, Any]:
    cfg: dict[str, Any] = {}
    if config_path:
        _warn_inline_password_in_config(config_path)
        loaded = load_config(config_path)
        cfg = loaded.model_dump()

    active_profile = profile or cfg.get("active_profile")
    merged_profile: dict[str, Any] = {}
    if active_profile:
        merged_profile = dict(DEFAULT_PROFILE_PRESETS.get(active_profile, {}))
        config_profiles = cfg.get("profiles") or {}
        if active_profile in config_profiles:
            profile_values = config_profiles.get(active_profile) or {}
            merged_profile.update(
                {key: value for key, value in profile_values.items() if value is not None}
            )

    resolved_verify_tls = _resolve_verify_tls_setting(
        cli_value=verify_tls,
        profile_value=merged_profile.get("verify_tls"),
        config_value=cfg.get("verify_tls"),
        env_value=os.getenv("WAZUH_OS_VERIFY_TLS"),
        active_profile=active_profile,
    )

    resolved = {
        "profile": active_profile,
        "start": start or merged_profile.get("start") or cfg.get("start"),
        "end": end or merged_profile.get("end") or cfg.get("end"),
        "agent_id": agent_id or merged_profile.get("agent_id") or cfg.get("agent_id"),
        "agent_name": agent_name or merged_profile.get("agent_name") or cfg.get("agent_name"),
        "out_dir": out_dir or merged_profile.get("out_dir") or cfg.get("out_dir"),
        "host": host or merged_profile.get("host") or cfg.get("host") or os.getenv("WAZUH_OS_HOST"),
        "user": user or merged_profile.get("user") or cfg.get("user") or os.getenv("WAZUH_OS_USER"),
        # Credentials are env-first by policy: avoid secrets in config files.
        "password": password or os.getenv("WAZUH_OS_PASSWORD"),
        "verify_tls": resolved_verify_tls,
        "index_pattern": index_pattern
        or merged_profile.get("index_pattern")
        or cfg.get("index_pattern"),
        "event_ids": event_ids or merged_profile.get("event_ids") or cfg.get("event_ids"),
        "alert_allowlist_basenames": allowlist_image
        or merged_profile.get("alert_allowlist_basenames")
        or cfg.get("alert_allowlist_basenames"),
        "suppressions": merged_profile.get("suppressions") or cfg.get("suppressions") or {},
        "context_roles": merged_profile.get("context_roles") or cfg.get("context_roles") or {},
        "print_stats": print_stats
        if print_stats is not None
        else merged_profile.get("print_stats", cfg.get("print_stats")),
        "alerts_only": alerts_only
        if alerts_only is not None
        else merged_profile.get("alerts_only", cfg.get("alerts_only")),
        "artifact_retention": merged_profile.get("artifact_retention")
        or cfg.get("artifact_retention")
        or {},
    }
    return resolved
