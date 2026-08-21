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
    preset_value: Any,
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
    elif preset_value is not None:
        result = bool(preset_value)
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
    cfg_explicit: set[str] = set()
    if config_path:
        _warn_inline_password_in_config(config_path)
        loaded = load_config(config_path)
        cfg = loaded.model_dump()
        cfg_explicit = set(loaded.model_dump(exclude_unset=True))

    active_profile = profile or cfg.get("active_profile")
    preset: dict[str, Any] = {}
    profile_values: dict[str, Any] = {}
    if active_profile:
        preset = dict(DEFAULT_PROFILE_PRESETS.get(active_profile, {}))
        configured_profile = (cfg.get("profiles") or {}).get(active_profile) or {}
        profile_values = {
            key: value for key, value in configured_profile.items() if value is not None
        }

    def written(key: str) -> Any:
        # model_dump() fills unset fields with model defaults, so only keys the user actually
        # wrote in the config file may outrank a built-in preset.
        return cfg.get(key) if key in cfg_explicit else None

    # A built-in preset is a default, so it ranks below anything the user wrote: CLI flag,
    # then the selected profile, then the config file, then the preset, then the model default.
    def setting(key: str, cli_value: Any = None) -> Any:
        return (
            cli_value
            or profile_values.get(key)
            or written(key)
            or preset.get(key)
            or cfg.get(key)
        )

    def flag(key: str, cli_value: bool | None) -> Any:
        # Same order, but False is a meaningful value rather than "unset".
        for layer in (
            cli_value,
            profile_values.get(key),
            written(key),
            preset.get(key),
            cfg.get(key),
        ):
            if layer is not None:
                return layer
        return None

    resolved_verify_tls = _resolve_verify_tls_setting(
        cli_value=verify_tls,
        profile_value=profile_values.get("verify_tls"),
        config_value=written("verify_tls"),
        preset_value=preset.get("verify_tls"),
        env_value=os.getenv("WAZUH_OS_VERIFY_TLS"),
        active_profile=active_profile,
    )

    resolved = {
        "profile": active_profile,
        "start": setting("start", start),
        "end": setting("end", end),
        "agent_id": setting("agent_id", agent_id),
        "agent_name": setting("agent_name", agent_name),
        "out_dir": setting("out_dir", out_dir),
        "host": setting("host", host) or os.getenv("WAZUH_OS_HOST"),
        "user": setting("user", user) or os.getenv("WAZUH_OS_USER"),
        # Credentials are env-first by policy: avoid secrets in config files.
        "password": password or os.getenv("WAZUH_OS_PASSWORD"),
        "verify_tls": resolved_verify_tls,
        "index_pattern": setting("index_pattern", index_pattern),
        "event_ids": setting("event_ids", event_ids),
        "alert_allowlist_basenames": setting("alert_allowlist_basenames", allowlist_image),
        "suppressions": setting("suppressions") or {},
        "context_roles": setting("context_roles") or {},
        "print_stats": flag("print_stats", print_stats),
        "alerts_only": flag("alerts_only", alerts_only),
        "artifact_retention": setting("artifact_retention") or {},
    }
    return resolved
