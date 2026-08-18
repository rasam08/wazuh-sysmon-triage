from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from wazuh_sysmon_triage.windows_paths import windows_basename


class SuppressionRuleConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    image_glob: str | None = None
    image_regex: str | None = None
    user: str | None = None
    destination_ports: list[int] | None = None
    destination_class: Literal["public", "private"] | None = None
    enabled: bool = True


class SuppressionSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    rules: list[SuppressionRuleConfig] = Field(default_factory=list)
    allowlist_override: list[SuppressionRuleConfig] = Field(default_factory=list)


class ContextRoleMatcher(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent_names: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    process_image_contains: list[str] = Field(default_factory=list)


class ArtifactRetentionConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    max_age_days: int | None = Field(
        30,
        ge=1,
        description="Remove case folders older than this number of days.",
    )
    max_total_size_mb: int | None = Field(
        2048,
        ge=1,
        description="Prune oldest case folders when total output size exceeds this threshold.",
    )
    min_keep_runs: int = Field(
        10,
        ge=0,
        description="Always keep at least this many most-recent runs.",
    )


class ProfileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: str | None = None
    end: str | None = None
    agent_id: str | None = None
    agent_name: str | None = None
    out_dir: str | None = None
    host: str | None = None
    user: str | None = None
    password: str | None = Field(None, alias="pass")
    verify_tls: bool | None = None
    index_pattern: str | None = None
    event_ids: list[int] | None = None
    alert_allowlist_basenames: list[str] | None = None
    suppressions: SuppressionSettings | None = None
    context_roles: dict[str, ContextRoleMatcher] | None = None
    print_stats: bool | None = None
    alerts_only: bool | None = None
    artifact_retention: ArtifactRetentionConfig | None = None


class Config(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    # These can be provided via CLI flags; keep optional so connection-only config files work.
    start: str | None = Field(None, description="Start time in ISO8601 format")
    end: str | None = Field(None, description="End time in ISO8601 format")
    agent_id: str | None = Field(None, description="Agent ID")
    agent_name: str | None = Field(None, description="Agent Name")
    out_dir: str = Field("./out", description="Output directory")
    host: str | None = Field(None, description="Host for OpenSearch")
    user: str | None = Field(None, description="Username for OpenSearch")
    password: str | None = Field(None, alias="pass", description="Password for OpenSearch")
    verify_tls: bool = Field(True, description="Verify TLS certificate")
    index_pattern: str = Field("wazuh-alerts-4.x-*", description="Index pattern for OpenSearch")
    event_ids: list[int] | None = Field(
        None,
        description=(
            "Sysmon event IDs to include. If omitted, the supported high-value evidence set applies."
        ),
    )
    alert_allowlist_basenames: list[str] | None = Field(
        None,
        description="Process image basenames that hard-suppress alerts.",
    )
    suppressions: SuppressionSettings | None = Field(
        None,
        description="Detection-stage suppression settings.",
    )
    context_roles: dict[str, ContextRoleMatcher] = Field(
        default_factory=dict,
        description="Context role mapping for tagging (developer/dev workstation context).",
    )
    active_profile: str | None = Field(
        None,
        description="Optional default profile name to apply when no --profile is provided.",
    )
    profiles: dict[str, ProfileConfig] = Field(
        default_factory=dict,
        description="Named profile presets that can be selected with --profile.",
    )
    artifact_retention: ArtifactRetentionConfig | None = Field(
        default=None,
        description="Optional retention policy for pruning old run folders.",
    )

    @field_validator("start", "end")
    @classmethod
    def _validate_iso8601(cls, value: str | None) -> str | None:
        if value is None:
            return value
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        datetime.fromisoformat(text)
        return value

    @field_validator("alert_allowlist_basenames", mode="before")
    @classmethod
    def _normalize_allowlist(cls, value: list[str] | str | None) -> list[str] | None:
        if value is None:
            return None
        values = [value] if isinstance(value, str) else list(value)
        normalized = []
        for entry in values:
            text = windows_basename(str(entry)).strip()
            if text:
                normalized.append(text)
        return normalized

    @classmethod
    def from_yaml(cls, file_path: str) -> Config:
        with open(file_path, encoding="utf-8") as file:
            config_data = yaml.safe_load(file) or {}
        return cls(**config_data)


def load_config(file_path: str) -> Config:
    """Load configuration from a YAML file."""
    return Config.from_yaml(file_path)


def _contains_inline_password(payload: Any) -> bool:
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_text = str(key).strip().lower()
            if key_text in {"pass", "password"} and isinstance(value, str) and value.strip():
                return True
            if _contains_inline_password(value):
                return True
        return False
    if isinstance(payload, list):
        return any(_contains_inline_password(item) for item in payload)
    return False


def config_has_inline_password(file_path: str) -> bool:
    try:
        with open(file_path, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
    except OSError:
        return False
    return _contains_inline_password(raw)


def validate_config(config: Config) -> None:
    """Validate the loaded configuration."""
    if config.start and config.end and config.start >= config.end:
        raise ValueError("start must be before end")
