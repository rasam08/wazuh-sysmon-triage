from __future__ import annotations

from datetime import datetime

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Config(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    start: str = Field(..., description="Start time in ISO8601 format")
    end: str = Field(..., description="End time in ISO8601 format")
    agent_id: str | None = Field(None, description="Agent ID")
    agent_name: str | None = Field(None, description="Agent Name")
    out_dir: str = Field(..., description="Output directory")
    host: str | None = Field(None, description="Host for OpenSearch")
    user: str | None = Field(None, description="Username for OpenSearch")
    password: str | None = Field(None, alias="pass", description="Password for OpenSearch")
    verify_tls: bool = Field(True, description="Verify TLS certificate")
    index_pattern: str = Field("wazuh-alerts-4.x-*", description="Index pattern for OpenSearch")

    @field_validator("start", "end")
    @classmethod
    def _validate_iso8601(cls, value: str) -> str:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        datetime.fromisoformat(text)
        return value

    @classmethod
    def from_yaml(cls, file_path: str) -> Config:
        with open(file_path, encoding="utf-8") as file:
            config_data = yaml.safe_load(file) or {}
        return cls(**config_data)


def load_config(file_path: str) -> Config:
    """Load configuration from a YAML file."""
    return Config.from_yaml(file_path)


def validate_config(config: Config) -> None:
    """Validate the loaded configuration."""
    if config.start >= config.end:
        raise ValueError("start must be before end")
