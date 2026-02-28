import pytest

from wazuh_sysmon_triage.config import Config, config_has_inline_password


def test_config_loading_from_yaml():
    """Test loading configuration from a YAML file."""
    config = Config.from_yaml("config.example.yaml")
    assert config is not None
    assert config.index_pattern == "wazuh-alerts-4.x-*"


def test_config_validation():
    """Test validation of configuration settings."""
    valid_data = {
        "start": "2023-01-01T00:00:00Z",
        "end": "2023-01-02T00:00:00Z",
        "agent_id": "12345",
        "out_dir": "./output",
        "host": "localhost",
        "user": "admin",
        "pass": "password",
        "verify_tls": True,
        "index_pattern": "wazuh-alerts-4.x-*",
        "min_alert_score": 75,
        "alert_allowlist_basenames": ["chrome.exe", "MsMpEng.exe"],
    }
    config = Config(**valid_data)
    assert config.agent_id == "12345"
    assert config.verify_tls is True
    assert config.min_alert_score == 75
    assert config.alert_allowlist_basenames == ["chrome.exe", "msmpeng.exe"]


def test_config_invalid_data():
    """Test that invalid configuration data raises validation errors."""
    invalid_data = {
        "start": "invalid-date",
        "end": "2023-01-02T00:00:00Z",
        "agent_id": "12345",
        "out_dir": "./output",
        "host": "localhost",
        "user": "admin",
        "pass": "password",
        "verify_tls": True,
        "index_pattern": "wazuh-alerts-4.x-*",
    }
    with pytest.raises(ValueError):
        Config(**invalid_data)


def test_config_invalid_alert_threshold() -> None:
    with pytest.raises(ValueError):
        Config(min_alert_score=101)


def test_config_inline_password_detection(tmp_path) -> None:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "\n".join(
            [
                "host: https://indexer:9920",
                "user: admin",
                "pass: secret",
                "profiles:",
                "  soc:",
                "    pass: profile-secret",
            ]
        ),
        encoding="utf-8",
    )
    assert config_has_inline_password(str(cfg)) is True

    cfg_clean = tmp_path / "cfg-clean.yaml"
    cfg_clean.write_text(
        "\n".join(
            [
                "host: https://indexer:9920",
                "user: admin",
            ]
        ),
        encoding="utf-8",
    )
    assert config_has_inline_password(str(cfg_clean)) is False
