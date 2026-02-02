import pytest

from wazuh_sysmon_triage.config import Config


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
    }
    config = Config(**valid_data)
    assert config.agent_id == "12345"
    assert config.verify_tls is True


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
