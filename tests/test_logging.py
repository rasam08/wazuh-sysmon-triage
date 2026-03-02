from wazuh_sysmon_triage.logging import _redact_sensitive


def test_redact_sensitive_nested_keys() -> None:
    payload = {
        "password": "root",  # pragma: allowlist secret
        "headers": {
            "Authorization": "Bearer x",
            "x-api-key": "visible",
        },
        "nested": {
            "token": "abc",
            "items": [{"secret": "one"}, {"ok": "two"}],  # pragma: allowlist secret
        },
    }

    redacted = _redact_sensitive(payload)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["headers"]["Authorization"] == "[REDACTED]"
    assert redacted["nested"]["token"] == "[REDACTED]"
    assert redacted["nested"]["items"][0]["secret"] == "[REDACTED]"
    assert redacted["nested"]["items"][1]["ok"] == "two"
