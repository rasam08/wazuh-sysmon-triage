from __future__ import annotations

from wazuh_sysmon_triage.sanitize import OutputSanitizer


def test_windows_user_path_redacted() -> None:
    sanitizer = OutputSanitizer()
    sanitized = sanitizer.sanitize_text(r"C:\Users\alice\Documents\file.txt")
    assert sanitized == r"C:\Users\user001\Documents\file.txt"


def test_linux_home_path_redacted() -> None:
    sanitizer = OutputSanitizer()
    sanitized = sanitizer.sanitize_text("/home/bob/scripts/test.sh")
    assert sanitized == "/home/user001/scripts/test.sh"


def test_domain_user_redacted() -> None:
    sanitizer = OutputSanitizer()
    sanitized = sanitizer.sanitize_text(r"CORP\alice")
    assert sanitized == r"CORP\user001"


def test_private_ipv4_redacted() -> None:
    sanitizer = OutputSanitizer()
    sanitized = sanitizer.sanitize_text("192.168.1.100")
    assert sanitized == "internal-ip-001"


def test_loopback_ipv4_redacted() -> None:
    sanitizer = OutputSanitizer()
    sanitized = sanitizer.sanitize_text("127.0.0.1")
    assert sanitized == "internal-ip-001"


def test_public_ipv4_unchanged() -> None:
    sanitizer = OutputSanitizer()
    sanitized = sanitizer.sanitize_text("8.8.8.8")
    assert sanitized == "8.8.8.8"


def test_stable_token_mapping() -> None:
    sanitizer = OutputSanitizer()
    first = sanitizer.sanitize_text(r"C:\Users\alice\a.txt")
    second = sanitizer.sanitize_text("/home/alice/scripts/test.sh")
    assert first is not None
    assert second is not None
    assert "\\user001\\" in first
    assert "/home/user001/" in second


def test_nested_dict_and_list() -> None:
    sanitizer = OutputSanitizer()
    payload = {"user": r"CORP\dave", "items": [r"C:\Users\dave\x"]}
    sanitized = sanitizer.sanitize_obj(payload)
    assert sanitized == {"user": r"CORP\user001", "items": [r"C:\Users\user001\x"]}


def test_empty_string() -> None:
    sanitizer = OutputSanitizer()
    assert sanitizer.sanitize_text("") == ""


def test_none_value() -> None:
    sanitizer = OutputSanitizer()
    assert sanitizer.sanitize_text(None) is None
