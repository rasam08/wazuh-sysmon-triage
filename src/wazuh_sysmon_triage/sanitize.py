from __future__ import annotations

import ipaddress
import re
from typing import Any

_WINDOWS_USER_PATH_RE = re.compile(r"(?i)(\\+Users\\+)([^\\]+)")
_LINUX_HOME_PATH_RE = re.compile(r"(?i)(/home/)([^/\s]+)")
_DOMAIN_USER_RE = re.compile(
    r"(?<![\\/:])\b([A-Za-z0-9._$-]{2,})\\+([A-Za-z0-9._$-]{2,})\b(?!\\)"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class OutputSanitizer:
    """
    Deterministic sanitizer for publish-safe outputs.

    - Redacts usernames in user principals and home-directory paths.
    - Redacts internal IPv4 addresses (private/loopback/link-local).
    - Preserves stable token mapping per run for analyst readability.
    """

    def __init__(self) -> None:
        self._user_map: dict[str, str] = {}
        self._ip_map: dict[str, str] = {}
        self._user_counter = 0
        self._ip_counter = 0

    def _user_token(self, value: str) -> str:
        key = value.strip().lower()
        if not key:
            return "<user>"
        if key not in self._user_map:
            self._user_counter += 1
            self._user_map[key] = f"user{self._user_counter:03d}"
        return self._user_map[key]

    def _ip_token(self, value: str) -> str:
        if value not in self._ip_map:
            self._ip_counter += 1
            self._ip_map[value] = f"internal-ip-{self._ip_counter:03d}"
        return self._ip_map[value]

    def sanitize_user(self, value: str | None) -> str | None:
        if value is None:
            return None
        text = str(value)
        if "\\" in text:
            domain, username = text.split("\\", 1)
            return f"{domain}\\{self._user_token(username)}"
        if "@" in text:
            local, _, domain = text.partition("@")
            return f"{self._user_token(local)}@{domain}"
        return self._user_token(text)

    def sanitize_ip(self, value: str | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return text
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return self._ip_token(text)
        return text

    def sanitize_text(self, value: str | None) -> str | None:
        if value is None:
            return None
        text = str(value)

        def _windows_user(match: re.Match[str]) -> str:
            return f"{match.group(1)}{self._user_token(match.group(2))}"

        def _linux_user(match: re.Match[str]) -> str:
            return f"{match.group(1)}{self._user_token(match.group(2))}"

        def _domain_user(match: re.Match[str]) -> str:
            return f"{match.group(1)}\\{self._user_token(match.group(2))}"

        def _ip_replace(match: re.Match[str]) -> str:
            replaced = self.sanitize_ip(match.group(0))
            return replaced if replaced is not None else match.group(0)

        text = _WINDOWS_USER_PATH_RE.sub(_windows_user, text)
        text = _LINUX_HOME_PATH_RE.sub(_linux_user, text)
        text = _DOMAIN_USER_RE.sub(_domain_user, text)
        text = _IPV4_RE.sub(_ip_replace, text)
        return text

    def sanitize_obj(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.sanitize_obj(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.sanitize_obj(item) for item in value]
        if isinstance(value, str):
            return self.sanitize_text(value)
        return value
