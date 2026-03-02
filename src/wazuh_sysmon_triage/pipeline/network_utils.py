from __future__ import annotations

import ipaddress


def destination_class(value: str | None) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "private"
    return "public"
