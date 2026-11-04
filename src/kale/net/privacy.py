"""What never leaves the machine (shared by every module that asks third parties).

Looking a value up in a threat intelligence service discloses it to that service. Private
addresses and internal host names reveal the user's network, and a URL with credentials
in it reveals the credentials, so these are refused before any request is made. Hashes
are always fine: only the digest is sent, never the file.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from kale.core import Kind, Observable

# Names that only make sense inside a network (RFC 6761/6762/8375 and common practice)
INTERNAL_SUFFIXES = (
    "local",
    "localhost",
    "localdomain",
    "lan",
    "home",
    "home.arpa",
    "internal",
    "intranet",
    "corp",
    "test",
    "invalid",
)


def blocked_reason(target: Observable) -> str | None:
    """Why ``target`` must not be sent to an external service, or ``None`` if it may be."""
    if target.kind is Kind.IP:
        return _ip_reason(target.value)
    if target.kind is Kind.DOMAIN:
        return _host_reason(target.value)
    if target.kind is Kind.URL:
        parts = urlsplit(target.value)
        if parts.username or parts.password:
            return "the URL contains credentials"
        return _host_reason(parts.hostname or "")
    return None


def _ip_reason(value: str) -> str | None:
    address = ipaddress.ip_address(value)
    if not address.is_global:
        return f"{address} is a private or reserved address"
    return None


def _host_reason(host: str) -> str | None:
    try:
        return _ip_reason(host)
    except ValueError:
        pass
    name = host.lower().rstrip(".")
    if "." not in name:
        return f"{name or 'the host'} is a single-label (internal) name"
    if any(name == suffix or name.endswith("." + suffix) for suffix in INTERNAL_SUFFIXES):
        return f"{name} is an internal name"
    return None
