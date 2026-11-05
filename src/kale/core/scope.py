"""Which targets active modules may touch.

Active modules (web and port scans) send traffic to the target, which can be illegal
without the owner's permission. They only run against targets the user lists in a
scope: domains (including their subdomains) and IP networks. Private and reserved
addresses additionally need ``allow_private``.

A domain in scope can still resolve to an address outside it; modules that connect
re-check the resolved address themselves (Kalkan's SSRF guard does).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from kale.core.errors import InvalidInputError, OutOfScopeError
from kale.core.models import Kind, Observable, normalize_hostname

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class Scope:
    domains: frozenset[str] = frozenset()
    networks: tuple[IPNetwork, ...] = ()
    allow_private: bool = False

    @classmethod
    def parse(cls, entries: Iterable[str], *, allow_private: bool = False) -> Scope:
        """Build a scope from lines like ``example.com``, ``*.example.org``, ``203.0.113.0/24``.

        Blank lines and ``#`` comments are ignored, so a scope file can be passed as is.
        """
        domains: set[str] = set()
        networks: list[IPNetwork] = []
        for raw in entries:
            entry = _parse_entry(raw)
            if isinstance(entry, str):
                domains.add(entry)
            elif entry is not None:
                networks.append(entry)
        return cls(frozenset(domains), tuple(networks), allow_private)

    def covers(self, entry: str) -> bool:
        """Whether the scope entry ``entry`` lies entirely inside this scope."""
        parsed = _parse_entry(entry)
        if parsed is None:
            raise InvalidInputError(f"invalid scope entry: {entry.strip()!r}")
        if isinstance(parsed, str):
            return any(parsed == d or parsed.endswith("." + d) for d in self.domains)
        return any(_subnet_of(parsed, network) for network in self.networks)

    def narrow(self, entries: Iterable[str], *, allow_private: bool = False) -> Scope:
        """The scope ``entries`` describe, which must not reach outside this one.

        Every entry this scope does not cover is listed in a single error, and private
        addresses can only be requested when this scope allows them.
        """
        requested = list(entries)
        wider = [
            raw.split("#", 1)[0].strip()
            for raw in requested
            if _parse_entry(raw) is not None and not self.covers(raw)
        ]
        if wider:
            raise InvalidInputError(f"not covered by the server scope: {', '.join(wider)}")
        if allow_private and not self.allow_private:
            raise InvalidInputError("private addresses are not allowed by the server")
        return Scope.parse(requested, allow_private=allow_private)

    def entries(self) -> list[str]:
        """The scope as entries ``parse`` reads back: domains sorted, then networks."""
        return [*sorted(self.domains), *(str(network) for network in self.networks)]

    @property
    def empty(self) -> bool:
        return not self.domains and not self.networks

    def check(self, target: Observable) -> None:
        """Raise ``OutOfScopeError`` unless ``target`` may be touched."""
        host = _network_host(target)
        if isinstance(host, str):
            if any(host == d or host.endswith("." + d) for d in self.domains):
                return
            raise OutOfScopeError(f"{host} is not in the authorized scope")
        if not host.is_global and not self.allow_private:
            raise OutOfScopeError(
                f"{host} is a private or reserved address; allow private addresses explicitly "
                "to test internal networks"
            )
        if any(host in network for network in self.networks):
            return
        raise OutOfScopeError(f"{host} is not in the authorized scope")


def _parse_entry(raw: str) -> str | IPNetwork | None:
    """A hostname or a network for one scope line, or ``None`` for a blank or comment line."""
    entry = raw.split("#", 1)[0].strip()
    if not entry:
        return None
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        pass
    try:
        return normalize_hostname(entry.removeprefix("*."))
    except ValueError:
        raise InvalidInputError(f"invalid scope entry: {raw.strip()!r}") from None


def _subnet_of(inner: IPNetwork, outer: IPNetwork) -> bool:
    if isinstance(inner, ipaddress.IPv4Network) and isinstance(outer, ipaddress.IPv4Network):
        return inner.subnet_of(outer)
    if isinstance(inner, ipaddress.IPv6Network) and isinstance(outer, ipaddress.IPv6Network):
        return inner.subnet_of(outer)
    return False


def _network_host(target: Observable) -> str | IPAddress:
    if target.kind is Kind.IP:
        return ipaddress.ip_address(target.value)
    if target.kind is Kind.DOMAIN:
        return target.value
    if target.kind is Kind.URL:
        hostname = urlsplit(target.value).hostname or ""
        try:
            return ipaddress.ip_address(hostname)
        except ValueError:
            pass
        try:
            return normalize_hostname(hostname)
        except ValueError as exc:
            raise InvalidInputError(str(exc)) from None
    raise OutOfScopeError(f"a scope only covers network targets, not {target.kind}")
