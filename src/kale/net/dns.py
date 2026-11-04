"""Async DNS lookups with a result type that keeps the cases recon cares about apart.

"The name does not exist" (NXDOMAIN) and "the name exists but has no record of this
type" (no answer) mean very different things for a CNAME target, and a timeout means
neither. Modules take a ``DnsLookup`` so tests can answer without a resolver.
"""

from __future__ import annotations

import enum
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import dns.resolver

DEFAULT_LIFETIME = 5.0


class Status(enum.StrEnum):
    OK = "ok"
    NXDOMAIN = "nxdomain"  # the name does not exist
    NO_ANSWER = "no_answer"  # the name exists, without records of this type
    ERROR = "error"  # timeout, SERVFAIL, refused: nothing can be concluded


@dataclass(frozen=True, slots=True)
class DnsAnswer:
    status: Status
    records: tuple[str, ...] = ()


DnsLookup = Callable[[str, str], Awaitable[DnsAnswer]]


def system_dns(lifetime: float = DEFAULT_LIFETIME) -> DnsLookup:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = lifetime

    async def lookup(name: str, rdtype: str) -> DnsAnswer:
        try:
            answer = await resolver.resolve(name, rdtype)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(Status.NXDOMAIN)
        except dns.resolver.NoAnswer:
            return DnsAnswer(Status.NO_ANSWER)
        except dns.exception.DNSException:
            return DnsAnswer(Status.ERROR)
        records = tuple(record.to_text().rstrip(".").lower() for record in answer)
        return DnsAnswer(Status.OK, records)

    return lookup
