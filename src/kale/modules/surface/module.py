"""``surface.discover``: a domain's hosts from Certificate Transparency logs, checked in DNS.

Nothing is sent to the hosts themselves: names come from public CT logs, and DNS answers
come from the resolver. That keeps the module passive, so it can run on any domain; the
active follow-up (``web.scan`` on what it finds) still needs a scope.

Findings:

* possible subdomain takeover: a CNAME pointing to a name that does not exist on a
  service where anyone can register that name (Azure, Elastic Beanstalk)
* dangling CNAME: the same on any other service; claimable or not, it should go
* public names that point to private addresses, which describes the internal network
* development and admin hosts that appear in public certificates
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import secrets
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import ClassVar

import httpx
from pydantic import JsonValue

from kale import __version__
from kale.core import (
    Category,
    Finding,
    InvalidInputError,
    KaleError,
    Kind,
    ModuleOutput,
    ModuleSpec,
    Observable,
    Option,
    RunContext,
    Severity,
)
from kale.modules.surface.sources import SOURCES, CTSource
from kale.net.cache import TTLCache, default_cache_dir
from kale.net.dns import DnsAnswer, DnsLookup, Status, system_dns
from kale.net.http import USER_AGENT, ServiceError
from kale.net.privacy import blocked_reason
from kale.net.ratelimit import MinInterval

log = logging.getLogger(__name__)

CACHE_FORMAT = "1"
TAKEOVER_REFERENCE = "https://github.com/EdOverflow/can-i-take-over-xyz"
_HOUR = 3600.0
_LISTED = 20  # names quoted in one finding

# A CNAME to a non-existent name under these suffixes can be claimed by anyone who
# creates a resource with that name (can-i-take-over-xyz: "NXDOMAIN" fingerprint).
TAKEOVER_PROVIDERS: dict[str, str] = {
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud Services",
    "cloudapp.azure.com": "Azure Virtual Machines",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "azureedge.net": "Azure CDN",
    "azure-api.net": "Azure API Management",
    "azurecontainer.io": "Azure Container Instances",
    "azurehdinsight.net": "Azure HDInsight",
    "azurecr.io": "Azure Container Registry",
    "database.windows.net": "Azure SQL Database",
    "search.windows.net": "Azure AI Search",
    "servicebus.windows.net": "Azure Service Bus",
    "redis.cache.windows.net": "Azure Cache for Redis",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
}

_SENSITIVE = re.compile(
    r"^(?:dev|develop|development|staging|stage|stg|test|testing|qa|uat|demo|beta|preview"
    r"|admin|internal|intranet|vpn|jenkins|gitlab|git|jira|confluence|grafana|kibana"
    r"|prometheus|phpmyadmin|pma|cpanel|whm|plesk|backup|old|legacy|db|mysql)\d*$"
)


@dataclass(frozen=True, slots=True)
class Host:
    name: str
    addresses: tuple[str, ...] = ()
    cname: str | None = None
    dangling: bool = False  # the CNAME target does not exist

    @property
    def resolves(self) -> bool:
        return bool(self.addresses)


@dataclass(slots=True)
class Discovery:
    names: set[str] = field(default_factory=set)
    complete: bool = True
    notes: list[str] = field(default_factory=list)
    answered: list[str] = field(default_factory=list)


def takeover_provider(cname: str) -> str | None:
    for suffix, provider in TAKEOVER_PROVIDERS.items():
        if cname == suffix or cname.endswith("." + suffix):
            return provider
    return None


def is_sensitive(name: str, domain: str) -> bool:
    if name == domain:
        return False
    first = name.split(".", 1)[0]
    return any(_SENSITIVE.match(token) for token in first.split("-"))


class SurfaceDiscoverModule:
    spec: ClassVar[ModuleSpec] = ModuleSpec(
        name="surface.discover",
        version=__version__,
        summary="Subdomains from Certificate Transparency logs, dangling CNAMEs and takeovers",
        category=Category.RECON,
        accepts=frozenset({Kind.DOMAIN}),
        optional_secrets=frozenset(s.key_env for s in SOURCES if s.key_env),
        options={
            "sources": Option(
                "str", "", f"comma-separated subset of: {', '.join(s.name for s in SOURCES)}"
            ),
            "max_names": Option(
                "int",
                300,
                "names checked in DNS; the rest are only counted",
                minimum=1,
                maximum=5000,
            ),
            "max_observables": Option(
                "int", 50, "hosts and addresses passed on to other modules", minimum=0
            ),
            "cache_hours": Option(
                "float", 24.0, "reuse CT answers this long; 0 disables the cache", minimum=0
            ),
            "timeout": Option("float", 30.0, "seconds per request", minimum=1, maximum=300),
        },
        timeout=900.0,
    )

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        cache: TTLCache | None = None,
        dns_lookup: DnsLookup | None = None,
        intervals: Mapping[str, float] | None = None,
        retry_delay: float = 5.0,
        concurrency: int = 20,
    ) -> None:
        self._transport = transport
        self._cache = cache
        self._dns = dns_lookup
        self._sources = [cls() for cls in SOURCES]
        overrides = intervals or {}
        self._limiters = {s.name: MinInterval(overrides.get(s.name, 2.0)) for s in self._sources}
        self._retry_delay = retry_delay
        self._concurrency = concurrency

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        reason = blocked_reason(target)
        if reason:
            raise InvalidInputError(f"not sent to Certificate Transparency services: {reason}")
        domain = target.value
        sources = self._select(ctx.get_str("sources"))
        ttl = ctx.get_float("cache_hours") * _HOUR
        cache = (self._cache or TTLCache(default_cache_dir() / "cache.sqlite3")) if ttl else None

        async with httpx.AsyncClient(
            transport=self._transport,
            timeout=ctx.get_float("timeout"),
            headers={"User-Agent": USER_AGENT},
        ) as client:
            discovery = await self._discover(client, domain, sources, ctx.secrets, cache, ttl)
        discovery.names.add(domain)

        dns = self._dns or system_dns()
        limit = ctx.get_int("max_names")
        names = sorted(discovery.names, key=lambda n: (n.count("."), n))
        checked = names[:limit]
        if len(names) > limit:
            discovery.notes.append(f"Only {limit} of {len(names)} names were checked in DNS.")
        wildcard = await _has_wildcard(dns, domain)
        hosts = await self._inspect(dns, checked)
        return _output(domain, names, hosts, discovery, wildcard, ctx.get_int("max_observables"))

    def _select(self, value: str) -> list[CTSource]:
        names = {n.strip() for n in value.split(",") if n.strip()}
        known = {s.name for s in self._sources}
        unknown = sorted(names - known)
        if unknown:
            raise InvalidInputError(
                f"unknown source(s): {', '.join(unknown)} (available: {', '.join(sorted(known))})"
            )
        return [s for s in self._sources if not names or s.name in names]

    async def _discover(
        self,
        client: httpx.AsyncClient,
        domain: str,
        sources: Sequence[CTSource],
        keys: Mapping[str, str],
        cache: TTLCache | None,
        ttl: float,
    ) -> Discovery:
        discovery = Discovery()

        async def one(source: CTSource) -> None:
            namespace = f"surface.ct.{source.name}.{CACHE_FORMAT}"
            hit = await _cache_get(cache, namespace, domain)
            cached_names = hit.get("names") if isinstance(hit, dict) else None
            if isinstance(hit, dict) and isinstance(cached_names, list):
                discovery.names |= {str(n) for n in cached_names}
                discovery.complete &= bool(hit.get("complete"))
                discovery.answered.append(source.name)
                return
            try:
                names, complete = await source.names(
                    client,
                    domain,
                    key=keys.get(source.key_env) if source.key_env else None,
                    limiter=self._limiters[source.name],
                    retry_delay=self._retry_delay,
                )
            except ServiceError as exc:
                discovery.notes.append(f"{source.label} failed: {exc}.")
                return
            discovery.names |= names
            discovery.answered.append(source.name)
            if not complete:
                discovery.complete = False
                discovery.notes.append(f"{source.label} returned only its first pages.")
            await _cache_set(
                cache, namespace, domain, {"names": list(sorted(names)), "complete": complete}, ttl
            )

        await asyncio.gather(*(one(s) for s in sources))
        if not discovery.answered:
            raise KaleError(
                "every Certificate Transparency source failed: " + "; ".join(discovery.notes)
            )
        return discovery

    async def _inspect(self, dns: DnsLookup, names: Sequence[str]) -> list[Host]:
        gate = asyncio.Semaphore(self._concurrency)

        async def inspect(name: str) -> Host:
            async with gate:
                cname_answer = await dns(name, "CNAME")
                cname = cname_answer.records[0] if cname_answer.status is Status.OK else None
                a = await dns(name, "A")
                addresses = a.records if a.status is Status.OK else ()
                dangling = False
                if cname and not addresses:
                    target: DnsAnswer = await dns(cname, "A")
                    dangling = target.status is Status.NXDOMAIN  # not on timeouts
                return Host(name, addresses, cname, dangling)

        return list(await asyncio.gather(*(inspect(n) for n in names)))


async def _has_wildcard(dns: DnsLookup, domain: str) -> bool:
    probe = f"kale-{secrets.token_hex(6)}.{domain}"
    return (await dns(probe, "A")).status is Status.OK


async def _cache_get(cache: TTLCache | None, namespace: str, key: str) -> JsonValue | None:
    if cache is None:
        return None
    try:
        return await asyncio.to_thread(cache.get, namespace, key)
    except (sqlite3.Error, OSError):
        log.warning("surface cache unreadable, ignoring it", exc_info=True)
        return None


async def _cache_set(
    cache: TTLCache | None, namespace: str, key: str, value: JsonValue, ttl: float
) -> None:
    if cache is None:
        return
    try:
        await asyncio.to_thread(cache.set, namespace, key, value, ttl)
    except (sqlite3.Error, OSError):
        log.warning("surface cache not writable, continuing without it", exc_info=True)


def _listing(names: Iterable[str]) -> str:
    items = sorted(names)
    shown = ", ".join(items[:_LISTED])
    return shown + (f" and {len(items) - _LISTED} more" if len(items) > _LISTED else "")


def _output(
    domain: str,
    names: Sequence[str],
    hosts: Sequence[Host],
    discovery: Discovery,
    wildcard: bool,
    max_observables: int,
) -> ModuleOutput:
    findings: list[Finding] = []
    for host in hosts:
        if not host.dangling or host.cname is None:
            continue
        provider = takeover_provider(host.cname)
        if provider:
            findings.append(
                Finding(
                    rule_id="surface.discover.takeover",
                    severity=Severity.HIGH,
                    title=f"Possible subdomain takeover: {host.name}",
                    description=(
                        f"{host.name} is a CNAME to {host.cname}, which does not exist. Anyone "
                        f"who creates {host.cname} on {provider} can serve content, set cookies "
                        f"and receive e-mail for {host.name}."
                    ),
                    recommendation=(
                        f"Delete the CNAME record, or re-create the resource on {provider} "
                        "before someone else does."
                    ),
                    evidence={"name": host.name, "cname": host.cname, "provider": provider},
                    references=(TAKEOVER_REFERENCE,),
                )
            )
        else:
            findings.append(
                Finding(
                    rule_id="surface.discover.dangling_cname",
                    severity=Severity.MEDIUM,
                    title=f"Dangling DNS record: {host.name}",
                    description=(
                        f"{host.name} is a CNAME to {host.cname}, which does not exist. If that "
                        "name can be registered, whoever registers it controls the subdomain."
                    ),
                    recommendation="Delete the record, or point it at a resource you control.",
                    evidence={"name": host.name, "cname": host.cname},
                    references=(TAKEOVER_REFERENCE,),
                )
            )

    private = {
        host.name: [a for a in host.addresses if not ipaddress.ip_address(a).is_global]
        for host in hosts
    }
    private = {name: addresses for name, addresses in private.items() if addresses}
    if private:
        findings.append(
            Finding(
                rule_id="surface.discover.private_addresses",
                severity=Severity.LOW,
                title=f"{len(private)} public name(s) point to private addresses",
                description=(
                    "Public DNS answers with internal addresses reveal how the internal network "
                    f"is laid out: {_listing(f'{n} ({a[0]})' for n, a in private.items())}."
                ),
                recommendation="Publish internal names only in internal (split-horizon) DNS.",
                evidence={"hosts": {name: list(addresses) for name, addresses in private.items()}},
            )
        )

    sensitive = [h.name for h in hosts if h.resolves and is_sensitive(h.name, domain)]
    if sensitive:
        findings.append(
            Finding(
                rule_id="surface.discover.sensitive_hosts",
                severity=Severity.LOW,
                title=f"{len(sensitive)} development or admin host(s) are publicly listed",
                description=(
                    "Certificates for these names are public, so attackers find them as easily "
                    f"as you do: {_listing(sensitive)}."
                ),
                recommendation=(
                    "Check that each one is meant to be reachable from the internet; put test "
                    "and admin systems behind a VPN or an IP allowlist."
                ),
                evidence={"hosts": sensitive},
            )
        )

    resolving = [h for h in hosts if h.resolves]
    findings.append(
        Finding(
            rule_id="surface.discover.hosts",
            severity=Severity.INFO,
            title=f"{len(names)} name(s) in certificate logs, {len(resolving)} resolve",
            description=(
                f"Sources: {', '.join(discovery.answered)}."
                + (" The domain has wildcard DNS: every name resolves." if wildcard else "")
                + (" " + " ".join(discovery.notes) if discovery.notes else "")
            ),
            evidence={
                "names": len(names),
                "checked": len(hosts),
                "resolving": len(resolving),
                "dns_wildcard": wildcard,
                "complete": discovery.complete,
                "hosts": [
                    {"name": h.name, "addresses": list(h.addresses), "cname": h.cname}
                    for h in resolving
                ],
            },
        )
    )

    observables: list[Observable] = []
    for host in resolving:
        if host.name != domain and len(observables) < max_observables:
            observables.append(Observable(kind=Kind.DOMAIN, value=host.name))
    addresses = sorted(
        {a for h in resolving for a in h.addresses if ipaddress.ip_address(a).is_global}
    )
    observables += [Observable(kind=Kind.IP, value=a) for a in addresses[:max_observables]]

    return ModuleOutput(
        findings=tuple(findings),
        observables=tuple(observables),
        summary={
            "domain": domain,
            "names": len(names),
            "resolving": len(resolving),
            "dns_wildcard": wildcard,
            "sources": list(discovery.answered),
            "notes": list(discovery.notes),
        },
    )
