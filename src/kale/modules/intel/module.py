"""``intel.enrich``: what threat intelligence sources know about an IP, domain, URL or hash.

Every source answers independently; one that is down, rate limited or not configured is
reported and skipped, never fatal, unless all of them fail. Answers are cached (24 hours
by default) because free tiers are small and investigations ask about the same values
again and again.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import ClassVar

import httpx
from pydantic import JsonValue, ValidationError

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
from kale.modules.intel.providers import PROVIDERS, Provider, ProviderError, Reputation, Verdict
from kale.net.cache import TTLCache, default_cache_dir
from kale.net.http import USER_AGENT, with_retry
from kale.net.privacy import blocked_reason
from kale.net.ratelimit import MinInterval

log = logging.getLogger(__name__)

CACHE_FORMAT = "2"  # bump when verdict parsing changes, so old cached answers are ignored
_HOUR = 3600.0

_SEVERITY = {
    Reputation.MALICIOUS: Severity.HIGH,
    Reputation.SUSPICIOUS: Severity.MEDIUM,
    Reputation.BENIGN: Severity.INFO,
}
_ADVICE = {
    Reputation.MALICIOUS: (
        "Block it (firewall, proxy, EDR) and search your logs for any other contact with it."
    ),
    Reputation.SUSPICIOUS: (
        "Treat it with caution: compare with the other sources and your own logs first."
    ),
    Reputation.BENIGN: "",
}


@dataclass(frozen=True, slots=True)
class Outcome:
    provider: Provider
    verdict: Verdict | None
    error: str | None = None
    cached: bool = False


class IntelEnrichModule:
    spec: ClassVar[ModuleSpec] = ModuleSpec(
        name="intel.enrich",
        version=__version__,
        summary="Reputation of an IP, domain, URL or file hash from threat intelligence sources",
        category=Category.THREAT_INTEL,
        accepts=frozenset({Kind.IP, Kind.DOMAIN, Kind.URL, Kind.HASH}),
        optional_secrets=frozenset(provider.key_env for provider in PROVIDERS),
        options={
            "sources": Option(
                "str",
                "",
                f"comma-separated subset of: {', '.join(p.name for p in PROVIDERS)}",
            ),
            "cache_hours": Option(
                "float", 24.0, "reuse answers this long; 0 disables the cache", minimum=0
            ),
            "timeout": Option("float", 15.0, "seconds per request", minimum=1, maximum=120),
        },
        timeout=300.0,
    )

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        cache: TTLCache | None = None,
        providers: Sequence[type[Provider]] = PROVIDERS,
        intervals: Mapping[str, float] | None = None,
        retry_delay: float = 2.0,
    ) -> None:
        self._transport = transport
        self._cache = cache
        self._providers = [cls() for cls in providers]
        overrides = intervals or {}
        self._limiters = {
            p.name: MinInterval(overrides.get(p.name, p.min_interval)) for p in self._providers
        }
        self._retry_delay = retry_delay

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        reason = blocked_reason(target)
        if reason:
            return _not_sent(reason)

        requested = self._requested(ctx.get_str("sources"))
        candidates = [
            p
            for p in self._providers
            if p.supports(target) and (requested is None or p.name in requested)
        ]
        usable = [p for p in candidates if not p.key_required or p.key_env in ctx.secrets]
        skipped = {p.name: f"set {p.key_env}" for p in candidates if p not in usable}
        if not usable:
            return _no_sources(target, candidates)

        ttl = ctx.get_float("cache_hours") * _HOUR
        cache = self._cache_for(ttl)
        async with httpx.AsyncClient(
            transport=self._transport,
            timeout=ctx.get_float("timeout"),
            headers={"User-Agent": USER_AGENT},
        ) as client:
            outcomes = await asyncio.gather(
                *(
                    self._lookup(p, client, target, ctx.secrets.get(p.key_env), cache, ttl)
                    for p in usable
                )
            )
        return _output(target, outcomes, skipped)

    def _requested(self, value: str) -> set[str] | None:
        names = {name.strip() for name in value.split(",") if name.strip()}
        known = {p.name for p in self._providers}
        unknown = sorted(names - known)
        if unknown:
            raise InvalidInputError(
                f"unknown source(s): {', '.join(unknown)} (available: {', '.join(sorted(known))})"
            )
        return names or None

    def _cache_for(self, ttl: float) -> TTLCache | None:
        if ttl <= 0:
            return None
        return self._cache or TTLCache(default_cache_dir() / "cache.sqlite3")

    async def _lookup(
        self,
        provider: Provider,
        client: httpx.AsyncClient,
        target: Observable,
        key: str | None,
        cache: TTLCache | None,
        ttl: float,
    ) -> Outcome:
        namespace = f"intel.{provider.name}.{CACHE_FORMAT}"
        cache_key = f"{target.kind}:{target.value}"
        if cache is not None:
            hit = await _cache_get(cache, namespace, cache_key)
            if hit is not None:
                return Outcome(provider, hit, cached=True)
        try:
            verdict = await self._fetch(provider, client, target, key)
        except ProviderError as exc:
            return Outcome(provider, None, error=str(exc))
        if cache is not None:
            await _cache_set(cache, namespace, cache_key, verdict, ttl)
        return Outcome(provider, verdict)

    async def _fetch(
        self, provider: Provider, client: httpx.AsyncClient, target: Observable, key: str | None
    ) -> Verdict:
        """One retry for transient failures (timeouts, 5xx); quota errors are not retried."""
        return await with_retry(
            lambda: provider.lookup(client, target, key),
            limiter=self._limiters[provider.name],
            delay=self._retry_delay,
        )


async def _cache_get(cache: TTLCache, namespace: str, key: str) -> Verdict | None:
    try:
        data = await asyncio.to_thread(cache.get, namespace, key)
        return Verdict.from_json(data) if isinstance(data, dict) else None
    except (sqlite3.Error, OSError, KeyError, TypeError, ValueError):
        log.warning("intel cache unreadable, ignoring it", exc_info=True)
        return None


async def _cache_set(
    cache: TTLCache, namespace: str, key: str, verdict: Verdict, ttl: float
) -> None:
    try:
        await asyncio.to_thread(cache.set, namespace, key, verdict.to_json(), ttl)
    except (sqlite3.Error, OSError):
        log.warning("intel cache not writable, continuing without it", exc_info=True)


def _not_sent(reason: str) -> ModuleOutput:
    return ModuleOutput(
        findings=(
            Finding(
                rule_id="intel.enrich.not_sent",
                severity=Severity.INFO,
                title=f"Not sent to external sources: {reason}",
                description=(
                    "kale never sends private addresses, internal names or URLs with "
                    "credentials to third parties."
                ),
            ),
        ),
        summary={"sent": False, "reason": reason},
    )


def _no_sources(target: Observable, candidates: Iterable[Provider]) -> ModuleOutput:
    keys = sorted({p.key_env for p in candidates})
    hint = f"Set {', '.join(keys)} to enable them." if keys else "No source supports it."
    return ModuleOutput(
        findings=(
            Finding(
                rule_id="intel.enrich.no_sources",
                severity=Severity.INFO,
                title=f"No configured source can look up this {target.kind}",
                description=hint,
                evidence={"missing_keys": list(keys)},
            ),
        ),
        summary={"sent": False, "missing_keys": list(keys)},
    )


def _output(
    target: Observable, outcomes: Sequence[Outcome], skipped: Mapping[str, str]
) -> ModuleOutput:
    answered = [(o, o.verdict) for o in outcomes if o.verdict is not None]
    errors = {o.provider.name: o.error or "" for o in outcomes if o.verdict is None}
    if not answered:
        failures = "; ".join(f"{name}: {error}" for name, error in errors.items())
        raise KaleError(f"every source failed ({failures})")

    findings = [
        _finding(outcome.provider, verdict)
        for outcome, verdict in answered
        if verdict.reputation is not Reputation.UNKNOWN
    ]
    if not findings:
        findings.append(
            Finding(
                rule_id="intel.enrich.no_reports",
                severity=Severity.INFO,
                title=f"No source has reports on {target.value}",
                description="; ".join(f"{o.provider.label}: {v.summary}" for o, v in answered),
            )
        )
    if errors:
        findings.append(
            Finding(
                rule_id="intel.enrich.source_failed",
                severity=Severity.INFO,
                title=f"{len(errors)} source(s) could not be checked",
                description="; ".join(f"{name}: {error}" for name, error in errors.items()),
            )
        )

    worst = min((verdict.reputation for _, verdict in answered), key=lambda r: r.rank)
    sources: dict[str, JsonValue] = {
        outcome.provider.name: {
            "reputation": verdict.reputation.value,
            "summary": verdict.summary,
            "link": verdict.link,
            "cached": outcome.cached,
        }
        for outcome, verdict in answered
    }
    return ModuleOutput(
        findings=tuple(findings),
        observables=tuple(_related(verdict for _, verdict in answered)),
        summary={
            "sent": True,
            "verdict": worst.value,
            "sources": sources,
            "errors": dict(errors),
            "skipped": dict(skipped),
        },
    )


def _finding(provider: Provider, verdict: Verdict) -> Finding:
    return Finding(
        rule_id=f"intel.enrich.{provider.name}.{verdict.reputation}",
        severity=_SEVERITY[verdict.reputation],
        title=f"{provider.label} reports it as {verdict.reputation}",
        description=verdict.summary,
        recommendation=_ADVICE[verdict.reputation],
        evidence={
            "source": provider.name,
            "reputation": verdict.reputation.value,
            "details": verdict.details,
        },
        references=(verdict.link,) if verdict.link else (),
    )


def _related(verdicts: Iterable[Verdict]) -> list[Observable]:
    related: list[Observable] = []
    for verdict in verdicts:
        for kind, value in verdict.related:
            try:
                related.append(Observable(kind=Kind(kind), value=value))
            except (ValueError, ValidationError):
                continue  # values come from a third party; skip anything malformed
    return related
