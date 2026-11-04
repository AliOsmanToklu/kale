"""``vuln.intel``: known vulnerabilities of a software version, or the details of a CVE,
in the order a defender should look at them.

Priority (the finding's severity):

* critical: in CISA's Known Exploited Vulnerabilities catalog (exploited in the wild)
* high: EPSS >= 10% (likely to be exploited within 30 days) or CVSS >= 9
* medium: CVSS >= 7
* low: everything else

CVSS alone says how bad an exploit would be, not how likely one is, so ranking by it
buries the handful of issues attackers actually use under hundreds of theoretical ones.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import ClassVar

import httpx
from pydantic import JsonValue

from kale import __version__
from kale.core import (
    Category,
    Finding,
    KaleError,
    Kind,
    ModuleOutput,
    ModuleSpec,
    Observable,
    Option,
    RunContext,
    Severity,
)
from kale.modules.vuln.software import parse_software
from kale.modules.vuln.sources import Epss, KevEntry, Sources, Vulnerability
from kale.net.cache import TTLCache, default_cache_dir
from kale.net.http import USER_AGENT, ServiceError
from kale.net.ratelimit import MinInterval

NVD_KEY_ENV = "NVD_API_KEY"
EPSS_HIGH = 0.10
_HOUR = 3600.0
_TITLE_LENGTH = 110

# Seconds between requests. NVD: 5 per 30 s without a key, 50 per 30 s with one.
INTERVALS = {"nvd": 6.5, "nvd_with_key": 0.7, "osv": 0.2, "kev": 0.0, "epss": 0.2}


@dataclass(frozen=True, slots=True)
class Ranked:
    vulnerability: Vulnerability
    priority: Severity
    reason: str
    kev: KevEntry | None
    epss: Epss | None


def prioritize(
    vulnerability: Vulnerability, kev: KevEntry | None, epss: Epss | None
) -> tuple[Severity, str]:
    if kev is not None:
        reason = f"In CISA's Known Exploited Vulnerabilities catalog since {kev.date_added}"
        if kev.ransomware:
            reason += ", used in ransomware campaigns"
        return Severity.CRITICAL, reason
    if epss is not None and epss.probability >= EPSS_HIGH:
        return Severity.HIGH, f"EPSS {epss.probability:.0%}: likely to be exploited within 30 days"
    score = vulnerability.cvss_score
    if score is not None:
        reason = f"CVSS {vulnerability.cvss_version or ''} {score:g}".replace("  ", " ")
        if score >= 9:
            return Severity.HIGH, reason
        if score >= 7:
            return Severity.MEDIUM, reason
        return Severity.LOW, reason
    severity = vulnerability.severity
    if severity == "CRITICAL":
        return Severity.HIGH, "Rated critical by the advisory"
    if severity == "HIGH":
        return Severity.MEDIUM, "Rated high by the advisory"
    return Severity.LOW, f"Rated {severity.lower()} by the advisory" if severity else "No score"


class VulnIntelModule:
    spec: ClassVar[ModuleSpec] = ModuleSpec(
        name="vuln.intel",
        version=__version__,
        summary="Known vulnerabilities of a software version or CVE, ranked with CISA KEV and EPSS",
        category=Category.VULNERABILITY,
        accepts=frozenset({Kind.SOFTWARE, Kind.CVE}),
        optional_secrets=frozenset({NVD_KEY_ENV}),
        options={
            "max_findings": Option(
                "int",
                10,
                "vulnerabilities reported one by one; the rest are counted",
                minimum=1,
                maximum=200,
            ),
            "cache_hours": Option(
                "float", 24.0, "reuse answers this long; 0 disables the cache", minimum=0
            ),
            "timeout": Option("float", 60.0, "seconds per request", minimum=1, maximum=300),
        },
        timeout=900.0,
    )

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        cache: TTLCache | None = None,
        intervals: Mapping[str, float] | None = None,
        retry_delay: float = 5.0,
    ) -> None:
        self._transport = transport
        self._cache = cache
        intervals = {**INTERVALS, **(intervals or {})}
        # One limiter per service for the module's lifetime: `kale investigate` runs the
        # module many times in a row, and NVD's spacing has to hold across those runs.
        self._limiters = {name: MinInterval(seconds) for name, seconds in intervals.items()}
        self._retry_delay = retry_delay

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        nvd_key = ctx.secrets.get(NVD_KEY_ENV)
        query = parse_software(target.value) if target.kind is Kind.SOFTWARE else None
        ttl = ctx.get_float("cache_hours") * _HOUR
        limiters = {name: self._limiters[name] for name in ("osv", "kev", "epss")}
        limiters["nvd"] = self._limiters["nvd_with_key" if nvd_key else "nvd"]
        async with httpx.AsyncClient(
            transport=self._transport,
            timeout=ctx.get_float("timeout"),
            headers={"User-Agent": USER_AGENT},
        ) as client:
            sources = Sources(
                client,
                cache=self._cache_for(ttl),
                ttl=ttl,
                limiters=limiters,
                nvd_key=nvd_key,
                retry_delay=self._retry_delay,
            )
            try:
                if query is None:
                    found = await sources.nvd_cve(target.value)
                    vulnerabilities = [found] if found else []
                    origin = "nvd"
                elif query.purl:
                    vulnerabilities = await sources.osv_for_purl(query.purl)
                    origin = "osv"
                else:
                    vulnerabilities = _merge([await sources.nvd_for_cpe(c) for c in query.cpes])
                    origin = "nvd"
            except ServiceError as exc:
                raise KaleError(f"{origin_name(query)} lookup failed: {exc}") from None
            notes: list[str] = []
            kev, epss = await _enrich(sources, vulnerabilities, notes)

        ranked = sorted(
            (_rank(v, kev, epss) for v in vulnerabilities),
            key=lambda r: (
                r.priority.rank,
                -(r.epss.probability if r.epss else 0.0),
                -(r.vulnerability.cvss_score or 0.0),
                r.vulnerability.id,
            ),
        )
        display = query.display if query else target.value
        limit = ctx.get_int("max_findings")
        return _output(target, display, origin, ranked, limit, notes)

    def _cache_for(self, ttl: float) -> TTLCache | None:
        if ttl <= 0:
            return None
        return self._cache or TTLCache(default_cache_dir() / "cache.sqlite3")


def origin_name(query: object) -> str:
    return "OSV" if getattr(query, "purl", None) else "NVD"


def _merge(groups: Sequence[Sequence[Vulnerability]]) -> list[Vulnerability]:
    merged: dict[str, Vulnerability] = {}
    for group in groups:
        for vulnerability in group:
            merged.setdefault(vulnerability.id, vulnerability)
    return list(merged.values())


async def _enrich(
    sources: Sources, vulnerabilities: Sequence[Vulnerability], notes: list[str]
) -> tuple[dict[str, KevEntry] | None, dict[str, Epss] | None]:
    """KEV and EPSS only raise priorities. When one is down the CVEs are still
    reported, ranked by CVSS, with a note saying what is missing."""
    cve_ids = [c for v in vulnerabilities for c in v.cve_ids]
    if not cve_ids:
        return {}, {}
    kev: dict[str, KevEntry] | None
    epss: dict[str, Epss] | None
    try:
        kev = await sources.kev()
    except ServiceError as exc:
        kev = None
        notes.append(
            f"CISA KEV catalog unavailable ({exc}): exploitation is taken from NVD "
            "records only, without ransomware use"
        )
    try:
        epss = await sources.epss(cve_ids)
    except ServiceError as exc:
        epss = None
        notes.append(f"EPSS unavailable ({exc}): ranking uses CVSS only")
    return kev, epss


def _rank(
    vulnerability: Vulnerability,
    kev: Mapping[str, KevEntry] | None,
    epss: Mapping[str, Epss] | None,
) -> Ranked:
    entry = next((kev[c] for c in vulnerability.cve_ids if kev and c in kev), vulnerability.kev)
    score = max(
        (epss[c] for c in vulnerability.cve_ids if epss and c in epss),
        key=lambda e: e.probability,
        default=None,
    )
    priority, reason = prioritize(vulnerability, entry, score)
    return Ranked(vulnerability, priority, reason, entry, score)


def _output(
    target: Observable,
    display: str,
    origin: str,
    ranked: Sequence[Ranked],
    limit: int,
    notes: Sequence[str],
) -> ModuleOutput:
    counts = Counter(r.priority.value for r in ranked)
    exploited = sum(1 for r in ranked if r.kev is not None)
    findings: list[Finding] = []
    if target.kind is Kind.SOFTWARE:
        findings.append(_headline(display, origin, ranked, counts, exploited))
    elif not ranked:
        findings.append(
            Finding(
                rule_id="vuln.intel.unknown_cve",
                severity=Severity.INFO,
                title=f"{target.value} is not in NVD",
                description="It may be reserved, rejected or not published yet.",
            )
        )
    findings += [_finding(r) for r in ranked[:limit]]
    if notes:
        findings.append(
            Finding(
                rule_id="vuln.intel.partial_data",
                severity=Severity.INFO,
                title="Some prioritization data was unavailable",
                description=" ".join(notes),
            )
        )
    by_priority: dict[str, JsonValue] = {
        s.value: counts[s.value] for s in Severity if counts[s.value]
    }
    return ModuleOutput(
        findings=tuple(findings),
        observables=tuple(
            Observable(kind=Kind.CVE, value=cve)
            for r in ranked[:limit]
            for cve in r.vulnerability.cve_ids
        ),
        summary={
            "subject": display,
            "source": origin,
            "total": len(ranked),
            "exploited": exploited,
            "by_priority": by_priority,
            "reported": min(limit, len(ranked)),
            "notes": list(notes),
        },
    )


def _headline(
    display: str,
    origin: str,
    ranked: Sequence[Ranked],
    counts: Mapping[str, int],
    exploited: int,
) -> Finding:
    if not ranked:
        return Finding(
            rule_id="vuln.intel.no_known_vulnerabilities",
            severity=Severity.INFO,
            title=f"No known vulnerabilities for {display}",
            description=(
                f"{origin.upper()} lists none. The detected version may be wrong, or the "
                "product may be published under another name."
            ),
        )
    total = len(ranked)
    title = f"{display} has {total} known vulnerabilit{'y' if total == 1 else 'ies'}"
    if exploited:
        title += f", {exploited} exploited in the wild"
    breakdown = ", ".join(f"{counts[s.value]} {s.value}" for s in Severity if counts[s.value])
    return Finding(
        rule_id="vuln.intel.affected",  # sorts before the CVE findings
        severity=ranked[0].priority,
        title=title,
        description=f"By priority: {breakdown}.",
        recommendation=(
            "Upgrade to a release that fixes these issues, starting with the exploited ones. "
            "Linux distributions often backport fixes without changing the version number: "
            "check the distribution's package before acting."
        ),
        evidence={"total": total, "exploited": exploited, "by_priority": dict(counts)},
    )


def _finding(ranked: Ranked) -> Finding:
    vulnerability = ranked.vulnerability
    summary = vulnerability.summary or "No description."
    short = summary if len(summary) <= _TITLE_LENGTH else summary[: _TITLE_LENGTH - 1] + "…"
    references = [vulnerability.link]
    if ranked.kev is not None:
        cve = vulnerability.cve_ids[0]
        references.append(
            f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}"
        )
    evidence: dict[str, JsonValue] = {
        "priority_reason": ranked.reason,
        "cvss_score": vulnerability.cvss_score,
        "cvss_version": vulnerability.cvss_version,
        "severity": vulnerability.severity,
        "epss": ranked.epss.probability if ranked.epss else None,
        "epss_percentile": ranked.epss.percentile if ranked.epss else None,
        "kev": ranked.kev.to_json() if ranked.kev else None,
        "published": vulnerability.published,
        "cwes": list(vulnerability.cwes),
        "aliases": list(vulnerability.aliases),
    }
    return Finding(
        rule_id=f"vuln.intel.{vulnerability.id.lower()}",
        severity=ranked.priority,
        title=f"{vulnerability.id}: {short}",
        description=f"{ranked.reason}. {summary}",
        recommendation=ranked.kev.required_action if ranked.kev else "",
        evidence=evidence,
        references=tuple(references),
    )
