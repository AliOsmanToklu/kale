"""Vulnerability data: NVD and OSV for "what affects this", CISA KEV and EPSS for "how
urgent is it".

* NVD: CVEs whose configurations match a CPE name (version ranges included). Without a
  key it allows 5 requests per 30 seconds and resets connections when pushed, so every
  call is spaced out and retried.
* OSV: advisories for a package URL across the package ecosystems.
* CISA KEV: the catalog of vulnerabilities known to be exploited in the wild.
* EPSS: FIRST's estimate of the probability of exploitation in the next 30 days.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import JsonValue

from kale.net.cache import TTLCache
from kale.net.http import ServiceError, check_status, json_object, send, with_retry
from kale.net.ratelimit import MinInterval

log = logging.getLogger(__name__)

NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_QUERY = "https://api.osv.dev/v1/query"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"

NVD_PAGE = 2000  # the API's maximum resultsPerPage
MAX_PAGES = 10
EPSS_BATCH = 100
CACHE_FORMAT = "1"

# CVSS versions in order of preference
_CVSS_KEYS = ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2")
_QUALITATIVE = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM"}


@dataclass(frozen=True, slots=True)
class KevEntry:
    date_added: str
    ransomware: bool  # "Known" use in ransomware campaigns
    required_action: str
    due_date: str
    name: str

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "date_added": self.date_added,
            "ransomware": self.ransomware,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "name": self.name,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> KevEntry:
        return cls(
            date_added=str(data["date_added"]),
            ransomware=bool(data["ransomware"]),
            required_action=str(data["required_action"]),
            due_date=str(data["due_date"]),
            name=str(data["name"]),
        )


@dataclass(frozen=True, slots=True)
class Vulnerability:
    id: str  # CVE-..., or an OSV id such as GHSA-... or PYSEC-...
    summary: str
    source: str  # "nvd" or "osv"
    link: str
    aliases: tuple[str, ...] = ()
    published: str | None = None
    cvss_score: float | None = None
    cvss_version: str | None = None
    severity: str | None = None  # CRITICAL / HIGH / MEDIUM / LOW
    cwes: tuple[str, ...] = ()
    kev: KevEntry | None = None  # NVD copies CISA's KEV fields into its records

    @property
    def cve_ids(self) -> tuple[str, ...]:
        ids = (self.id, *self.aliases)
        return tuple(dict.fromkeys(i for i in ids if i.startswith("CVE-")))

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "id": self.id,
            "summary": self.summary,
            "source": self.source,
            "link": self.link,
            "aliases": list(self.aliases),
            "published": self.published,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "severity": self.severity,
            "cwes": list(self.cwes),
            "kev": self.kev.to_json() if self.kev else None,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Vulnerability:
        score = data.get("cvss_score")
        return cls(
            id=str(data["id"]),
            summary=str(data["summary"]),
            source=str(data["source"]),
            link=str(data["link"]),
            aliases=tuple(str(a) for a in data.get("aliases") or ()),
            published=data.get("published"),
            cvss_score=float(score) if score is not None else None,
            cvss_version=data.get("cvss_version"),
            severity=data.get("severity"),
            cwes=tuple(str(c) for c in data.get("cwes") or ()),
            kev=KevEntry.from_json(data["kev"]) if data.get("kev") else None,
        )


@dataclass(frozen=True, slots=True)
class Epss:
    probability: float  # 0-1: chance of exploitation activity in the next 30 days
    percentile: float  # 0-1: share of all CVEs with a lower score


class Sources:
    """The four services behind one HTTP client, one cache and per-service rate limits."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        cache: TTLCache | None,
        ttl: float,
        limiters: Mapping[str, MinInterval],
        nvd_key: str | None,
        retry_delay: float,
    ) -> None:
        self._client = client
        self._cache = cache
        self._ttl = ttl
        self._limiters = limiters
        self._nvd_key = nvd_key
        self._retry_delay = retry_delay

    # --- NVD ---------------------------------------------------------------

    async def nvd_for_cpe(self, cpe: str) -> list[Vulnerability]:
        return [
            Vulnerability.from_json(v)
            for v in await self._cached_list("nvd.cpe", cpe, lambda: self._nvd({"cpeName": cpe}))
        ]

    async def nvd_cve(self, cve_id: str) -> Vulnerability | None:
        found = await self._cached_list("nvd.cve", cve_id, lambda: self._nvd({"cveId": cve_id}))
        return Vulnerability.from_json(found[0]) if found else None

    async def _nvd(self, params: Mapping[str, str]) -> list[JsonValue]:
        headers = {"apiKey": self._nvd_key} if self._nvd_key else {}
        vulnerabilities: list[JsonValue] = []
        start = 0
        for _ in range(MAX_PAGES):
            page = {**params, "resultsPerPage": str(NVD_PAGE), "startIndex": str(start)}

            async def fetch(page: dict[str, str] = page) -> tuple[int, int, list[JsonValue]]:
                response = await send(self._client, "GET", NVD_CVES, params=page, headers=headers)
                if response.status_code == 404:  # nothing known under that name
                    return 0, 0, []
                check_status(response)
                data = json_object(response)
                items = data["vulnerabilities"]
                parsed: list[JsonValue] = [
                    parse_nvd(item["cve"]).to_json()
                    for item in items
                    if item["cve"].get("vulnStatus") != "Rejected"
                ]
                return len(items), int(data["totalResults"]), parsed

            count, total, parsed = await with_retry(
                fetch, limiter=self._limiters["nvd"], attempts=3, delay=self._retry_delay
            )
            vulnerabilities += parsed
            start += count
            if not count or start >= total:
                break
        return vulnerabilities

    # --- OSV ---------------------------------------------------------------

    async def osv_for_purl(self, purl: str) -> list[Vulnerability]:
        return [
            Vulnerability.from_json(v)
            for v in await self._cached_list("osv.purl", purl, lambda: self._osv(purl))
        ]

    async def _osv(self, purl: str) -> list[JsonValue]:
        found: list[JsonValue] = []
        body: dict[str, Any] = {"package": {"purl": purl}}
        for _ in range(MAX_PAGES):

            async def fetch(body: dict[str, Any] = body) -> tuple[list[JsonValue], str | None]:
                response = await send(self._client, "POST", OSV_QUERY, json=body)
                if response.status_code == 400:
                    raise ServiceError("OSV rejected the package URL (HTTP 400)")
                check_status(response)
                data = json_object(response)
                parsed: list[JsonValue] = [parse_osv(v).to_json() for v in data.get("vulns") or []]
                token = data.get("next_page_token")
                return parsed, str(token) if token else None

            parsed, token = await with_retry(
                fetch, limiter=self._limiters["osv"], delay=self._retry_delay
            )
            found += parsed
            if not token:
                break
            body = {**body, "page_token": token}
        return found

    # --- CISA KEV ------------------------------------------------------------

    async def kev(self) -> dict[str, KevEntry]:
        catalog = await self._cached("kev", "catalog", self._kev_catalog)
        if not isinstance(catalog, dict):
            raise ServiceError("unexpected response format")
        return {
            cve: KevEntry.from_json(entry)
            for cve, entry in catalog.items()
            if isinstance(entry, dict)
        }

    async def _kev_catalog(self) -> JsonValue:
        async def fetch() -> JsonValue:
            response = await send(self._client, "GET", KEV_FEED)
            check_status(response)
            catalog: dict[str, JsonValue] = {}
            for item in json_object(response)["vulnerabilities"]:
                catalog[str(item["cveID"])] = KevEntry(
                    date_added=str(item.get("dateAdded", "")),
                    ransomware=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
                    required_action=str(item.get("requiredAction", "")),
                    due_date=str(item.get("dueDate", "")),
                    name=str(item.get("vulnerabilityName", "")),
                ).to_json()
            return catalog

        return await with_retry(fetch, limiter=self._limiters["kev"], delay=self._retry_delay)

    # --- EPSS ----------------------------------------------------------------

    async def epss(self, cve_ids: Iterable[str]) -> dict[str, Epss]:
        wanted = sorted(set(cve_ids))
        scores: dict[str, Epss] = {}
        missing: list[str] = []
        for cve in wanted:
            hit = await self._cache_get("epss", cve)
            if not isinstance(hit, dict):
                missing.append(cve)
            elif hit.get("epss") is not None:  # None: EPSS has no score for it (cached too)
                scores[cve] = Epss(_float(hit["epss"]), _float(hit["percentile"]))
        for start in range(0, len(missing), EPSS_BATCH):
            batch = missing[start : start + EPSS_BATCH]

            async def fetch(batch: Sequence[str] = batch) -> dict[str, Epss]:
                response = await send(
                    self._client, "GET", EPSS_API, params={"cve": ",".join(batch)}
                )
                check_status(response)
                return {
                    str(item["cve"]): Epss(_float(item["epss"]), _float(item["percentile"]))
                    for item in json_object(response)["data"]
                }

            found = await with_retry(fetch, limiter=self._limiters["epss"], delay=self._retry_delay)
            scores |= found
            for cve in batch:
                score = found.get(cve)
                cached: JsonValue = (
                    {"epss": score.probability, "percentile": score.percentile}
                    if score
                    else {"epss": None, "percentile": None}
                )
                await self._cache_set("epss", cve, cached)
        return scores

    # --- cache ---------------------------------------------------------------

    async def _cached_list(
        self, namespace: str, key: str, load: Callable[[], Awaitable[list[JsonValue]]]
    ) -> list[Mapping[str, Any]]:
        value = await self._cached(namespace, key, load)
        if not isinstance(value, list):
            raise ServiceError("unexpected response format")
        return [v for v in value if isinstance(v, dict)]

    async def _cached(
        self, namespace: str, key: str, load: Callable[[], Awaitable[JsonValue]]
    ) -> JsonValue:
        hit = await self._cache_get(namespace, key)
        if hit is not None:
            return hit
        value = await load()
        await self._cache_set(namespace, key, value)
        return value

    async def _cache_get(self, namespace: str, key: str) -> JsonValue | None:
        if self._cache is None:
            return None
        try:
            return await asyncio.to_thread(self._cache.get, f"vuln.{namespace}.{CACHE_FORMAT}", key)
        except (sqlite3.Error, OSError):
            log.warning("vulnerability cache unreadable, ignoring it", exc_info=True)
            return None

    async def _cache_set(self, namespace: str, key: str, value: JsonValue) -> None:
        if self._cache is None:
            return
        try:
            await asyncio.to_thread(
                self._cache.set, f"vuln.{namespace}.{CACHE_FORMAT}", key, value, self._ttl
            )
        except (sqlite3.Error, OSError):
            log.warning("vulnerability cache not writable, continuing without it", exc_info=True)


def parse_nvd(cve: Mapping[str, Any]) -> Vulnerability:
    cve_id = str(cve["id"])
    summary = next(
        (str(d["value"]) for d in cve.get("descriptions") or () if d.get("lang") == "en"), ""
    )
    score = version = severity = None
    metrics = cve.get("metrics") or {}
    for key in _CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        metric = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = metric["cvssData"]
        score = float(data["baseScore"])
        version = str(data.get("version") or key.removeprefix("cvssMetricV"))
        # v2 keeps the qualitative severity next to cvssData instead of inside it
        severity = str(data.get("baseSeverity") or metric.get("baseSeverity") or "") or None
        break
    cwes = tuple(
        dict.fromkeys(
            str(d["value"])
            for weakness in cve.get("weaknesses") or ()
            for d in weakness.get("description") or ()
            if str(d.get("value", "")).startswith("CWE-")
        )
    )
    kev = None
    if cve.get("cisaExploitAdd"):
        kev = KevEntry(
            date_added=str(cve["cisaExploitAdd"]),
            ransomware=False,  # only the CISA catalog itself records ransomware use
            required_action=str(cve.get("cisaRequiredAction") or ""),
            due_date=str(cve.get("cisaActionDue") or ""),
            name=str(cve.get("cisaVulnerabilityName") or ""),
        )
    return Vulnerability(
        id=cve_id,
        summary=summary,
        source="nvd",
        link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        published=cve.get("published"),
        cvss_score=score,
        cvss_version=version,
        severity=severity.upper() if severity else None,
        cwes=cwes,
        kev=kev,
    )


def parse_osv(vuln: Mapping[str, Any]) -> Vulnerability:
    """OSV gives CVSS as a vector, not a score; GitHub advisories add a qualitative
    severity, which is what the priority uses for OSV-only records."""
    osv_id = str(vuln["id"])
    summary = str(vuln.get("summary") or str(vuln.get("details") or "").split("\n", 1)[0])
    specific = vuln.get("database_specific") or {}
    qualitative = str(specific.get("severity") or "").upper()
    return Vulnerability(
        id=osv_id,
        summary=summary,
        source="osv",
        link=f"https://osv.dev/vulnerability/{osv_id}",
        aliases=tuple(str(a) for a in vuln.get("aliases") or ()),
        published=vuln.get("published"),
        severity=_QUALITATIVE.get(qualitative, "LOW" if qualitative == "LOW" else None),
        cwes=tuple(str(c) for c in specific.get("cwe_ids") or ()),
    )


def _float(value: object) -> float:
    """EPSS sends its numbers as strings ("0.94358")."""
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        raise ValueError(f"not a number: {value!r}")
    return float(value)
