"""vuln.intel against a fake HTTP layer shaped like the real NVD, OSV, KEV and EPSS answers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import JsonValue

from kale.core import ErrorCode, Kind, ModuleResult, Observable, Severity, run_module
from kale.modules.vuln import VulnIntelModule, sources
from kale.modules.vuln.sources import KevEntry, Vulnerability, parse_nvd
from kale.net.cache import TTLCache
from tests.fakehttp import FakeAPI

NVD = sources.NVD_CVES
OSV = sources.OSV_QUERY
KEV = sources.KEV_FEED
EPSS = sources.EPSS_API
NO_WAIT = {"nvd": 0.0, "nvd_with_key": 0.0, "osv": 0.0, "kev": 0.0, "epss": 0.0}
F5 = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
OLD = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"


def nvd_cve(
    cve_id: str,
    score: float | None = 7.5,
    *,
    kev: bool = False,
    status: str = "Analyzed",
    description: str = "A flaw.",
) -> dict[str, Any]:
    cve: dict[str, Any] = {
        "id": cve_id,
        "published": "2021-06-01T13:15:07.853",
        "vulnStatus": status,
        "descriptions": [
            {"lang": "es", "value": "Un fallo."},
            {"lang": "en", "value": description},
        ],
        "metrics": {},
        "weaknesses": [
            {"type": "Primary", "description": [{"lang": "en", "value": "CWE-787"}]},
            {"type": "Secondary", "description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]},
        ],
    }
    if score is not None:
        cve["metrics"]["cvssMetricV31"] = [
            {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 1.0}},
            {
                "type": "Primary",
                "cvssData": {"version": "3.1", "baseScore": score, "baseSeverity": "HIGH"},
            },
        ]
    if kev:
        cve |= {
            "cisaExploitAdd": "2023-10-10",
            "cisaActionDue": "2023-10-31",
            "cisaRequiredAction": "Apply mitigations per vendor instructions.",
            "cisaVulnerabilityName": "HTTP/2 Rapid Reset Attack Vulnerability",
        }
    return cve


def nvd_page(*cves: dict[str, Any], total: int | None = None, start: int = 0) -> JsonValue:
    return {
        "resultsPerPage": len(cves),
        "startIndex": start,
        "totalResults": len(cves) if total is None else total,
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [{"cve": c} for c in cves],
    }


def kev_feed(*cves: str, ransomware: tuple[str, ...] = ()) -> JsonValue:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "count": len(cves),
        "vulnerabilities": [
            {
                "cveID": cve,
                "dateAdded": "2021-12-10",
                "knownRansomwareCampaignUse": "Known" if cve in ransomware else "Unknown",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-12-24",
                "vulnerabilityName": f"{cve} name",
            }
            for cve in cves
        ],
    }


def epss_handler(scores: dict[str, float]) -> Any:
    def handle(request: httpx.Request) -> httpx.Response:
        wanted = request.url.params["cve"].split(",")
        data = [
            {"cve": cve, "epss": f"{scores[cve]:.9f}", "percentile": "0.900000000", "date": "x"}
            for cve in wanted
            if cve in scores
        ]
        return httpx.Response(200, json={"status": "OK", "total": len(data), "data": data})

    return handle


def nvd_by_cpe(pages: dict[str, JsonValue]) -> Any:
    def handle(request: httpx.Request) -> httpx.Response:
        key = request.url.params.get("cpeName") or request.url.params.get("cveId", "")
        if key not in pages:
            return httpx.Response(200, json=nvd_page())
        return httpx.Response(200, json=pages[key])

    return handle


@pytest.fixture
def api() -> FakeAPI:
    return FakeAPI()


@pytest.fixture
def cache(tmp_path: Path) -> TTLCache:
    return TTLCache(tmp_path / "cache.sqlite3")


async def lookup(
    api: FakeAPI,
    value: str,
    kind: Kind = Kind.SOFTWARE,
    *,
    cache: TTLCache | None = None,
    environ: dict[str, str] | None = None,
    **options: str,
) -> ModuleResult:
    options.setdefault("cache_hours", "0" if cache is None else "24")
    module = VulnIntelModule(
        transport=httpx.MockTransport(api.handle), cache=cache, intervals=NO_WAIT, retry_delay=0
    )
    return await run_module(
        module, Observable(kind=kind, value=value), options=options, environ=environ or {}
    )


def nginx_world(api: FakeAPI) -> None:
    """Rapid Reset (KEV, via NVD and the catalog), the resolver bug (high EPSS) under the
    F5 name, and an old issue only under the original nginx vendor name."""
    api.route(
        NVD,
        nvd_by_cpe(
            {
                F5: nvd_page(
                    nvd_cve("CVE-2023-44487", 7.5, kev=True),
                    nvd_cve("CVE-2021-23017", 7.7),
                    nvd_cve("CVE-2021-3618", 7.4),
                    nvd_cve("CVE-2020-0001", status="Rejected"),
                ),
                OLD: nvd_page(nvd_cve("CVE-2021-23017", 7.7), nvd_cve("CVE-2019-9511", 5.3)),
            }
        ),
    )
    api.json(KEV, kev_feed("CVE-2023-44487", ransomware=("CVE-2023-44487",)))
    api.route(EPSS, epss_handler({"CVE-2021-23017": 0.53, "CVE-2023-44487": 0.94}))


async def test_software_is_ranked_by_exploitation(api: FakeAPI) -> None:
    nginx_world(api)
    result = await lookup(api, "nginx@1.18.0")
    assert result.ok, result.error
    assert [(f.rule_id, f.severity) for f in result.findings] == [
        ("vuln.intel.affected", Severity.CRITICAL),
        ("vuln.intel.cve-2023-44487", Severity.CRITICAL),
        ("vuln.intel.cve-2021-23017", Severity.HIGH),
        ("vuln.intel.cve-2021-3618", Severity.MEDIUM),
        ("vuln.intel.cve-2019-9511", Severity.LOW),
    ]
    headline, rapid_reset, resolver, *_ = result.findings
    assert headline.title == "nginx 1.18.0 has 4 known vulnerabilities, 1 exploited in the wild"
    assert headline.description == "By priority: 1 critical, 1 high, 1 medium, 1 low."
    assert "backport" in headline.recommendation
    assert rapid_reset.description.startswith(
        "In CISA's Known Exploited Vulnerabilities catalog since 2021-12-10, used in ransomware"
    )
    assert rapid_reset.recommendation == "Apply updates per vendor instructions."
    assert rapid_reset.references[1].endswith("CVE-2023-44487")
    assert resolver.description.startswith("EPSS 53%: likely to be exploited within 30 days.")
    assert resolver.evidence["epss"] == 0.53
    assert resolver.evidence["cvss_score"] == 7.7
    assert resolver.evidence["cwes"] == ["CWE-787"]
    assert [str(o) for o in result.observables] == [
        "cve:CVE-2023-44487",
        "cve:CVE-2021-23017",
        "cve:CVE-2021-3618",
        "cve:CVE-2019-9511",
    ]
    assert result.summary["by_priority"] == {"critical": 1, "high": 1, "medium": 1, "low": 1}
    assert result.summary["exploited"] == 1
    queried = sorted(r.url.params["cpeName"] for r in api.hits(NVD))
    assert queried == sorted([F5, OLD])  # both vendor names, results merged


async def test_nvd_request_shape_and_key(api: FakeAPI) -> None:
    nginx_world(api)
    await lookup(api, "nginx@1.18.0", environ={"NVD_API_KEY": "nvd-key"})
    request = api.hits(NVD)[0]
    assert request.headers["apiKey"] == "nvd-key"
    assert request.url.params["resultsPerPage"] == "2000"
    assert request.url.params["startIndex"] == "0"
    assert all("nvd-key" not in str(r.url) for r in api.requests)
    (epss,) = api.hits(EPSS)
    assert sorted(epss.url.params["cve"].split(",")) == [
        "CVE-2019-9511",
        "CVE-2021-23017",
        "CVE-2021-3618",
        "CVE-2023-44487",
    ]


async def test_nvd_pages_are_followed(api: FakeAPI, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sources, "NVD_PAGE", 2)

    def pages(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["startIndex"])
        cves = [nvd_cve(f"CVE-2020-000{i}") for i in range(3)][start : start + 2]
        return httpx.Response(200, json=nvd_page(*cves, total=3, start=start))

    api.route(NVD, pages)
    api.json(KEV, kev_feed())
    api.route(EPSS, epss_handler({}))
    result = await lookup(api, "php@7.4.3")
    assert result.summary["total"] == 3
    assert [r.url.params["startIndex"] for r in api.hits(NVD)] == ["0", "2"]


async def test_max_findings(api: FakeAPI) -> None:
    api.json(NVD, nvd_page(*(nvd_cve(f"CVE-2020-{i:04d}", 5.0 + i / 10) for i in range(15))))
    api.json(KEV, kev_feed())
    api.route(EPSS, epss_handler({}))
    result = await lookup(api, "php@7.4.3", max_findings="3")
    assert len(result.findings) == 4  # the headline and the three most urgent
    assert result.findings[1].rule_id == "vuln.intel.cve-2020-0014"  # highest CVSS first
    assert result.summary["reported"] == 3
    assert len(result.observables) == 3


async def test_javascript_library_through_osv(api: FakeAPI) -> None:
    advisory = {
        "id": "GHSA-jpcq-cgw6-v4j6",
        "summary": "Potential XSS vulnerability in jQuery",
        "aliases": ["CVE-2020-11023"],
        "published": "2020-04-29T22:18:55Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
        "database_specific": {"severity": "MODERATE", "cwe_ids": ["CWE-79"]},
    }
    second = {"id": "GHSA-0000-0000-0000", "details": "Prototype pollution.\nMore text."}
    api.add(
        OSV,
        httpx.Response(200, json={"vulns": [advisory], "next_page_token": "t1"}),
        httpx.Response(200, json={"vulns": [second]}),
    )
    api.json(KEV, kev_feed("CVE-2020-11023"))
    api.route(EPSS, epss_handler({"CVE-2020-11023": 0.02}))
    result = await lookup(api, "jquery@1.12.4")
    assert result.summary["source"] == "osv"
    bodies = [json.loads(r.content) for r in api.hits(OSV)]
    assert bodies == [
        {"package": {"purl": "pkg:npm/jquery@1.12.4"}},
        {"package": {"purl": "pkg:npm/jquery@1.12.4"}, "page_token": "t1"},
    ]
    by_rule = {f.rule_id: f for f in result.findings}
    xss = by_rule["vuln.intel.ghsa-jpcq-cgw6-v4j6"]
    assert xss.severity is Severity.CRITICAL  # its CVE alias is in KEV
    assert xss.evidence["cwes"] == ["CWE-79"]
    assert xss.references[0] == "https://osv.dev/vulnerability/GHSA-jpcq-cgw6-v4j6"
    pollution = by_rule["vuln.intel.ghsa-0000-0000-0000"]
    assert pollution.title == "GHSA-0000-0000-0000: Prototype pollution."
    assert pollution.severity is Severity.LOW
    assert [str(o) for o in result.observables] == ["cve:CVE-2020-11023"]


async def test_osv_rejects_a_bad_purl(api: FakeAPI) -> None:
    api.json(OSV, {"code": 3, "message": "Invalid query."}, status=400)
    result = await lookup(api, "pkg:npm/lodash@not-a-version")
    assert result.error is not None
    assert result.error.code is ErrorCode.FAILED
    assert "OSV lookup failed: OSV rejected the package URL (HTTP 400)" in result.error.message


async def test_single_cve(api: FakeAPI) -> None:
    api.route(NVD, nvd_by_cpe({"CVE-2021-44228": nvd_page(nvd_cve("CVE-2021-44228", 10.0))}))
    api.json(KEV, kev_feed("CVE-2021-44228", ransomware=("CVE-2021-44228",)))
    api.route(EPSS, epss_handler({"CVE-2021-44228": 0.99999}))
    result = await lookup(api, "CVE-2021-44228", Kind.CVE)
    assert [(f.rule_id, f.severity) for f in result.findings] == [
        ("vuln.intel.cve-2021-44228", Severity.CRITICAL)
    ]
    assert result.summary["subject"] == "CVE-2021-44228"
    assert api.hits(NVD)[0].url.params["cveId"] == "CVE-2021-44228"


async def test_unknown_cve(api: FakeAPI) -> None:
    api.json(NVD, nvd_page())
    result = await lookup(api, "CVE-2099-0001", Kind.CVE)
    assert [f.rule_id for f in result.findings] == ["vuln.intel.unknown_cve"]
    assert api.hits(KEV) == [] and api.hits(EPSS) == []  # nothing to prioritize


async def test_no_known_vulnerabilities(api: FakeAPI) -> None:
    api.json(NVD, {"error": "not found"}, status=404)
    result = await lookup(api, "proftpd@1.3.8")
    assert [(f.rule_id, f.severity) for f in result.findings] == [
        ("vuln.intel.no_known_vulnerabilities", Severity.INFO)
    ]


async def test_prioritization_degrades_when_kev_or_epss_fail(api: FakeAPI) -> None:
    api.json(NVD, nvd_page(nvd_cve("CVE-2023-44487", 7.5, kev=True), nvd_cve("CVE-2021-23017")))
    api.add(KEV, httpx.Response(503))
    api.add(EPSS, httpx.Response(200, json={"data": [{"cve": "CVE-2021-23017", "epss": None}]}))
    result = await lookup(api, "nginx@1.18.0")
    assert result.ok
    by_rule = {f.rule_id: f for f in result.findings}
    # NVD's own KEV fields still mark the exploited issue, without ransomware use
    assert by_rule["vuln.intel.cve-2023-44487"].severity is Severity.CRITICAL
    assert "ransomware" not in by_rule["vuln.intel.cve-2023-44487"].description
    assert by_rule["vuln.intel.cve-2021-23017"].severity is Severity.MEDIUM
    notes = result.summary["notes"]
    assert isinstance(notes, list) and len(notes) == 2
    assert "CISA KEV catalog unavailable (service error (HTTP 503))" in str(notes[0])
    assert "EPSS unavailable (unexpected response format (ValueError))" in str(notes[1])
    assert by_rule["vuln.intel.partial_data"].severity is Severity.INFO
    assert len(api.hits(KEV)) == 2  # one retry for the 5xx


async def test_nvd_outage_fails_the_module(api: FakeAPI) -> None:
    api.add(NVD, httpx.ConnectError("connection reset by peer"))
    result = await lookup(api, "nginx@1.18.0")
    assert result.error is not None
    assert result.error.code is ErrorCode.FAILED
    assert result.error.message == "NVD lookup failed: connection failed (ConnectError)"
    assert len(api.hits(NVD)) == 3  # NVD resets connections often: three attempts


async def test_answers_are_cached(api: FakeAPI, cache: TTLCache) -> None:
    nginx_world(api)
    first = await lookup(api, "nginx@1.18.0", cache=cache)
    count = len(api.requests)
    second = await lookup(api, "nginx@1.18.0", cache=cache)
    assert len(api.requests) == count
    assert [f.rule_id for f in second.findings] == [f.rule_id for f in first.findings]
    assert second.findings[2].evidence["epss"] == 0.53


async def test_epss_is_asked_in_batches_and_cached(api: FakeAPI, cache: TTLCache) -> None:
    cves = [nvd_cve(f"CVE-2020-{i:04d}") for i in range(150)]
    api.json(NVD, nvd_page(*cves))
    api.json(KEV, kev_feed())
    api.route(EPSS, epss_handler({c["id"]: 0.01 for c in cves}))
    await lookup(api, "php@7.4.3", cache=cache)
    assert [len(r.url.params["cve"].split(",")) for r in api.hits(EPSS)] == [100, 50]


async def test_unusable_software(api: FakeAPI) -> None:
    result = await lookup(api, "frobnicator@1.0")
    assert result.error is not None
    assert result.error.code is ErrorCode.INVALID_INPUT
    assert api.requests == []


def test_cvss_fallbacks() -> None:
    v2 = {
        "id": "CVE-2010-0001",
        "metrics": {
            "cvssMetricV2": [
                {"type": "Primary", "baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}
            ]
        },
    }
    parsed = parse_nvd(v2)
    assert (parsed.cvss_score, parsed.cvss_version, parsed.severity) == (5.0, "2", "MEDIUM")
    bare = parse_nvd({"id": "CVE-2024-0001"})
    assert (bare.cvss_score, bare.summary, bare.cwes, bare.kev) == (None, "", (), None)


def test_records_survive_the_cache_format() -> None:
    kev = KevEntry("2023-10-10", False, "Patch.", "2023-10-31", "Rapid Reset")
    vulnerability = Vulnerability(
        id="GHSA-1",
        summary="s",
        source="osv",
        link="l",
        aliases=("CVE-2023-44487",),
        cvss_score=7.5,
        cvss_version="3.1",
        severity="HIGH",
        cwes=("CWE-400",),
        kev=kev,
    )
    assert Vulnerability.from_json(vulnerability.to_json()) == vulnerability
    assert vulnerability.cve_ids == ("CVE-2023-44487",)


def test_default_module_uses_the_user_cache_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("KALE_CACHE_DIR", str(tmp_path))
    cache = VulnIntelModule()._cache_for(3600)
    assert cache is not None and cache.path == tmp_path / "cache.sqlite3"
    assert VulnIntelModule()._cache_for(0) is None
