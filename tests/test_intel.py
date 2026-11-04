"""intel.enrich against a fake HTTP layer: no test talks to a real service."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import JsonValue

from kale import __version__
from kale.core import ErrorCode, Kind, ModuleResult, Observable, Severity, run_module
from kale.modules.intel import IntelEnrichModule
from kale.modules.intel.privacy import blocked_reason
from kale.modules.intel.providers import PROVIDERS, Reputation, Verdict
from kale.net.cache import TTLCache

PUBLIC_IP = "185.10.20.30"
SHA256 = "c" * 64
PAYLOAD = "a" * 64
ALL_KEYS = {
    "ABUSEIPDB_API_KEY": "abuse-key",
    "ABUSECH_AUTH_KEY": "abusech-key",
    "VIRUSTOTAL_API_KEY": "vt-key",
}
NO_WAIT = {provider.name: 0.0 for provider in PROVIDERS}

GREYNOISE = "https://api.greynoise.io/v3/community/"
ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
BAZAAR = "https://mb-api.abuse.ch/api/v1/"
VT = "https://www.virustotal.com/api/v3/"

Reply = httpx.Response | Exception


class FakeAPI:
    """Routes requests by URL prefix. A list of replies is served in order; the last
    one repeats. Unrouted requests fail the test."""

    def __init__(self) -> None:
        self.routes: dict[str, list[Reply]] = {}
        self.requests: list[httpx.Request] = []

    def add(self, prefix: str, *replies: Reply) -> None:
        self.routes[prefix] = list(replies)

    def json(self, prefix: str, data: JsonValue, status: int = 200) -> None:
        self.add(prefix, httpx.Response(status, json=data))

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        for prefix, replies in self.routes.items():
            if url.startswith(prefix):
                reply = replies.pop(0) if len(replies) > 1 else replies[0]
                if isinstance(reply, Exception):
                    raise reply
                return reply
        raise AssertionError(f"unexpected request: {request.method} {url}")

    def hits(self, prefix: str) -> list[httpx.Request]:
        return [r for r in self.requests if str(r.url).startswith(prefix)]


def form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


@pytest.fixture
def api() -> FakeAPI:
    return FakeAPI()


@pytest.fixture
def cache(tmp_path: Path) -> TTLCache:
    return TTLCache(tmp_path / "cache.sqlite3")


def module(api: FakeAPI, cache: TTLCache | None = None) -> IntelEnrichModule:
    return IntelEnrichModule(
        transport=httpx.MockTransport(api.handle), cache=cache, intervals=NO_WAIT, retry_delay=0
    )


async def enrich(
    api: FakeAPI,
    kind: Kind,
    value: str,
    *,
    cache: TTLCache | None = None,
    environ: dict[str, str] | None = None,
    **options: str,
) -> ModuleResult:
    options.setdefault("cache_hours", "0" if cache is None else "24")
    return await run_module(
        module(api, cache),
        Observable(kind=kind, value=value),
        options=options,
        environ=ALL_KEYS if environ is None else environ,
    )


def malicious_ip_answers(api: FakeAPI) -> None:
    api.json(
        GREYNOISE,
        {
            "ip": PUBLIC_IP,
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "name": "unknown",
            "link": f"https://viz.greynoise.io/ip/{PUBLIC_IP}",
            "last_seen": "2026-11-01",
        },
    )
    api.json(
        ABUSEIPDB,
        {
            "data": {
                "abuseConfidenceScore": 100,
                "totalReports": 37,
                "countryCode": "NL",
                "isp": "Example Hosting",
                "usageType": "Data Center/Web Hosting/Transit",
                "isTor": True,
                "isWhitelisted": False,
                "lastReportedAt": "2026-11-03T10:00:00+00:00",
            }
        },
    )
    api.json(URLHAUS_HOST, {"query_status": "no_results"})
    api.json(VT, {"error": {"code": "NotFoundError"}}, status=404)


def by_rule(result: ModuleResult) -> dict[str, Severity]:
    return {f.rule_id: f.severity for f in result.findings}


async def test_malicious_ip(api: FakeAPI) -> None:
    malicious_ip_answers(api)
    result = await enrich(api, Kind.IP, PUBLIC_IP)
    assert result.ok, result.error
    assert by_rule(result) == {
        "intel.enrich.abuseipdb.malicious": Severity.HIGH,
        "intel.enrich.greynoise.malicious": Severity.HIGH,
    }
    abuse = next(f for f in result.findings if f.rule_id.startswith("intel.enrich.abuseipdb"))
    assert abuse.description == "Abuse confidence 100%, 37 report(s) in 90 days, Tor exit node"
    assert abuse.references == (f"https://www.abuseipdb.com/check/{PUBLIC_IP}",)
    assert "Block it" in abuse.recommendation
    assert result.summary["verdict"] == "malicious"
    sources = result.summary["sources"]
    assert isinstance(sources, dict)
    assert set(sources) == {"greynoise", "abuseipdb", "urlhaus", "virustotal"}
    assert result.summary["errors"] == {}


async def test_keys_travel_only_in_headers(api: FakeAPI) -> None:
    malicious_ip_answers(api)
    await enrich(api, Kind.IP, PUBLIC_IP)
    (abuse,) = api.hits(ABUSEIPDB)
    assert abuse.headers["Key"] == "abuse-key"
    assert abuse.headers["Accept"] == "application/json"
    assert abuse.url.params["ipAddress"] == PUBLIC_IP
    assert abuse.url.params["maxAgeInDays"] == "90"
    assert api.hits(VT)[0].headers["x-apikey"] == "vt-key"
    assert api.hits(URLHAUS_HOST)[0].headers["Auth-Key"] == "abusech-key"
    assert form(api.hits(URLHAUS_HOST)[0]) == {"host": PUBLIC_IP}
    assert "key" not in api.hits(GREYNOISE)[0].headers
    for request in api.requests:
        assert request.headers["User-Agent"] == f"kale/{__version__}"
        assert not any(secret in str(request.url) for secret in ALL_KEYS.values())


async def test_without_keys_only_keyless_sources_run(api: FakeAPI) -> None:
    malicious_ip_answers(api)
    result = await enrich(api, Kind.IP, PUBLIC_IP, environ={"GREYNOISE_API_KEY": "gn"})
    assert {str(r.url).split("?")[0] for r in api.requests} == {GREYNOISE + PUBLIC_IP}
    assert api.requests[0].headers["key"] == "gn"
    assert result.summary["skipped"] == {
        "abuseipdb": "set ABUSEIPDB_API_KEY",
        "urlhaus": "set ABUSECH_AUTH_KEY",
        "virustotal": "set VIRUSTOTAL_API_KEY",
    }


async def test_sources_option(api: FakeAPI) -> None:
    malicious_ip_answers(api)
    result = await enrich(api, Kind.IP, PUBLIC_IP, sources="virustotal")
    assert [str(r.url) for r in api.requests] == [f"{VT}ip_addresses/{PUBLIC_IP}"]
    assert by_rule(result) == {"intel.enrich.no_reports": Severity.INFO}

    bad = await enrich(api, Kind.IP, PUBLIC_IP, sources="virustotal,crystalball")
    assert bad.error is not None
    assert bad.error.code is ErrorCode.INVALID_INPUT
    assert "crystalball" in bad.error.message


@pytest.mark.parametrize(
    ("answer", "reputation", "summary"),
    [
        (
            {"noise": False, "riot": True, "classification": "benign", "name": "Google DNS"},
            "benign",
            "Known business service (Google DNS)",
        ),
        (
            {"noise": True, "riot": False, "classification": "benign", "name": "Shodan.io"},
            "benign",
            "Benign internet scanner (Shodan.io)",
        ),
        (
            {"noise": True, "riot": False, "classification": "unknown"},
            "suspicious",
            "Scans the internet, intent unknown",
        ),
        ({"noise": False, "riot": False}, "unknown", "No GreyNoise record"),
    ],
)
async def test_greynoise_classifications(
    api: FakeAPI, answer: JsonValue, reputation: str, summary: str
) -> None:
    api.json(GREYNOISE, answer)
    result = await enrich(api, Kind.IP, PUBLIC_IP, sources="greynoise")
    source = result.summary["sources"]
    assert isinstance(source, dict)
    assert source["greynoise"] == {
        "reputation": reputation,
        "summary": summary,
        "link": f"https://viz.greynoise.io/ip/{PUBLIC_IP}",
        "cached": False,
    }


async def test_greynoise_not_found(api: FakeAPI) -> None:
    api.json(GREYNOISE, {"message": "IP not observed"}, status=404)
    result = await enrich(api, Kind.IP, PUBLIC_IP, sources="greynoise")
    assert by_rule(result) == {"intel.enrich.no_reports": Severity.INFO}
    assert "Not seen scanning the internet" in result.findings[0].description


@pytest.mark.parametrize(
    ("data", "reputation"),
    [
        ({"abuseConfidenceScore": 40, "totalReports": 3}, "suspicious"),
        ({"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": True}, "benign"),
        ({"abuseConfidenceScore": 90, "totalReports": 9, "isWhitelisted": True}, "malicious"),
        ({"abuseConfidenceScore": 10, "totalReports": 1}, "unknown"),
    ],
)
async def test_abuseipdb_thresholds(
    api: FakeAPI, data: dict[str, JsonValue], reputation: str
) -> None:
    api.json(ABUSEIPDB, {"data": data})
    result = await enrich(api, Kind.IP, PUBLIC_IP, sources="abuseipdb")
    assert result.summary["verdict"] == reputation


async def test_url_lookup_and_payload_hashes(api: FakeAPI) -> None:
    url = "http://evil.example/payload.bin"
    api.json(
        URLHAUS_URL,
        {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exe", "AgentTesla"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
            "payloads": [{"response_sha256": PAYLOAD}, {"response_sha256": "not-a-hash"}, {}],
        },
    )
    api.json(
        VT,
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 0, "harmless": 60},
                }
            }
        },
    )
    result = await enrich(api, Kind.URL, url)
    assert by_rule(result) == {
        "intel.enrich.urlhaus.malicious": Severity.HIGH,
        "intel.enrich.virustotal.suspicious": Severity.MEDIUM,
    }
    assert form(api.hits(URLHAUS_URL)[0]) == {"url": url}
    vt_request = api.hits(VT)[0]
    assert str(vt_request.url) == VT + "urls/aHR0cDovL2V2aWwuZXhhbXBsZS9wYXlsb2FkLmJpbg"
    urlhaus = next(f for f in result.findings if "urlhaus" in f.rule_id)
    assert urlhaus.description == (
        "Listed as a malware distribution URL (status online), tags: exe, AgentTesla"
    )
    assert [str(o) for o in result.observables] == [f"hash:{PAYLOAD}"]
    assert result.observables[0].source == "intel.enrich"


@pytest.mark.parametrize(
    ("answer", "reputation"),
    [
        (
            # the docs spell the key "query_staus" in one example: both spellings work
            {"query_staus": "ok", "url_count": "3", "urls": [{"url_status": "online"}]},
            "malicious",
        ),
        (
            {"query_status": "ok", "url_count": "2", "urls": [{"url_status": "offline"}]},
            "suspicious",
        ),
        ({"query_status": "no_results"}, "unknown"),
    ],
)
async def test_urlhaus_hosts(api: FakeAPI, answer: JsonValue, reputation: str) -> None:
    api.json(URLHAUS_HOST, answer)
    result = await enrich(api, Kind.DOMAIN, "evil.example", sources="urlhaus")
    assert result.summary["verdict"] == reputation


async def test_hash_lookup(api: FakeAPI) -> None:
    api.json(
        BAZAAR,
        {
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": SHA256,
                    "signature": "AgentTesla",
                    "file_type": "exe",
                    "tags": ["AgentTesla"],
                    "first_seen": "2026-10-01 10:00:00",
                }
            ],
        },
    )
    api.json(
        VT,
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 40, "suspicious": 1, "undetected": 20},
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.agenttesla"
                    },
                }
            }
        },
    )
    result = await enrich(api, Kind.HASH, SHA256)
    assert by_rule(result) == {
        "intel.enrich.malwarebazaar.malicious": Severity.HIGH,
        "intel.enrich.virustotal.malicious": Severity.HIGH,
    }
    assert form(api.hits(BAZAAR)[0]) == {"query": "get_info", "hash": SHA256}
    descriptions = {f.rule_id: f.description for f in result.findings}
    assert descriptions["intel.enrich.virustotal.malicious"] == (
        "40 of 61 engines flag it as malicious, 1 as suspicious (trojan.agenttesla)"
    )
    assert descriptions["intel.enrich.malwarebazaar.malicious"].startswith(
        "Known malware sample: AgentTesla (exe)"
    )


async def test_unknown_hash(api: FakeAPI) -> None:
    api.json(BAZAAR, {"query_status": "hash_not_found"})
    api.json(VT, {"data": {"attributes": {"last_analysis_stats": {"undetected": 70}}}})
    result = await enrich(api, Kind.HASH, SHA256)
    assert by_rule(result) == {"intel.enrich.no_reports": Severity.INFO}
    assert "does not prove it is clean" in result.findings[0].description


async def test_sha512_skips_malwarebazaar(api: FakeAPI) -> None:
    api.json(VT, {"error": {}}, status=404)
    await enrich(api, Kind.HASH, "d" * 128)
    assert api.hits(BAZAAR) == []


async def test_ipv6_skips_ipv4_only_sources(api: FakeAPI) -> None:
    api.json(ABUSEIPDB, {"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    api.json(VT, {"error": {}}, status=404)
    await enrich(api, Kind.IP, "2606:4700::1111")
    assert api.hits(GREYNOISE) == [] and api.hits(URLHAUS_HOST) == []


async def test_one_failing_source_is_reported(api: FakeAPI) -> None:
    malicious_ip_answers(api)
    api.json(VT, {"error": {"code": "QuotaExceededError"}}, status=429)
    result = await enrich(api, Kind.IP, PUBLIC_IP)
    assert result.ok
    assert result.summary["errors"] == {"virustotal": "rate limit or quota reached (HTTP 429)"}
    assert by_rule(result)["intel.enrich.source_failed"] is Severity.INFO
    assert len(api.hits(VT)) == 1  # quota errors are not retried


async def test_every_source_failing_fails_the_module(api: FakeAPI) -> None:
    api.json(GREYNOISE, {}, status=401)
    result = await enrich(api, Kind.IP, PUBLIC_IP, environ={})
    assert result.error is not None
    assert result.error.code is ErrorCode.FAILED
    assert "greynoise: API key rejected (HTTP 401)" in result.error.message


async def test_transient_errors_are_retried_once(api: FakeAPI) -> None:
    api.add(
        GREYNOISE,
        httpx.Response(503),
        httpx.Response(200, json={"noise": False, "riot": False}),
    )
    result = await enrich(api, Kind.IP, PUBLIC_IP, environ={})
    assert result.ok
    assert len(api.hits(GREYNOISE)) == 2


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        (httpx.ConnectTimeout("slow"), "timed out"),
        (httpx.ConnectError("refused"), "connection failed (ConnectError)"),
        (httpx.Response(200, text="<html>not json</html>"), "unexpected response format"),
        (httpx.Response(200, json=["a", "list"]), "unexpected response format"),
        (httpx.Response(302), "unexpected HTTP 302"),
    ],
)
async def test_bad_answers(api: FakeAPI, reply: Reply, message: str) -> None:
    api.add(GREYNOISE, reply)
    result = await enrich(api, Kind.IP, PUBLIC_IP, environ={})
    assert result.error is not None
    assert message in result.error.message


@pytest.mark.parametrize(
    ("prefix", "answer"),
    [
        (URLHAUS_URL, {"query_status": "http_post_expected"}),
        (URLHAUS_HOST, {"query_status": "http_post_expected"}),
        (BAZAAR, {"query_status": "illegal_hash"}),
        (ABUSEIPDB, {"data": {"totalReports": 1}}),  # no score: unreadable
    ],
)
async def test_unexpected_query_status(api: FakeAPI, prefix: str, answer: JsonValue) -> None:
    api.json(prefix, answer)
    api.json(GREYNOISE, {"noise": False, "riot": False})
    api.json(VT, {"error": {}}, status=404)
    kind, value, source = {
        URLHAUS_URL: (Kind.URL, "http://evil.example/", "urlhaus"),
        URLHAUS_HOST: (Kind.DOMAIN, "evil.example", "urlhaus"),
        BAZAAR: (Kind.HASH, SHA256, "malwarebazaar"),
        ABUSEIPDB: (Kind.IP, PUBLIC_IP, "abuseipdb"),
    }[prefix]
    result = await enrich(api, kind, value, sources=f"{source},virustotal")
    errors = result.summary["errors"]
    assert isinstance(errors, dict) and source in errors


async def test_answers_are_cached(api: FakeAPI, cache: TTLCache) -> None:
    malicious_ip_answers(api)
    first = await enrich(api, Kind.IP, PUBLIC_IP, cache=cache)
    count = len(api.requests)
    second = await enrich(api, Kind.IP, PUBLIC_IP, cache=cache)
    assert len(api.requests) == count  # nothing was asked again
    assert by_rule(second) == by_rule(first)
    sources = second.summary["sources"]
    assert isinstance(sources, dict)
    assert all(isinstance(s, dict) and s["cached"] for s in sources.values())


async def test_cache_can_be_turned_off(api: FakeAPI, cache: TTLCache) -> None:
    api.json(GREYNOISE, {"noise": False, "riot": False})
    for _ in range(2):
        await enrich(api, Kind.IP, PUBLIC_IP, cache=cache, environ={}, cache_hours="0")
    assert len(api.requests) == 2
    assert cache.get("intel.greynoise.2", f"ip:{PUBLIC_IP}") is None


async def test_a_broken_cache_does_not_break_lookups(api: FakeAPI, tmp_path: Path) -> None:
    class BrokenCache(TTLCache):
        def get(self, namespace: str, key: str) -> JsonValue | None:
            raise sqlite3.OperationalError("database is locked")

        def set(self, namespace: str, key: str, value: JsonValue, ttl: float) -> None:
            raise OSError("read-only file system")

    api.json(GREYNOISE, {"noise": False, "riot": False})
    result = await enrich(api, Kind.IP, PUBLIC_IP, cache=BrokenCache(tmp_path / "c"), environ={})
    assert result.ok


async def test_damaged_cached_verdicts_are_misses(api: FakeAPI, cache: TTLCache) -> None:
    cache.set("intel.greynoise.2", f"ip:{PUBLIC_IP}", {"reputation": "nonsense"}, ttl=600)
    api.json(GREYNOISE, {"noise": False, "riot": False})
    result = await enrich(api, Kind.IP, PUBLIC_IP, cache=cache, environ={})
    assert result.ok
    assert len(api.requests) == 1


@pytest.mark.parametrize(
    ("kind", "value", "reason"),
    [
        (Kind.IP, "10.0.0.5", "private or reserved"),
        (Kind.IP, "203.0.113.7", "private or reserved"),  # documentation range
        (Kind.DOMAIN, "fileserver.corp", "internal name"),
        (Kind.DOMAIN, "printer.home.arpa", "internal name"),
        (Kind.URL, "http://intranet/login", "single-label"),
        (Kind.URL, "https://user:secret@evil.example/", "credentials"),
        (Kind.URL, "http://192.168.1.1/admin", "private or reserved"),
    ],
)
async def test_private_values_never_leave(
    api: FakeAPI, kind: Kind, value: str, reason: str
) -> None:
    result = await enrich(api, kind, value)
    assert api.requests == []
    assert by_rule(result) == {"intel.enrich.not_sent": Severity.INFO}
    assert reason in result.findings[0].title
    assert result.summary["sent"] is False


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        (Kind.IP, PUBLIC_IP),
        (Kind.DOMAIN, "evil.example"),
        (Kind.URL, "https://evil.example/a?b=1"),
        (Kind.HASH, SHA256),
    ],
)
def test_public_values_may_leave(kind: Kind, value: str) -> None:
    assert blocked_reason(Observable(kind=kind, value=value)) is None


async def test_no_configured_source(api: FakeAPI) -> None:
    result = await enrich(api, Kind.HASH, SHA256, environ={})
    assert by_rule(result) == {"intel.enrich.no_sources": Severity.INFO}
    assert result.findings[0].description == (
        "Set ABUSECH_AUTH_KEY, VIRUSTOTAL_API_KEY to enable them."
    )
    nothing = await enrich(api, Kind.HASH, SHA256, environ={}, sources="greynoise")
    assert nothing.findings[0].description == "No source supports it."


def test_verdicts_survive_the_cache_format() -> None:
    verdict = Verdict(
        Reputation.MALICIOUS, "bad", "https://x.example", {"n": 1}, (("hash", PAYLOAD),)
    )
    assert Verdict.from_json(verdict.to_json()) == verdict


def test_default_module_uses_the_user_cache_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("KALE_CACHE_DIR", str(tmp_path))
    cache = IntelEnrichModule()._cache_for(3600)
    assert cache is not None and cache.path == tmp_path / "cache.sqlite3"
    assert IntelEnrichModule()._cache_for(0) is None
