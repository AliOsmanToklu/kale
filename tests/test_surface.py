"""surface.discover against fake CT services and a fake resolver: no network."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import pytest
from pydantic import JsonValue

from kale.core import ErrorCode, Kind, ModuleResult, Observable, Severity, run_module
from kale.modules.surface import SurfaceDiscoverModule
from kale.modules.surface.module import is_sensitive, takeover_provider
from kale.modules.surface.sources import CertSpotter, CrtSh, in_domain
from kale.net import dns as kale_dns
from kale.net.cache import TTLCache
from kale.net.dns import DnsAnswer, Status
from tests.fakehttp import FakeAPI

CRTSH = CrtSh.URL
SPOTTER = CertSpotter.URL
NO_WAIT = {"crtsh": 0.0, "certspotter": 0.0}


class FakeDNS:
    """Answers from a table; anything else does not exist (or has no CNAME)."""

    def __init__(self, records: Mapping[tuple[str, str], DnsAnswer] | None = None) -> None:
        self.records = dict(records or {})
        self.asked: list[tuple[str, str]] = []
        self.wildcard = False

    def a(self, name: str, *addresses: str) -> None:
        self.records[(name, "A")] = DnsAnswer(Status.OK, addresses)

    def cname(self, name: str, target: str) -> None:
        self.records[(name, "CNAME")] = DnsAnswer(Status.OK, (target,))

    async def __call__(self, name: str, rdtype: str) -> DnsAnswer:
        self.asked.append((name, rdtype))
        if (name, rdtype) in self.records:
            return self.records[(name, rdtype)]
        if self.wildcard and rdtype == "A" and name.startswith("kale-"):
            return DnsAnswer(Status.OK, ("203.0.113.9",))
        return DnsAnswer(Status.NO_ANSWER if rdtype == "CNAME" else Status.NXDOMAIN)


def crtsh_rows(*name_values: str) -> JsonValue:
    return [
        {"issuer_name": "C=US, O=Let's Encrypt", "common_name": nv.split("\n")[0], "name_value": nv}
        for nv in name_values
    ]


@pytest.fixture
def api() -> FakeAPI:
    return FakeAPI()


@pytest.fixture
def resolver() -> FakeDNS:
    return FakeDNS()


async def discover(
    api: FakeAPI,
    resolver: FakeDNS,
    domain: str = "example.com",
    *,
    cache: TTLCache | None = None,
    environ: dict[str, str] | None = None,
    **options: str,
) -> ModuleResult:
    options.setdefault("cache_hours", "0" if cache is None else "24")
    module = SurfaceDiscoverModule(
        transport=httpx.MockTransport(api.handle),
        cache=cache,
        dns_lookup=resolver,
        intervals=NO_WAIT,
        retry_delay=0,
    )
    return await run_module(
        module, Observable(kind=Kind.DOMAIN, value=domain), options=options, environ=environ or {}
    )


def by_rule(result: ModuleResult) -> dict[str, Any]:
    return {f.rule_id: f for f in result.findings}


def standard_world(api: FakeAPI, resolver: FakeDNS) -> None:
    api.json(
        CRTSH,
        crtsh_rows(
            "example.com\nwww.example.com",
            "*.example.com",
            "DEV.example.com\nadmin-panel.example.com",
            "old-shop.example.com",  # gone: no finding
            "intranet.example.com",
            "hostmaster@example.com",  # e-mail address in a certificate
            "example.com.attacker.net\nnot a host",
        ),
    )
    api.json(SPOTTER, [{"id": "1", "dns_names": ["www.example.com", "legacy.example.com"]}])
    resolver.a("example.com", "93.184.215.14")
    resolver.cname("www.example.com", "example.edgekey.net")
    resolver.a("www.example.com", "93.184.215.14", "23.215.0.136")
    resolver.a("dev.example.com", "93.184.215.20")
    resolver.a("admin-panel.example.com", "93.184.215.15")
    resolver.a("intranet.example.com", "10.1.2.3")
    resolver.cname("legacy.example.com", "shop-legacy.azurewebsites.net")


async def test_hosts_and_findings(api: FakeAPI, resolver: FakeDNS) -> None:
    standard_world(api, resolver)
    result = await discover(api, resolver)
    assert result.ok, result.error
    assert [(f.rule_id, f.severity) for f in result.findings] == [
        ("surface.discover.takeover", Severity.HIGH),
        ("surface.discover.private_addresses", Severity.LOW),
        ("surface.discover.sensitive_hosts", Severity.LOW),
        ("surface.discover.hosts", Severity.INFO),
    ]
    rules = by_rule(result)
    takeover = rules["surface.discover.takeover"]
    assert takeover.title == "Possible subdomain takeover: legacy.example.com"
    assert takeover.evidence == {
        "name": "legacy.example.com",
        "cname": "shop-legacy.azurewebsites.net",
        "provider": "Azure App Service",
    }
    assert (
        "intranet.example.com (10.1.2.3)" in rules["surface.discover.private_addresses"].description
    )
    assert rules["surface.discover.sensitive_hosts"].evidence == {
        "hosts": ["admin-panel.example.com", "dev.example.com", "intranet.example.com"]
    }
    hosts = rules["surface.discover.hosts"]
    assert hosts.title == "7 name(s) in certificate logs, 5 resolve"
    assert hosts.evidence["dns_wildcard"] is False
    assert result.summary["sources"] == ["crtsh", "certspotter"]
    assert [str(o) for o in result.observables] == [
        "domain:admin-panel.example.com",
        "domain:dev.example.com",
        "domain:intranet.example.com",
        "domain:www.example.com",
        "ip:23.215.0.136",
        "ip:93.184.215.14",
        "ip:93.184.215.15",
        "ip:93.184.215.20",
    ]  # 10.1.2.3 is private: never passed on


async def test_dangling_cname_on_another_service(api: FakeAPI, resolver: FakeDNS) -> None:
    api.json(CRTSH, crtsh_rows("docs.example.com\nstatus.example.com"))
    api.json(SPOTTER, [])
    resolver.cname("docs.example.com", "example-docs.gitbook.io")
    resolver.cname("status.example.com", "example.statuspage.io")
    resolver.records[("example.statuspage.io", "A")] = DnsAnswer(Status.ERROR)  # a timeout
    result = await discover(api, resolver)
    rules = by_rule(result)
    assert rules["surface.discover.dangling_cname"].severity is Severity.MEDIUM
    assert rules["surface.discover.dangling_cname"].evidence["name"] == "docs.example.com"
    assert sum(f.rule_id == "surface.discover.dangling_cname" for f in result.findings) == 1


async def test_wildcard_dns_is_reported(api: FakeAPI, resolver: FakeDNS) -> None:
    api.json(CRTSH, crtsh_rows("example.com"))
    api.json(SPOTTER, [])
    resolver.wildcard = True
    result = await discover(api, resolver)
    hosts = by_rule(result)["surface.discover.hosts"]
    assert "wildcard DNS" in hosts.description
    assert result.summary["dns_wildcard"] is True
    probes = [name for name, _ in resolver.asked if name.startswith("kale-")]
    assert len(probes) == 1 and probes[0].endswith(".example.com")


async def test_limits(api: FakeAPI, resolver: FakeDNS) -> None:
    names = "\n".join(f"h{i:02d}.example.com" for i in range(30))
    api.json(CRTSH, crtsh_rows(names, "a.b.example.com"))
    api.json(SPOTTER, [])
    for i in range(30):
        resolver.a(f"h{i:02d}.example.com", f"93.184.216.{i}")
    result = await discover(api, resolver, max_names="10", max_observables="3")
    hosts = by_rule(result)["surface.discover.hosts"]
    assert hosts.evidence["checked"] == 10
    assert "Only 10 of 32 names were checked in DNS." in hosts.description
    checked = {name for name, rdtype in resolver.asked if rdtype == "CNAME"}
    assert "example.com" in checked and "a.b.example.com" not in checked  # shallow names first
    assert [o.kind for o in result.observables] == [Kind.DOMAIN] * 3 + [Kind.IP] * 3


async def test_certspotter_pages_and_budget(api: FakeAPI, resolver: FakeDNS) -> None:
    def pages(request: httpx.Request) -> httpx.Response:
        after = request.url.params.get("after")
        number = int(after) if after else 0
        items = [{"id": str(number + 1), "dns_names": [f"p{number}.example.com"]}]
        next_link = f'<https://api.certspotter.com/issuances?after={number + 1}>; rel="next"'
        return httpx.Response(200, json=items, headers={"link": next_link})

    api.route(SPOTTER, pages)
    result = await discover(api, resolver, sources="certspotter")
    requests = api.hits(SPOTTER)
    assert [r.url.params.get("after") for r in requests] == [None, "1"]
    assert all(str(r.url).startswith(SPOTTER) for r in requests)  # not the broken next link
    assert requests[0].url.params["include_subdomains"] == "true"
    assert "Authorization" not in requests[0].headers
    assert (
        "CertSpotter returned only its first pages."
        in by_rule(result)["surface.discover.hosts"].description
    )

    api.requests.clear()
    await discover(api, resolver, sources="certspotter", environ={"CERTSPOTTER_API_KEY": "k"})
    requests = api.hits(SPOTTER)
    assert len(requests) == CertSpotter.PAGES_WITH_KEY
    assert requests[0].headers["Authorization"] == "Bearer k"


async def test_certspotter_last_page(api: FakeAPI, resolver: FakeDNS) -> None:
    api.json(SPOTTER, [{"id": "7", "dns_names": ["www.example.com"]}])  # no next link
    result = await discover(api, resolver, sources="certspotter")
    assert by_rule(result)["surface.discover.hosts"].evidence["complete"] is True
    assert len(api.hits(SPOTTER)) == 1


async def test_crtsh_query(api: FakeAPI, resolver: FakeDNS) -> None:
    api.json(CRTSH, crtsh_rows("www.example.com"))
    await discover(api, resolver, sources="crtsh")
    (request,) = api.hits(CRTSH)
    assert request.url.params["q"] == "%.example.com"
    assert request.url.params["output"] == "json"


async def test_one_source_failing_is_a_note(api: FakeAPI, resolver: FakeDNS) -> None:
    api.add(CRTSH, httpx.Response(502))
    api.json(SPOTTER, [{"id": "1", "dns_names": ["www.example.com"]}])
    result = await discover(api, resolver)
    assert result.ok
    assert result.summary["notes"] == ["crt.sh failed: service error (HTTP 502)."]
    assert len(api.hits(CRTSH)) == 2  # one retry for the 5xx


async def test_every_source_failing_fails_the_module(api: FakeAPI, resolver: FakeDNS) -> None:
    api.json(CRTSH, {"not": "a list"})
    api.add(SPOTTER, httpx.Response(429))
    result = await discover(api, resolver)
    assert result.error is not None
    assert result.error.code is ErrorCode.FAILED
    assert "crt.sh failed: unexpected response format" in result.error.message
    assert "CertSpotter failed: rate limit or quota reached (HTTP 429)" in result.error.message


async def test_answers_are_cached(api: FakeAPI, resolver: FakeDNS, tmp_path: Path) -> None:
    standard_world(api, resolver)
    cache = TTLCache(tmp_path / "cache.sqlite3")
    first = await discover(api, resolver, cache=cache)
    count = len(api.requests)
    second = await discover(api, resolver, cache=cache)
    assert len(api.requests) == count  # CT answers reused; DNS is always asked fresh
    assert second.summary["names"] == first.summary["names"]


async def test_internal_names_are_not_sent(api: FakeAPI, resolver: FakeDNS) -> None:
    result = await discover(api, resolver, "corp.local")
    assert result.error is not None
    assert result.error.code is ErrorCode.INVALID_INPUT
    assert api.requests == [] and resolver.asked == []


async def test_unknown_source(api: FakeAPI, resolver: FakeDNS) -> None:
    result = await discover(api, resolver, sources="shodan")
    assert result.error is not None
    assert "shodan" in result.error.message


def test_in_domain() -> None:
    names = in_domain(
        [
            "*.Example.com",
            "www.example.com.",
            "a@example.com",
            "x y",
            "evil-example.com",
            "-bad.example.com",
        ],
        "example.com",
    )
    assert names == {"example.com", "www.example.com"}


@pytest.mark.parametrize(
    ("cname", "provider"),
    [
        ("shop.azurewebsites.net", "Azure App Service"),
        ("app.eu-west-1.elasticbeanstalk.com", "AWS Elastic Beanstalk"),
        ("files.blob.core.windows.net", "Azure Blob Storage"),
        ("notazurewebsites.net", None),
        ("example.github.io", None),
    ],
)
def test_takeover_provider(cname: str, provider: str | None) -> None:
    assert takeover_provider(cname) == provider


@pytest.mark.parametrize(
    ("name", "sensitive"),
    [
        ("dev.example.com", True),
        ("dev2.example.com", True),
        ("blog-stage.example.com", True),
        ("jenkins.ci.example.com", True),
        ("developer-docs.example.com", False),
        ("www.example.com", False),
        ("example.com", False),
    ],
)
def test_is_sensitive(name: str, sensitive: bool) -> None:
    assert is_sensitive(name, "example.com") is sensitive


@pytest.mark.parametrize(
    ("raised", "status"),
    [
        (dns.resolver.NXDOMAIN(), Status.NXDOMAIN),  # type: ignore[no-untyped-call]
        (dns.resolver.NoAnswer(), Status.NO_ANSWER),  # type: ignore[no-untyped-call]
        (dns.exception.Timeout(), Status.ERROR),  # type: ignore[no-untyped-call]
    ],
)
async def test_system_dns_statuses(
    monkeypatch: pytest.MonkeyPatch, raised: Exception, status: Status
) -> None:
    async def resolve(self: object, name: str, rdtype: str) -> object:
        raise raised

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    assert (await kale_dns.system_dns()("x.example.com", "A")).status is status


async def test_system_dns_records(monkeypatch: pytest.MonkeyPatch) -> None:
    class Record:
        def __init__(self, text: str) -> None:
            self.text = text

        def to_text(self) -> str:
            return self.text

    async def resolve(self: object, name: str, rdtype: str) -> list[Record]:
        return [Record("Target.Example.NET.")]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    answer = await kale_dns.system_dns()("x.example.com", "CNAME")
    assert answer == DnsAnswer(Status.OK, ("target.example.net",))
