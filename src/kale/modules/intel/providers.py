"""Threat intelligence sources. Each one turns an API answer into a :class:`Verdict`.

Answers are untrusted input too: a provider that cannot read a response raises
``ProviderError`` instead of guessing. Keys only ever travel in request headers, so they
cannot end up in URLs, logs or error messages.
"""

from __future__ import annotations

import abc
import base64
import enum
import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import quote

import httpx
from pydantic import JsonValue

from kale.core import Kind, Observable

MAX_RELATED = 10  # payload hashes taken from one URLhaus answer


class Reputation(enum.StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"  # the source has no data, or no opinion

    @property
    def rank(self) -> int:
        return list(Reputation).index(self)


class ProviderError(Exception):
    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient  # worth one retry: timeouts, 5xx


@dataclass(frozen=True, slots=True)
class Verdict:
    reputation: Reputation
    summary: str
    link: str | None = None
    details: dict[str, JsonValue] = field(default_factory=dict)
    related: tuple[tuple[str, str], ...] = ()  # (kind, value), e.g. payload hashes

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "reputation": self.reputation.value,
            "summary": self.summary,
            "link": self.link,
            "details": self.details,
            "related": [[kind, value] for kind, value in self.related],
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Verdict:
        return cls(
            reputation=Reputation(data["reputation"]),
            summary=str(data["summary"]),
            link=data.get("link"),
            details=dict(data.get("details") or {}),
            related=tuple((str(kind), str(value)) for kind, value in data.get("related") or ()),
        )


class Provider(abc.ABC):
    name: ClassVar[str]
    label: ClassVar[str]
    kinds: ClassVar[frozenset[Kind]]
    key_env: ClassVar[str]
    key_required: ClassVar[bool] = True
    min_interval: ClassVar[float] = 1.0  # seconds between requests (free tier limits)

    def supports(self, target: Observable) -> bool:
        return target.kind in self.kinds

    @abc.abstractmethod
    async def lookup(
        self, client: httpx.AsyncClient, target: Observable, key: str | None
    ) -> Verdict: ...


async def send(client: httpx.AsyncClient, method: str, url: str, **kwargs: Any) -> httpx.Response:
    try:
        return await client.request(method, url, **kwargs)
    except httpx.TimeoutException:
        raise ProviderError("timed out", transient=True) from None
    except httpx.HTTPError as exc:
        raise ProviderError(f"connection failed ({type(exc).__name__})", transient=True) from None


def check_status(response: httpx.Response) -> None:
    code = response.status_code
    if code in (401, 403):
        raise ProviderError(f"API key rejected (HTTP {code})")
    if code == 429:
        raise ProviderError("rate limit or quota reached (HTTP 429)")
    if code >= 500:
        raise ProviderError(f"service error (HTTP {code})", transient=True)
    if not 200 <= code < 300:
        raise ProviderError(f"unexpected HTTP {code}")


def json_object(response: httpx.Response) -> dict[str, Any]:
    data = response.json()  # ValueError on invalid JSON: reported as a bad response
    if not isinstance(data, dict):
        raise ProviderError("unexpected response format")
    return data


def _is_ipv4(target: Observable) -> bool:
    try:
        return ipaddress.ip_address(target.value).version == 4
    except ValueError:  # a domain or URL
        return True


class GreyNoise(Provider):
    """Tells internet-wide scanners and well-known services apart from everything else.

    For a brute force source this is context, not a verdict: "scans the whole internet"
    means opportunistic, "not seen scanning" means the activity may be targeted.
    """

    name = "greynoise"
    label = "GreyNoise"
    kinds = frozenset({Kind.IP})
    key_env = "GREYNOISE_API_KEY"
    key_required = False  # the community API answers a small number of lookups without one
    URL = "https://api.greynoise.io/v3/community/{ip}"

    def supports(self, target: Observable) -> bool:
        return super().supports(target) and _is_ipv4(target)

    async def lookup(
        self, client: httpx.AsyncClient, target: Observable, key: str | None
    ) -> Verdict:
        headers = {"key": key} if key else {}
        response = await send(client, "GET", self.URL.format(ip=target.value), headers=headers)
        viz = f"https://viz.greynoise.io/ip/{target.value}"
        if response.status_code == 404:
            # Only a statement about scanning: without a key the community API does not
            # mark even well-known services (8.8.8.8) as RIOT, so nothing more is implied.
            return Verdict(Reputation.UNKNOWN, "Not seen scanning the internet", viz)
        check_status(response)
        data = json_object(response)
        link = str(data.get("link") or viz)
        name = str(data.get("name") or "unknown")
        details: dict[str, JsonValue] = {
            key_: data.get(key_)
            for key_ in ("noise", "riot", "classification", "name", "last_seen")
        }
        if data.get("riot"):
            return Verdict(Reputation.BENIGN, f"Known business service ({name})", link, details)
        if data.get("noise"):
            classification = data.get("classification")
            last_seen = data.get("last_seen") or "unknown"
            if classification == "malicious":
                summary = f"Scans the internet, classified malicious (last seen {last_seen})"
                return Verdict(Reputation.MALICIOUS, summary, link, details)
            if classification == "benign":
                return Verdict(
                    Reputation.BENIGN, f"Benign internet scanner ({name})", link, details
                )
            return Verdict(
                Reputation.SUSPICIOUS, "Scans the internet, intent unknown", link, details
            )
        return Verdict(Reputation.UNKNOWN, "No GreyNoise record", link, details)


class AbuseIPDB(Provider):
    name = "abuseipdb"
    label = "AbuseIPDB"
    kinds = frozenset({Kind.IP})
    key_env = "ABUSEIPDB_API_KEY"
    URL = "https://api.abuseipdb.com/api/v2/check"
    MAX_AGE_DAYS = 90

    async def lookup(
        self, client: httpx.AsyncClient, target: Observable, key: str | None
    ) -> Verdict:
        response = await send(
            client,
            "GET",
            self.URL,
            params={"ipAddress": target.value, "maxAgeInDays": str(self.MAX_AGE_DAYS)},
            headers={"Key": key or "", "Accept": "application/json"},
        )
        check_status(response)
        data = json_object(response)["data"]
        score = int(data["abuseConfidenceScore"])
        reports = int(data.get("totalReports") or 0)
        summary = f"Abuse confidence {score}%, {reports} report(s) in {self.MAX_AGE_DAYS} days"
        if data.get("isTor"):
            summary += ", Tor exit node"
        details: dict[str, JsonValue] = {
            key_: data.get(key_)
            for key_ in (
                "abuseConfidenceScore",
                "totalReports",
                "countryCode",
                "isp",
                "usageType",
                "isTor",
                "isWhitelisted",
                "lastReportedAt",
            )
        }
        link = f"https://www.abuseipdb.com/check/{target.value}"
        if score >= 75:
            reputation = Reputation.MALICIOUS
        elif data.get("isWhitelisted") is True:
            reputation = Reputation.BENIGN
            summary = f"On AbuseIPDB's allowlist; {summary}"
        elif score >= 25:
            reputation = Reputation.SUSPICIOUS
        else:
            reputation = Reputation.UNKNOWN
        return Verdict(reputation, summary, link, details)


class URLhaus(Provider):
    """abuse.ch's list of URLs that distribute malware, and the hosts serving them."""

    name = "urlhaus"
    label = "URLhaus"
    kinds = frozenset({Kind.URL, Kind.DOMAIN, Kind.IP})
    key_env = "ABUSECH_AUTH_KEY"
    URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
    HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

    def supports(self, target: Observable) -> bool:
        return super().supports(target) and _is_ipv4(target)  # the host API takes IPv4 only

    async def lookup(
        self, client: httpx.AsyncClient, target: Observable, key: str | None
    ) -> Verdict:
        headers = {"Auth-Key": key or ""}
        if target.kind is Kind.URL:
            response = await send(
                client, "POST", self.URL_ENDPOINT, data={"url": target.value}, headers=headers
            )
            check_status(response)
            return self._url_verdict(json_object(response))
        response = await send(
            client, "POST", self.HOST_ENDPOINT, data={"host": target.value}, headers=headers
        )
        check_status(response)
        return self._host_verdict(json_object(response))

    @staticmethod
    def _status(data: Mapping[str, Any]) -> object:
        # the documented key is query_status; an example in the docs spells it query_staus
        return data.get("query_status", data.get("query_staus"))

    def _url_verdict(self, data: Mapping[str, Any]) -> Verdict:
        status = self._status(data)
        if status in ("no_results", "invalid_url"):
            return Verdict(Reputation.UNKNOWN, "Not listed in URLhaus")
        if status != "ok":
            raise ProviderError(f"query failed ({status})")
        payloads = data.get("payloads") or []
        hashes = [str(p["response_sha256"]) for p in payloads if p.get("response_sha256")]
        tags = data.get("tags") or []
        summary = f"Listed as a malware distribution URL (status {data.get('url_status')})"
        if tags:
            summary += f", tags: {', '.join(str(t) for t in tags)}"
        details: dict[str, JsonValue] = {
            "url_status": data.get("url_status"),
            "threat": data.get("threat"),
            "tags": [str(t) for t in tags],
            "date_added": data.get("date_added"),
            "payloads": len(payloads),
        }
        related = tuple(("hash", h) for h in hashes[:MAX_RELATED])
        return Verdict(
            Reputation.MALICIOUS, summary, data.get("urlhaus_reference"), details, related
        )

    def _host_verdict(self, data: Mapping[str, Any]) -> Verdict:
        status = self._status(data)
        if status in ("no_results", "invalid_host"):
            return Verdict(Reputation.UNKNOWN, "No malware URLs known on this host")
        if status != "ok":
            raise ProviderError(f"query failed ({status})")
        urls = data.get("urls") or []
        count = int(data.get("url_count") or len(urls))
        online = sum(1 for u in urls if u.get("url_status") == "online")
        details: dict[str, JsonValue] = {"url_count": count, "online": online}
        link = data.get("urlhaus_reference")
        if online:
            summary = f"Hosts {count} known malware URL(s), {online} online now"
            return Verdict(Reputation.MALICIOUS, summary, link, details)
        summary = f"Hosted {count} known malware URL(s), none online now"
        return Verdict(Reputation.SUSPICIOUS, summary, link, details)


class MalwareBazaar(Provider):
    name = "malwarebazaar"
    label = "MalwareBazaar"
    kinds = frozenset({Kind.HASH})
    key_env = "ABUSECH_AUTH_KEY"
    URL = "https://mb-api.abuse.ch/api/v1/"

    def supports(self, target: Observable) -> bool:
        return super().supports(target) and len(target.value) in (32, 40, 64)  # no SHA-512

    async def lookup(
        self, client: httpx.AsyncClient, target: Observable, key: str | None
    ) -> Verdict:
        response = await send(
            client,
            "POST",
            self.URL,
            data={"query": "get_info", "hash": target.value},
            headers={"Auth-Key": key or ""},
        )
        check_status(response)
        data = json_object(response)
        status = data.get("query_status")
        if status == "hash_not_found":
            return Verdict(Reputation.UNKNOWN, "Not in MalwareBazaar")
        samples = data.get("data")
        if not isinstance(samples, list) or not samples:
            raise ProviderError(f"query failed ({status})")
        sample = samples[0]
        family = sample.get("signature") or "unknown family"
        sha256 = sample.get("sha256_hash")
        summary = (
            f"Known malware sample: {family} ({sample.get('file_type')}), "
            f"first seen {sample.get('first_seen')}"
        )
        details: dict[str, JsonValue] = {
            "signature": sample.get("signature"),
            "file_type": sample.get("file_type"),
            "tags": [str(t) for t in sample.get("tags") or []],
            "first_seen": sample.get("first_seen"),
        }
        link = f"https://bazaar.abuse.ch/sample/{sha256}/" if sha256 else None
        return Verdict(Reputation.MALICIOUS, summary, link, details)


class VirusTotal(Provider):
    """Detections from VirusTotal's engines. Only stored reports are read: nothing is ever
    submitted for scanning. The free API is limited to 4 requests a minute and is for
    non-commercial use only."""

    name = "virustotal"
    label = "VirusTotal"
    kinds = frozenset({Kind.IP, Kind.DOMAIN, Kind.URL, Kind.HASH})
    key_env = "VIRUSTOTAL_API_KEY"
    min_interval = 15.0
    API = "https://www.virustotal.com/api/v3/"
    GUI = "https://www.virustotal.com/gui/"
    MALICIOUS_ENGINES = 3

    def _paths(self, target: Observable) -> tuple[str, str]:
        value = target.value
        if target.kind is Kind.HASH:
            return f"files/{value}", f"file/{value}"
        if target.kind is Kind.IP:
            return f"ip_addresses/{value}", f"ip-address/{value}"
        if target.kind is Kind.DOMAIN:
            return f"domains/{value}", f"domain/{value}"
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"urls/{url_id}", f"search/{quote(value, safe='')}"

    async def lookup(
        self, client: httpx.AsyncClient, target: Observable, key: str | None
    ) -> Verdict:
        api_path, gui_path = self._paths(target)
        link = self.GUI + gui_path
        response = await send(client, "GET", self.API + api_path, headers={"x-apikey": key or ""})
        if response.status_code == 404:
            return Verdict(Reputation.UNKNOWN, "Not in VirusTotal", link)
        check_status(response)
        attributes = json_object(response)["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, int))
        threat = (attributes.get("popular_threat_classification") or {}).get(
            "suggested_threat_label"
        )
        details: dict[str, JsonValue] = {
            "last_analysis_stats": {str(k): v for k, v in stats.items()},
            "reputation": attributes.get("reputation"),
        }
        if threat:
            details["suggested_threat_label"] = threat
        if not malicious and not suspicious:
            summary = f"No engine flags it (0 of {total}); that does not prove it is clean"
            return Verdict(Reputation.UNKNOWN, summary, link, details)
        summary = f"{malicious} of {total} engines flag it as malicious"
        if suspicious:
            summary += f", {suspicious} as suspicious"
        if threat:
            summary += f" ({threat})"
        if malicious >= self.MALICIOUS_ENGINES:
            return Verdict(Reputation.MALICIOUS, summary, link, details)
        return Verdict(Reputation.SUSPICIOUS, summary, link, details)


PROVIDERS: tuple[type[Provider], ...] = (GreyNoise, AbuseIPDB, URLhaus, MalwareBazaar, VirusTotal)
