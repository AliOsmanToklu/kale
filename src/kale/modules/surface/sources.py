"""Certificate Transparency search: every certificate a public CA issues is logged, so the
names on them map a domain's hosts without sending a packet to the domain itself.

* crt.sh: free and complete, but slow (a minute for a mid-sized domain) and the answer
  can be a few megabytes.
* CertSpotter: fast, but without a key it allows about ten requests an hour, so only
  the first pages are read.
"""

from __future__ import annotations

import abc
import re
from collections.abc import Iterable
from typing import ClassVar

import httpx

from kale.core.models import normalize_hostname
from kale.net.http import ServiceError, check_status, send, with_retry
from kale.net.ratelimit import MinInterval

_NEXT_LINK = re.compile(r"<([^>]+)>;\s*rel=\"next\"")


def in_domain(names: Iterable[str], domain: str) -> set[str]:
    """Hostnames under ``domain``: wildcards unwrapped, e-mail addresses and junk dropped."""
    found: set[str] = set()
    for raw in names:
        name = raw.strip().lower().removeprefix("*.")
        if not name or "@" in name or " " in name:
            continue
        try:
            name = normalize_hostname(name)
        except ValueError:
            continue
        if name == domain or name.endswith("." + domain):
            found.add(name)
    return found


class CTSource(abc.ABC):
    name: ClassVar[str]
    label: ClassVar[str]
    key_env: ClassVar[str | None] = None

    @abc.abstractmethod
    async def names(
        self,
        client: httpx.AsyncClient,
        domain: str,
        *,
        key: str | None,
        limiter: MinInterval,
        retry_delay: float,
    ) -> tuple[set[str], bool]:
        """Names found and whether the list is complete."""


class CrtSh(CTSource):
    name = "crtsh"
    label = "crt.sh"
    URL = "https://crt.sh/"
    TIMEOUT = 150.0  # crt.sh answers slowly; a minute is normal

    async def names(
        self,
        client: httpx.AsyncClient,
        domain: str,
        *,
        key: str | None,
        limiter: MinInterval,
        retry_delay: float,
    ) -> tuple[set[str], bool]:
        async def fetch() -> set[str]:
            response = await send(
                client,
                "GET",
                self.URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=self.TIMEOUT,
            )
            check_status(response)
            rows = response.json()
            if not isinstance(rows, list):
                raise ServiceError("unexpected response format")
            return in_domain(
                (n for row in rows for n in str(row["name_value"]).split("\n")), domain
            )

        return await with_retry(fetch, limiter=limiter, delay=retry_delay), True


class CertSpotter(CTSource):
    name = "certspotter"
    label = "CertSpotter"
    key_env = "CERTSPOTTER_API_KEY"
    URL = "https://api.certspotter.com/v1/issuances"
    PAGES_WITHOUT_KEY = 2  # the anonymous limit is about ten requests an hour
    PAGES_WITH_KEY = 20

    async def names(
        self,
        client: httpx.AsyncClient,
        domain: str,
        *,
        key: str | None,
        limiter: MinInterval,
        retry_delay: float,
    ) -> tuple[set[str], bool]:
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        base = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        found: set[str] = set()
        after: str | None = None
        for _ in range(self.PAGES_WITH_KEY if key else self.PAGES_WITHOUT_KEY):
            # The API's own "next" link drops the /v1 prefix and answers 404, so the next
            # page is asked for with the documented `after` parameter instead.
            params = {**base, "after": after} if after else base

            async def fetch(params: dict[str, str] = params) -> tuple[set[str], str | None]:
                response = await send(client, "GET", self.URL, params=params, headers=headers)
                check_status(response)
                items = response.json()
                if not isinstance(items, list):
                    raise ServiceError("unexpected response format")
                names = in_domain((n for item in items for n in item["dns_names"]), domain)
                more = bool(items) and _NEXT_LINK.search(response.headers.get("link", ""))
                return names, str(items[-1]["id"]) if more else None

            page, after = await with_retry(fetch, limiter=limiter, delay=retry_delay)
            found |= page
            if after is None:
                return found, True
        return found, False


SOURCES: tuple[type[CTSource], ...] = (CrtSh, CertSpotter)
