"""A fake HTTP layer for modules that call external services: no test touches the network."""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import parse_qs

import httpx
from pydantic import JsonValue

Reply = httpx.Response | Exception


class FakeAPI:
    """Routes requests by URL prefix. A list of replies is served in order; the last
    one repeats. Unrouted requests fail the test."""

    def __init__(self) -> None:
        self.routes: dict[str, list[Reply]] = {}
        self.handlers: dict[str, Callable[[httpx.Request], httpx.Response]] = {}
        self.requests: list[httpx.Request] = []

    def route(self, prefix: str, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        """Answer requests under ``prefix`` by looking at them (query, body)."""
        self.handlers[prefix] = handler

    def add(self, prefix: str, *replies: Reply) -> None:
        self.routes[prefix] = list(replies)

    def json(self, prefix: str, data: JsonValue, status: int = 200) -> None:
        self.add(prefix, httpx.Response(status, json=data))

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        for prefix, handler in self.handlers.items():
            if url.startswith(prefix):
                return handler(request)
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
