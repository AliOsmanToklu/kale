"""HTTP helpers for modules that call third-party APIs.

Every failure becomes a ``ServiceError`` with a short, safe message (status code or error
type, never a response body or a URL that could carry a key). Transient failures
(timeouts, connection resets, 5xx) are retried; quota and authentication errors are not,
because retrying them only burns more quota.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from kale import __version__
from kale.net.ratelimit import MinInterval

USER_AGENT = f"kale/{__version__}"


class ServiceError(Exception):
    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient  # worth a retry: timeouts, resets, 5xx


async def send(client: httpx.AsyncClient, method: str, url: str, **kwargs: Any) -> httpx.Response:
    try:
        return await client.request(method, url, **kwargs)
    except httpx.TimeoutException:
        raise ServiceError("timed out", transient=True) from None
    except httpx.HTTPError as exc:
        raise ServiceError(f"connection failed ({type(exc).__name__})", transient=True) from None


def check_status(response: httpx.Response) -> None:
    code = response.status_code
    if code in (401, 403):
        raise ServiceError(f"API key rejected (HTTP {code})")
    if code == 429:
        raise ServiceError("rate limit or quota reached (HTTP 429)")
    if code >= 500:
        raise ServiceError(f"service error (HTTP {code})", transient=True)
    if not 200 <= code < 300:
        raise ServiceError(f"unexpected HTTP {code}")


def json_object(response: httpx.Response) -> dict[str, Any]:
    data = response.json()  # ValueError on invalid JSON: reported as a bad response
    if not isinstance(data, dict):
        raise ServiceError("unexpected response format")
    return data


async def with_retry[T](
    call: Callable[[], Awaitable[T]],
    *,
    limiter: MinInterval | None = None,
    attempts: int = 2,
    delay: float = 2.0,
) -> T:
    """Run ``call``, waiting for ``limiter`` before every attempt. Parsing errors
    (missing keys, wrong types) mean the answer was not what we expected: they become a
    ``ServiceError`` instead of crashing the module."""
    for attempt in range(1, attempts + 1):
        if limiter is not None:
            await limiter.wait()
        try:
            return await call()
        except ServiceError as exc:
            if not exc.transient or attempt == attempts:
                raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ServiceError(f"unexpected response format ({type(exc).__name__})") from None
        await asyncio.sleep(delay * attempt)
    raise AssertionError("unreachable")  # pragma: no cover
