"""Space out requests to one service. Free API tiers allow a few requests per minute."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable


class MinInterval:
    """Lets calls through at most once per ``interval`` seconds, in arrival order.

    Each caller reserves its slot before it awaits anything, so concurrent callers queue
    up without a lock. That also keeps one limiter usable across event loops, which an
    ``asyncio.Lock`` is not.
    """

    def __init__(
        self,
        interval: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if interval < 0:
            raise ValueError("interval must not be negative")
        self.interval = interval
        self._clock = clock
        self._sleep = sleep
        self._next = 0.0

    async def wait(self) -> None:
        now = self._clock()
        start = max(now, self._next)
        self._next = start + self.interval
        if start > now:
            await self._sleep(start - now)
