from __future__ import annotations

import asyncio
import sqlite3
import sys
from pathlib import Path

import pytest

from kale.net.cache import TTLCache, default_cache_dir
from kale.net.ratelimit import MinInterval


class FakeTime:
    def __init__(self, now: float = 100.0) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


async def test_min_interval_queues_callers_in_order() -> None:
    time = FakeTime()
    limiter = MinInterval(15, clock=time.clock, sleep=time.sleep)
    await asyncio.gather(limiter.wait(), limiter.wait(), limiter.wait())
    assert time.sleeps == [15, 30]  # the first call goes straight through


async def test_min_interval_does_not_wait_after_a_pause() -> None:
    time = FakeTime()
    limiter = MinInterval(10, clock=time.clock, sleep=time.sleep)
    await limiter.wait()
    time.now += 60
    await limiter.wait()
    assert time.sleeps == []


async def test_zero_interval_never_waits() -> None:
    time = FakeTime()
    limiter = MinInterval(0, clock=time.clock, sleep=time.sleep)
    for _ in range(3):
        await limiter.wait()
    assert time.sleeps == []


def test_min_interval_rejects_negative_values() -> None:
    with pytest.raises(ValueError, match="negative"):
        MinInterval(-1)


@pytest.fixture
def clock() -> FakeTime:
    return FakeTime(now=1_000.0)


@pytest.fixture
def cache(tmp_path: Path, clock: FakeTime) -> TTLCache:
    return TTLCache(tmp_path / "nested" / "cache.sqlite3", clock=clock.clock)


def test_cache_round_trip_and_expiry(cache: TTLCache, clock: FakeTime) -> None:
    assert cache.get("ns", "k") is None
    cache.set("ns", "k", {"verdict": "malicious", "n": [1, 2]}, ttl=60)
    assert cache.get("ns", "k") == {"verdict": "malicious", "n": [1, 2]}
    assert cache.get("other", "k") is None
    clock.now += 61
    assert cache.get("ns", "k") is None
    with sqlite3.connect(cache.path) as db:  # the expired row was removed on read
        assert db.execute("SELECT COUNT(*) FROM entries").fetchone() == (0,)
    db.close()


def test_cache_ttl_zero_stores_nothing(cache: TTLCache) -> None:
    cache.set("ns", "k", 1, ttl=0)
    assert cache.get("ns", "k") is None


def test_damaged_entries_are_misses(cache: TTLCache) -> None:
    cache.set("ns", "k", "fine", ttl=60)
    with sqlite3.connect(cache.path) as db:
        db.execute("UPDATE entries SET value = 'not json {'")
    db.close()
    assert cache.get("ns", "k") is None


def test_purge_expired(cache: TTLCache, clock: FakeTime) -> None:
    cache.set("ns", "old", 1, ttl=10)
    cache.set("ns", "new", 2, ttl=100)
    clock.now += 50
    assert cache.purge_expired() == 1
    assert cache.get("ns", "new") == 2


def test_default_cache_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert default_cache_dir({"KALE_CACHE_DIR": str(tmp_path)}) == tmp_path
    monkeypatch.setattr(sys, "platform", "win32")
    assert default_cache_dir({"LOCALAPPDATA": "C:/Users/x/AppData/Local"}) == Path(
        "C:/Users/x/AppData/Local/kale/cache"
    )
    monkeypatch.setattr(sys, "platform", "linux")
    assert default_cache_dir({"XDG_CACHE_HOME": "/tmp/xdg"}) == Path("/tmp/xdg/kale")
    assert default_cache_dir({}) == Path.home() / ".cache" / "kale"
