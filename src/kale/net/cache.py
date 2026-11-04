"""A small persistent cache with expiry, for answers from third-party APIs.

Lookups cost quota (VirusTotal's free tier allows 500 a day), and the same IP or hash
comes up again and again during an investigation. Entries live in one SQLite file in the
user's cache directory; ``KALE_CACHE_DIR`` moves it.

The calls are synchronous and short. Async code runs them through ``asyncio.to_thread``.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from pydantic import JsonValue

CACHE_DIR_ENV = "KALE_CACHE_DIR"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (namespace, key)
)
"""


def default_cache_dir(environ: Mapping[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    if env.get(CACHE_DIR_ENV):
        return Path(env[CACHE_DIR_ENV])
    if sys.platform == "win32":
        base = env.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "kale" / "cache"
    return Path(env.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "kale"


class TTLCache:
    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = path
        self._clock = clock

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute(_SCHEMA)
        return connection

    def get(self, namespace: str, key: str) -> JsonValue | None:
        with contextlib.closing(self._connect()) as db, db:
            row = db.execute(
                "SELECT value, expires_at FROM entries WHERE namespace = ? AND key = ?",
                (namespace, key),
            ).fetchone()
            if row is None:
                return None
            value, expires_at = row
            if expires_at <= self._clock():
                db.execute("DELETE FROM entries WHERE namespace = ? AND key = ?", (namespace, key))
                return None
        try:
            decoded: JsonValue = json.loads(value)
        except ValueError:  # a damaged entry is a miss, not a crash
            return None
        return decoded

    def set(self, namespace: str, key: str, value: JsonValue, ttl: float) -> None:
        if ttl <= 0:
            return
        with contextlib.closing(self._connect()) as db, db:
            db.execute(
                "INSERT OR REPLACE INTO entries (namespace, key, value, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (namespace, key, json.dumps(value), self._clock() + ttl),
            )

    def purge_expired(self) -> int:
        with contextlib.closing(self._connect()) as db, db:
            return db.execute(
                "DELETE FROM entries WHERE expires_at <= ?", (self._clock(),)
            ).rowcount
