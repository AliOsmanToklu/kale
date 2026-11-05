"""``kale db``, ``kale token``, ``kale serve`` and ``kale worker``.

The sub-parsers live in ``kale.cli`` so that the commands are listed, and explain the
missing extra, even when the ``server`` extra is not installed. This module is imported
only to run one of them.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import sys
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError
from sqlalchemy import Engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from kale.core import Registry
from kale.server.config import ConfigError, Settings, load_scope
from kale.server.db import make_engine, make_session_factory, utcnow
from kale.server.errors import Conflict
from kale.server.migrate import SchemaOutdated, current_revision, ensure_current, upgrade_database
from kale.server.tables import Role
from kale.server.tokens import create_token, list_tokens, revoke_token
from kale.server.worker import Worker, install_signal_handlers

log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_USAGE = 2
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class _Refused(Exception):
    """The command cannot go on; the message is printed as ``kale: error: ...``."""


def run(args: argparse.Namespace) -> int:
    if not args.debug:
        logging.getLogger().setLevel(logging.INFO)
    try:
        settings = Settings()
    except ValidationError as exc:
        first = exc.errors()[0]
        name = "KALE_" + "_".join(str(part) for part in first["loc"]).upper()
        return _error(f"invalid setting {name}: {first['msg']}")
    try:
        if args.command == "db":
            return _db_upgrade(settings)
        if args.command == "token":
            return _token(settings, args)
        if args.command == "serve":
            return _serve(settings, args.host, args.port)
        return _worker(settings)
    except (_Refused, SchemaOutdated, ConfigError, Conflict) as exc:
        return _error(str(exc))
    except OperationalError as exc:
        return _error(f"cannot use the database: {exc.orig or exc}")


def _error(message: str) -> int:
    print(f"kale: error: {message}", file=sys.stderr)
    return EXIT_USAGE


def _sqlite_file(settings: Settings) -> Path | None:
    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite" or url.database in (None, "", ":memory:"):
        return None
    return Path(url.database)


def _require_database(settings: Settings) -> None:
    """Fail with the fix, instead of letting SQLite create an empty file or fail to."""
    path = _sqlite_file(settings)
    if path is not None and not path.is_file():
        raise SchemaOutdated(f"no database at {path}: run `kale db upgrade`")


@contextlib.contextmanager
def _engine(settings: Settings, *, current: bool = True) -> Iterator[Engine]:
    if current:
        _require_database(settings)
    engine = make_engine(settings.database_url)
    try:
        if current:
            ensure_current(engine)
        yield engine
    finally:
        engine.dispose()


@contextlib.contextmanager
def _session(settings: Settings) -> Iterator[Session]:
    with _engine(settings) as engine, make_session_factory(engine)() as db:
        yield db


def _db_upgrade(settings: Settings) -> int:
    path = _sqlite_file(settings)
    if path is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise _Refused(f"cannot create {path.parent}: {exc.strerror or exc}") from None
    with _engine(settings, current=False) as engine:
        upgrade_database(engine)
        print(f"database is at revision {current_revision(engine)}")
    return EXIT_OK


def _when(moment: datetime | None) -> str:
    return moment.strftime("%Y-%m-%d %H:%M") if moment else "-"


def _token(settings: Settings, args: argparse.Namespace) -> int:
    with _session(settings) as db:
        if args.subcommand == "create":
            _, raw = create_token(db, args.name, Role(args.role), now=utcnow())
            print(raw)
            print("store it now: it is not shown again")
            return EXIT_OK
        if args.subcommand == "revoke":
            if not revoke_token(db, args.name, now=utcnow()):
                raise _Refused(f"no token named {args.name}")
            print(f"revoked {args.name}")
            return EXIT_OK
        tokens = list_tokens(db)
    if not tokens:
        print("no tokens")
        return EXIT_OK
    rows = [("NAME", "ROLE", "PREFIX", "CREATED", "LAST USED", "REVOKED")] + [
        (t.name, t.role, t.prefix, _when(t.created_at), _when(t.last_used_at), _when(t.revoked_at))
        for t in tokens
    ]
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for row in rows:
        print(
            "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()
        )
    return EXIT_OK


def _serve(settings: Settings, host: str, port: int) -> int:
    import uvicorn

    from kale.server.app import create_app

    with _engine(settings) as engine:
        app = create_app(settings, session_factory=make_session_factory(engine))
        if host not in LOOPBACK:
            print(
                f"kale: warning: serving on {host} without TLS; put a TLS reverse proxy in "
                "front before exposing the API",
                file=sys.stderr,
            )
        uvicorn.run(app, host=host, port=port)
    return EXIT_OK


def _worker(settings: Settings) -> int:
    with _engine(settings) as engine:
        if load_scope(settings) is None:
            log.warning("no server scope: active modules are disabled")
        worker = Worker(settings, Registry.discover(), make_session_factory(engine))

        async def work() -> None:
            stop = asyncio.Event()
            install_signal_handlers(stop)
            log.info("worker %s waiting for jobs", worker.worker_id)
            await worker.run_forever(stop)

        asyncio.run(work())
    return EXIT_OK
