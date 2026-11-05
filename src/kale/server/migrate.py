"""Schema migrations (Alembic), run by ``kale db upgrade``."""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any, Literal

from alembic import command
from alembic.autogenerate.api import AutogenContext
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine

from kale.server.db import UTCDateTime

SCRIPT_LOCATION = "kale.server:migrations"


class SchemaOutdated(Exception):
    """The database is not at the revision this version of kale expects."""


def render_item(type_: str, obj: Any, autogen_context: AutogenContext) -> str | Literal[False]:
    """Write portable column types into migration files instead of our TypeDecorator."""
    if type_ == "type" and isinstance(obj, UTCDateTime):
        return "sa.DateTime(timezone=True)"
    return False


def alembic_config(connection: Connection | None = None) -> Config:
    config = Config()
    config.set_main_option("script_location", SCRIPT_LOCATION)
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def head_revision() -> str:
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    if head is None:  # pragma: no cover - the package always ships revisions
        raise RuntimeError("no migration revisions found")
    return head


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


@contextlib.contextmanager
def _migration_connection(engine: Engine) -> Iterator[Connection]:
    """A connection in a transaction, with SQLite foreign keys switched off.

    SQLite cannot alter columns, so Alembic "batch" migrations copy a table and drop
    the original; with foreign keys enforced, that drop would cascade into child rows.
    The pragma only takes effect outside a transaction, hence the explicit commit.
    """
    with engine.connect() as connection:
        sqlite = connection.dialect.name == "sqlite"
        if sqlite:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
        try:
            with connection.begin():
                yield connection
        finally:
            if sqlite:
                connection.exec_driver_sql("PRAGMA foreign_keys=ON")
                connection.commit()


def upgrade_database(engine: Engine) -> None:
    with _migration_connection(engine) as connection:
        command.upgrade(alembic_config(connection), "head")


def ensure_current(engine: Engine) -> None:
    """Refuse to work against a database that has not been migrated."""
    if current_revision(engine) != head_revision():
        raise SchemaOutdated("database schema is out of date: run `kale db upgrade`")
