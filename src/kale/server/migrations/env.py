"""Alembic environment.

``kale db upgrade`` calls :func:`kale.server.migrate.upgrade_database`, which hands over
an open connection through ``config.attributes["connection"]``. The ``alembic`` command
(for ``revision --autogenerate``) falls back to ``KALE_DATABASE_URL``.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import Connection

from kale.server import tables  # noqa: F401 - registers the tables on Base.metadata
from kale.server.config import Settings
from kale.server.db import Base, make_engine
from kale.server.migrate import render_item

config = context.config
target_metadata = Base.metadata


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",  # SQLite cannot ALTER much
        compare_type=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        return
    url = config.get_main_option("sqlalchemy.url") or Settings().database_url  # pragma: no cover
    engine = make_engine(url)  # pragma: no cover
    try:  # pragma: no cover
        with engine.connect() as conn:
            _configure(conn)
            conn.commit()
    finally:  # pragma: no cover
        engine.dispose()


def run_offline() -> None:  # pragma: no cover - only for generating SQL by hand
    context.configure(
        url=config.get_main_option("sqlalchemy.url") or Settings().database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():  # pragma: no cover
    run_offline()
else:
    run_online()
