from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from kale.core import Registry
from kale.modules.auth_logs import AuthLogModule
from kale.server.config import Settings
from kale.server.db import make_engine, make_session_factory
from kale.server.migrate import upgrade_database
from tests.fakes import (
    ActiveModule,
    CrashModule,
    EchoModule,
    OptionalSecretModule,
    RejectModule,
    SlowModule,
)
from tests.test_pipeline import Discover, Reputation


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'kale.db'}",
        upload_dir=tmp_path / "uploads",
        scope_file=None,
        allow_private=False,
    )


@pytest.fixture
def engine(settings: Settings) -> Iterator[Engine]:
    engine = make_engine(settings.database_url)
    try:
        upgrade_database(engine)
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    return make_session_factory(engine)


@pytest.fixture
def db(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as session:
        yield session


@pytest.fixture
def registry() -> Registry:
    return Registry(
        [
            EchoModule(),
            ActiveModule(),
            SlowModule(),
            CrashModule(),
            RejectModule(),
            OptionalSecretModule(),
            AuthLogModule(),
            Discover(),
            Reputation(),
        ]
    )
