from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, inspect
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session

from kale.server.db import Base, make_engine
from kale.server.migrate import (
    SchemaOutdated,
    current_revision,
    ensure_current,
    head_revision,
    render_item,
    upgrade_database,
)
from kale.server.tables import Job, JobKind, JobStatus, Role, Token, Upload


def test_head_matches_the_models(engine: Engine) -> None:
    """Fails when a model changes without a new migration (autogenerate would emit ops)."""
    assert {"jobs", "uploads", "tokens", "alembic_version"} <= set(
        inspect(engine).get_table_names()
    )
    with engine.connect() as connection:
        context = MigrationContext.configure(
            connection, opts={"compare_type": True, "render_item": render_item}
        )
        assert compare_metadata(context, Base.metadata) == []


def test_ensure_current(tmp_path: Path) -> None:
    fresh = make_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    try:
        assert current_revision(fresh) is None
        with pytest.raises(SchemaOutdated, match="kale db upgrade"):
            ensure_current(fresh)
        upgrade_database(fresh)
        ensure_current(fresh)
        assert current_revision(fresh) == head_revision() == "0001"
    finally:
        fresh.dispose()


def token(name: str = "ci") -> Token:
    return Token(
        name=name,
        role=Role.RUNNER,
        digest="0" * 64,
        prefix="abcdefgh",
        created_at=datetime(2026, 11, 5, 12, tzinfo=UTC),
    )


def test_datetimes_are_utc(db: Session) -> None:
    row = token()
    db.add(row)
    db.commit()
    db.expire_all()
    stored = db.get(Token, row.id)
    assert stored is not None
    assert stored.created_at == datetime(2026, 11, 5, 12, tzinfo=UTC)
    assert stored.created_at.tzinfo is UTC

    db.add(
        Token(
            name="naive",
            role=Role.READER,
            digest="1" * 64,
            prefix="x",
            created_at=datetime(2026, 1, 1),
        )
    )
    with pytest.raises(StatementError, match="naive datetime"):
        db.flush()


def test_a_job_round_trips(db: Session) -> None:
    owner = token()
    upload = Upload(
        stored_path="/q/0123",
        original_name="auth.log",
        size=3,
        sha256="a" * 64,
        created_at=datetime(2026, 11, 5, tzinfo=UTC),
    )
    db.add_all([owner, upload])
    db.flush()
    job = Job(
        kind=JobKind.RUN,
        module="logs.auth",
        target={"kind": "file", "value": "/q/0123"},
        options={},
        scope={"entries": [], "allow_private": False},
        lang="en",
        created_by=owner.id,
        created_at=datetime(2026, 11, 5, tzinfo=UTC),
        upload_id=upload.id,
    )
    db.add(job)
    db.commit()
    db.expire_all()
    stored = db.get(Job, job.id)
    assert stored is not None
    assert len(stored.id) == 36
    assert stored.status is JobStatus.QUEUED
    assert stored.attempts == 0
    assert stored.upload is not None
    assert stored.upload.original_name == "auth.log"
    assert stored.target == {"kind": "file", "value": "/q/0123"}


def test_final_statuses() -> None:
    assert {s for s in JobStatus if s.final} == {
        JobStatus.SUCCEEDED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    }


def test_runner_allows_reader() -> None:
    assert Role.RUNNER.allows(Role.READER)
    assert Role.RUNNER.allows(Role.RUNNER)
    assert Role.READER.allows(Role.READER)
    assert not Role.READER.allows(Role.RUNNER)
