from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from kale.server.errors import Conflict, ServiceError
from kale.server.tables import Role
from kale.server.tokens import (
    TOKEN_PREFIX,
    create_token,
    list_tokens,
    revoke_token,
    verify_token,
)

T = datetime(2026, 11, 5, 12, tzinfo=UTC)


def test_only_the_digest_is_stored(db: Session) -> None:
    token, raw = create_token(db, "ci", Role.RUNNER, now=T)
    assert raw.startswith(TOKEN_PREFIX)
    assert raw.startswith("kale_")
    assert len(raw) > 40
    assert token.digest == hashlib.sha256(raw.encode()).hexdigest()
    assert token.prefix == raw[5:13]
    assert token.created_at == T
    assert (token.name, token.role) == ("ci", Role.RUNNER)
    columns = {c.name: getattr(token, c.key) for c in token.__table__.columns}
    assert all(raw not in str(value) for value in columns.values())


def test_tokens_are_random(db: Session) -> None:
    _, first = create_token(db, "a", Role.READER, now=T)
    _, second = create_token(db, "b", Role.READER, now=T)
    assert first != second


def test_verify(db: Session) -> None:
    token, raw = create_token(db, "ci", Role.RUNNER, now=T)
    assert verify_token(db, raw, now=T) == token
    for wrong in ("", "kale_", "kale_" + "x" * 43, raw.removeprefix("kale_"), raw + "x"):
        assert verify_token(db, wrong, now=T) is None
    assert revoke_token(db, "ci", now=T)
    assert verify_token(db, raw, now=T) is None


def test_last_used_is_throttled(db: Session) -> None:
    token, raw = create_token(db, "ci", Role.RUNNER, now=T)
    assert token.last_used_at is None
    verify_token(db, raw, now=T)
    assert token.last_used_at == T
    verify_token(db, raw, now=T + timedelta(seconds=30))
    assert token.last_used_at == T
    verify_token(db, raw, now=T + timedelta(seconds=61))
    assert token.last_used_at == T + timedelta(seconds=61)


def test_duplicate_name_conflicts(db: Session) -> None:
    create_token(db, "ci", Role.RUNNER, now=T)
    with pytest.raises(Conflict, match="a token named ci already exists"):
        create_token(db, "ci", Role.READER, now=T)
    assert [t.name for t in list_tokens(db)] == ["ci"]


def test_revoke(db: Session) -> None:
    create_token(db, "zeta", Role.READER, now=T)
    create_token(db, "alpha", Role.RUNNER, now=T)
    assert not revoke_token(db, "nope", now=T)
    assert revoke_token(db, "zeta", now=T)
    assert [t.name for t in list_tokens(db)] == ["alpha", "zeta"]
    assert list_tokens(db)[1].revoked_at == T


def test_service_errors_carry_the_detail() -> None:
    assert issubclass(Conflict, ServiceError)
    assert str(Conflict("taken")) == "taken"
