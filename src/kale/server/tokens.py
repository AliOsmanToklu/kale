"""API tokens: shown once at creation, stored only as their SHA-256 digest.

A token carries 32 random bytes, so a fast hash is enough: there is nothing to guess
that a slow hash would protect. Lookups go by digest, which is not secret, so no
constant-time comparison is needed.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from kale.server.errors import Conflict
from kale.server.tables import Role, Token

TOKEN_PREFIX = "kale_"  # noqa: S105 - a public prefix, not a secret
# How often last_used_at may be written: once a minute is precise enough for an audit
# and keeps reads from turning every request into a write.
LAST_USED_RESOLUTION = timedelta(seconds=60)


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_token(db: Session, name: str, role: Role, *, now: datetime) -> tuple[Token, str]:
    """Create a token and return it with its raw value, which is never available again."""
    if db.scalar(select(Token.id).where(Token.name == name)) is not None:
        raise Conflict(f"a token named {name} already exists")
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = Token(
        name=name,
        role=role,
        digest=_digest(raw),
        prefix=raw[len(TOKEN_PREFIX) : len(TOKEN_PREFIX) + 8],
        created_at=now,
    )
    db.add(token)
    db.commit()
    return token, raw


def verify_token(db: Session, raw: str, *, now: datetime) -> Token | None:
    """The live token ``raw`` stands for, or ``None``."""
    if not raw.startswith(TOKEN_PREFIX) or len(raw) == len(TOKEN_PREFIX):
        return None
    token = db.scalar(select(Token).where(Token.digest == _digest(raw)))
    if token is None or token.revoked_at is not None:
        return None
    if token.last_used_at is None or now - token.last_used_at >= LAST_USED_RESOLUTION:
        token.last_used_at = now
        db.commit()
    return token


def revoke_token(db: Session, name: str, *, now: datetime) -> bool:
    """Revoke the token called ``name``; ``False`` when there is none."""
    token = db.scalar(select(Token).where(Token.name == name))
    if token is None:
        return False
    if token.revoked_at is None:
        token.revoked_at = now
        db.commit()
    return True


def list_tokens(db: Session) -> list[Token]:
    return list(db.scalars(select(Token).order_by(Token.name)))
