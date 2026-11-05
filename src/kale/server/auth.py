"""Request dependencies: a database session, and the bearer token with its role."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session, sessionmaker

from kale.server.db import utcnow
from kale.server.tables import Role, Token
from kale.server.tokens import verify_token

CHALLENGE = {"WWW-Authenticate": "Bearer"}


def get_db(request: Request) -> Iterator[Session]:
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as db:
        yield db


def require(role: Role) -> Callable[..., Token]:
    """A dependency that admits a live token whose role covers ``role``."""

    def dependency(
        db: Annotated[Session, Depends(get_db)],
        authorization: Annotated[str | None, Header()] = None,
    ) -> Token:
        scheme, _, raw = (authorization or "").partition(" ")
        raw = raw.strip()
        if scheme.lower() != "bearer" or not raw:  # RFC 6750: the scheme is case-insensitive
            raise HTTPException(401, "missing or malformed bearer token", headers=CHALLENGE)
        token = verify_token(db, raw, now=utcnow())
        if token is None:
            raise HTTPException(401, "unknown or revoked token", headers=CHALLENGE)
        if not token.role.allows(role):
            raise HTTPException(403, f"this needs a {role} token")
        return token

    return dependency
