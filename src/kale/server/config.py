"""Service settings, read from ``KALE_*`` environment variables, and the server scope."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from kale.core import InvalidInputError, Scope


class ConfigError(Exception):
    """The service is configured in a way it must not start with."""


def default_data_dir(environ: Mapping[str, str] | None = None) -> Path:
    """Where the database and the upload quarantine live unless configured otherwise."""
    env = os.environ if environ is None else environ
    if sys.platform == "win32":
        base = env.get("LOCALAPPDATA")
        return Path(base) / "kale" if base else Path.home() / "AppData" / "Local" / "kale"
    base = env.get("XDG_DATA_HOME")
    return Path(base) / "kale" if base else Path.home() / ".local/share/kale"


def _default_database_url() -> str:
    return f"sqlite:///{default_data_dir() / 'kale.db'}"


def _default_upload_dir() -> Path:
    return default_data_dir() / "uploads"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KALE_", extra="ignore")

    # SQLAlchemy URL; PostgreSQL through postgresql+psycopg://
    database_url: str = Field(default_factory=_default_database_url)
    # The server scope: active modules only run on targets it covers. Unset: none run.
    scope_file: Path | None = None
    allow_private: bool = False
    # Quarantine for uploaded files: never executed, never served, deleted with the job.
    upload_dir: Path = Field(default_factory=_default_upload_dir)
    max_upload_mb: int = Field(default=64, ge=1)
    # Upper bound for an investigation's max_runs.
    max_runs: int = Field(default=100, ge=1)
    job_timeout: float = Field(default=3600, gt=0)
    # Claims before a job whose worker keeps dying counts as poison.
    job_attempts: int = Field(default=3, ge=1)
    heartbeat_seconds: float = Field(default=15, gt=0)
    stale_seconds: float = Field(default=120, gt=0)
    worker_poll_seconds: float = Field(default=1, gt=0)


def load_scope(settings: Settings) -> Scope | None:
    """The server scope, or ``None`` when no scope file is configured.

    A configured file that cannot be read or holds an invalid entry is an error, never
    an empty scope: the service must not run without the scope its operator wrote.
    """
    path = settings.scope_file
    if path is None:
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else exc
        raise ConfigError(f"cannot read scope file {path}: {reason}") from None
    try:
        return Scope.parse(lines, allow_private=settings.allow_private)
    except InvalidInputError as exc:
        raise ConfigError(f"scope file {path}: {exc}") from None
