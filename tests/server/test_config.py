from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kale.server.config import ConfigError, Settings, default_data_dir, load_scope


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("KALE_DATABASE_URL", "KALE_UPLOAD_DIR", "KALE_SCOPE_FILE", "KALE_MAX_UPLOAD_MB"):
        monkeypatch.delenv(name, raising=False)


def test_defaults_live_in_the_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    settings = Settings()
    assert settings.database_url == f"sqlite:///{tmp_path / 'kale' / 'kale.db'}"
    assert settings.upload_dir == tmp_path / "kale" / "uploads"
    assert settings.scope_file is None
    assert not settings.allow_private
    assert (settings.max_upload_mb, settings.max_runs, settings.job_attempts) == (64, 100, 3)
    assert (settings.job_timeout, settings.heartbeat_seconds) == (3600, 15)
    assert (settings.stale_seconds, settings.worker_poll_seconds) == (120, 1)


def test_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KALE_MAX_UPLOAD_MB", "5")
    assert Settings().max_upload_mb == 5
    monkeypatch.setenv("KALE_MAX_UPLOAD_MB", "0")
    with pytest.raises(ValidationError):
        Settings()


def test_default_data_dir_on_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert default_data_dir({"XDG_DATA_HOME": "/tmp/x"}) == Path("/tmp/x/kale")
    assert default_data_dir({}) == Path.home() / ".local/share/kale"


def test_default_data_dir_on_windows_without_localappdata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    assert default_data_dir({}) == Path.home() / "AppData" / "Local" / "kale"


def test_load_scope(tmp_path: Path) -> None:
    assert load_scope(Settings(scope_file=None)) is None

    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n# comment\n", encoding="utf-8")
    scope = load_scope(Settings(scope_file=scope_file))
    assert scope is not None
    assert scope.domains == {"example.com"}
    assert not scope.allow_private

    private = load_scope(Settings(scope_file=scope_file, allow_private=True))
    assert private is not None
    assert private.allow_private

    with pytest.raises(ConfigError, match="cannot read scope file"):
        load_scope(Settings(scope_file=tmp_path / "missing.txt"))

    scope_file.write_text("not a domain!\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid scope entry"):
        load_scope(Settings(scope_file=scope_file))
