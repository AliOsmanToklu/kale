from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from kale.cli import main
from kale.server.worker import Worker

EXTRA = 'the server extra is not installed: pip install "kale[server]"'


@pytest.fixture(autouse=True)
def environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    database = tmp_path / "data" / "kale.db"
    monkeypatch.setenv("KALE_DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("KALE_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.delenv("KALE_SCOPE_FILE", raising=False)
    monkeypatch.delenv("KALE_ALLOW_PRIVATE", raising=False)
    return database


def test_db_upgrade_and_tokens(capsys: pytest.CaptureFixture[str], environment: Path) -> None:
    assert main(["db", "upgrade"]) == 0
    assert capsys.readouterr().out == "database is at revision 0001\n"
    assert environment.exists()  # the data directory was created

    assert main(["token", "create", "--name", "ci", "--role", "runner"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert re.fullmatch(r"kale_[A-Za-z0-9_-]{43}", out[0])
    assert out[1] == "store it now: it is not shown again"

    assert main(["token", "create", "--name", "ci", "--role", "reader"]) == 2
    assert "a token named ci already exists" in capsys.readouterr().err

    assert main(["token", "create", "--name", "dash", "--role", "reader"]) == 0
    capsys.readouterr()
    assert main(["token", "list"]) == 0
    listing = capsys.readouterr().out
    assert re.search(r"^NAME\s+ROLE\s+PREFIX\s+CREATED\s+LAST USED\s+REVOKED$", listing, re.M)
    assert re.search(r"^ci\s+runner\s+\S{8}\s+\d{4}-\d\d-\d\d \d\d:\d\d\s+-\s+-$", listing, re.M)
    assert out[0] not in listing

    assert main(["token", "revoke", "ci"]) == 0
    assert capsys.readouterr().out == "revoked ci\n"
    assert main(["token", "revoke", "nope"]) == 2
    assert "no token named nope" in capsys.readouterr().err
    main(["token", "list"])
    revoked = capsys.readouterr().out
    assert re.search(r"^ci\s+runner\s+.*\d\d:\d\d$", revoked, re.M)


def test_token_list_when_empty(capsys: pytest.CaptureFixture[str]) -> None:
    main(["db", "upgrade"])
    capsys.readouterr()
    assert main(["token", "list"]) == 0
    assert capsys.readouterr().out == "no tokens\n"


def test_commands_refuse_an_outdated_schema(capsys: pytest.CaptureFixture[str]) -> None:
    for command in (["serve"], ["worker"], ["token", "list"]):
        assert main(command) == 2
        assert "kale db upgrade" in capsys.readouterr().err


def test_serve_refuses_a_broken_scope_file(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    main(["db", "upgrade"])
    monkeypatch.setenv("KALE_SCOPE_FILE", str(tmp_path / "missing.txt"))
    assert main(["serve"]) == 2
    assert "cannot read scope file" in capsys.readouterr().err
    assert main(["worker"]) == 2
    assert "cannot read scope file" in capsys.readouterr().err


def test_invalid_settings_are_a_usage_error(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KALE_MAX_UPLOAD_MB", "0")
    assert main(["serve"]) == 2
    assert "invalid setting" in capsys.readouterr().err


def test_unreachable_database_is_a_usage_error(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("KALE_DATABASE_URL", f"sqlite:///{blocker / 'kale.db'}")
    assert main(["token", "list"]) == 2
    assert "run `kale db upgrade`" in capsys.readouterr().err
    assert main(["db", "upgrade"]) == 2
    assert "cannot create" in capsys.readouterr().err

    folder = tmp_path / "folder"
    folder.mkdir()
    monkeypatch.setenv("KALE_DATABASE_URL", f"sqlite:///{folder}")  # a directory, not a file
    assert main(["db", "upgrade"]) == 2
    assert "cannot use the database: unable to open database file" in capsys.readouterr().err


def test_serve_starts_uvicorn(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import uvicorn

    main(["db", "upgrade"])
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append({"app": app, **kw}))
    assert main(["serve"]) == 0
    [call] = calls
    assert (call["host"], call["port"]) == ("127.0.0.1", 8000)
    assert call["app"].title == "kale API"
    assert main(["serve", "--host", "0.0.0.0", "--port", "9000"]) == 0  # noqa: S104
    assert (calls[1]["host"], calls[1]["port"]) == ("0.0.0.0", 9000)  # noqa: S104
    assert "TLS" in capsys.readouterr().err


def test_worker_runs_until_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    main(["db", "upgrade"])
    seen: list[asyncio.Event] = []

    async def run_forever(self: Worker, stop: asyncio.Event) -> None:
        seen.append(stop)

    monkeypatch.setattr(Worker, "run_forever", run_forever)
    monkeypatch.setattr("kale.server.cli.install_signal_handlers", lambda stop: None)
    assert main(["worker"]) == 0
    assert len(seen) == 1


def test_missing_extra(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setitem(sys.modules, "kale.server.cli", None)
    for command in (["serve"], ["worker"], ["db", "upgrade"], ["token", "list"]):
        assert main(command) == 2
        assert EXTRA in capsys.readouterr().err


def test_other_import_errors_are_not_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    import kale.server.cli as server_cli

    def broken(args: Any) -> int:
        raise ImportError("cannot import name 'x' from 'kale.core'", name="kale.core")

    monkeypatch.setattr(server_cli, "run", broken)
    with pytest.raises(ImportError, match="cannot import name"):
        main(["serve"])


def test_only_serve_and_worker_log_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    import logging

    root, alembic = logging.getLogger(), logging.getLogger("alembic")
    monkeypatch.setattr(root, "level", logging.CRITICAL)
    monkeypatch.setattr(alembic, "level", logging.NOTSET)
    assert main(["db", "upgrade"]) == 0
    assert main(["token", "list"]) == 0
    assert root.level == logging.CRITICAL

    async def run_forever(self: Worker, stop: asyncio.Event) -> None:
        return None

    monkeypatch.setattr(Worker, "run_forever", run_forever)
    monkeypatch.setattr("kale.server.cli.install_signal_handlers", lambda stop: None)
    assert main(["worker"]) == 0
    assert root.level == logging.INFO
    assert alembic.level == logging.WARNING


def test_serve_and_worker_logs_carry_timestamps(monkeypatch: pytest.MonkeyPatch) -> None:
    import logging

    formats: dict[str, str] = {}

    def record(**kwargs: Any) -> None:
        formats[current] = kwargs["format"]

    monkeypatch.setattr(logging, "basicConfig", record)

    async def run_forever(self: Worker, stop: asyncio.Event) -> None:
        return None

    monkeypatch.setattr(Worker, "run_forever", run_forever)
    monkeypatch.setattr("kale.server.cli.install_signal_handlers", lambda stop: None)
    monkeypatch.setattr(logging.getLogger(), "level", logging.CRITICAL)
    current = "db"
    main(["db", "upgrade"])
    current = "worker"
    main(["worker"])
    assert "%(asctime)s" in formats["worker"]  # an audit line needs its time
    assert "%(asctime)s" not in formats["db"]
