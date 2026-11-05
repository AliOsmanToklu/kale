from __future__ import annotations

import asyncio
import logging
import signal
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any, ClassVar

import pytest
from pydantic import TypeAdapter
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from kale.core import (
    Investigation,
    Kind,
    ModuleOutput,
    ModuleSpec,
    Observable,
    Option,
    Registry,
    RunContext,
    Scope,
    investigate,
    run_module,
)
from kale.server.config import Settings
from kale.server.db import utcnow
from kale.server.jobs import get_job, submit_job
from kale.server.schemas import JobIn
from kale.server.tables import Job, JobStatus, Role, Token, Upload
from kale.server.tokens import create_token
from kale.server.uploads import store_upload
from kale.server.worker import Worker, install_signal_handlers
from tests.fakes import EchoModule, make_spec

JOB_IN: TypeAdapter[Any] = TypeAdapter(JobIn)


class Sleeper:
    spec: ClassVar[ModuleSpec] = make_spec(
        "fake.sleeper", options={"seconds": Option("float", 1.0, "how long to sleep")}
    )

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        await asyncio.sleep(ctx.get_float("seconds"))
        return ModuleOutput(summary={"slept": ctx.get_float("seconds")})


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.txt"
    path.write_text("example.com\n", encoding="utf-8")
    return path


@pytest.fixture
def fast(settings: Settings, scope_file: Path) -> Settings:
    return settings.model_copy(
        update={"scope_file": scope_file, "heartbeat_seconds": 0.05, "worker_poll_seconds": 0.05}
    )


@pytest.fixture
def modules(registry: Registry) -> Registry:
    return Registry([*registry.modules, Sleeper()])


@pytest.fixture
def token(db: Session) -> Token:
    return create_token(db, "ci", Role.RUNNER, now=utcnow())[0]


Submit = Callable[..., Job]


@pytest.fixture
def submit(db: Session, modules: Registry, fast: Settings, token: Token) -> Submit:
    def submit(upload: Upload | None = None, **fields: Any) -> Job:
        body: dict[str, Any] = {
            "kind": "run",
            "module": "fake.echo",
            "target": {"kind": "domain", "value": "shop.example.com"},
        }
        body.update(fields)
        if body["kind"] == "investigate":
            del body["module"]
        return submit_job(
            db,
            JOB_IN.validate_python(body),
            registry=modules,
            server_scope=Scope.parse(["example.com"]),
            settings=fast,
            token=token,
            upload=upload,
            now=utcnow(),
        )

    return submit


def make_worker(
    settings: Settings,
    modules: Registry,
    session_factory: sessionmaker[Session],
    **kwargs: Any,
) -> Worker:
    return Worker(settings, modules, session_factory, worker_id="test:1", **kwargs)


def fetch(session_factory: sessionmaker[Session], job_id: str) -> Job:
    with session_factory() as db:
        return get_job(db, job_id)


async def test_run_job_succeeds_like_run_module(
    submit: Submit, fast: Settings, modules: Registry, session_factory: sessionmaker[Session]
) -> None:
    job = submit(options={"count": "2", "severity": "high"})
    assert await make_worker(fast, modules, session_factory).run_once()
    done = fetch(session_factory, job.id)
    assert done.status is JobStatus.SUCCEEDED
    assert done.error is None
    assert done.worker_id == "test:1"
    assert done.started_at is not None and done.finished_at is not None
    direct = await run_module(
        EchoModule(),
        Observable(kind=Kind.DOMAIN, value="shop.example.com"),
        options={"count": "2", "severity": "high"},
    )
    expected = direct.model_dump(mode="json", exclude={"started_at", "finished_at"})
    assert done.result is not None
    stored = {k: v for k, v in done.result.items() if k not in ("started_at", "finished_at")}
    assert stored == expected


async def test_module_error_is_a_succeeded_job(
    submit: Submit, fast: Settings, modules: Registry, session_factory: sessionmaker[Session]
) -> None:
    job = submit(module="fake.reject")
    await make_worker(fast, modules, session_factory).run_once()
    done = fetch(session_factory, job.id)
    assert done.status is JobStatus.SUCCEEDED
    assert done.result is not None
    assert done.result["error"]["code"] == "invalid_input"


async def test_investigate_job(
    submit: Submit, fast: Settings, modules: Registry, session_factory: sessionmaker[Session]
) -> None:
    job = submit(
        kind="investigate",
        target={"kind": "domain", "value": "example.com"},
        depth=1,
        modules=["fake.discover", "fake.reputation"],
    )
    await make_worker(fast, modules, session_factory).run_once()
    done = fetch(session_factory, job.id)
    assert done.status is JobStatus.SUCCEEDED
    result = Investigation.model_validate(done.result)
    direct = await investigate(
        modules,
        Observable(kind=Kind.DOMAIN, value="example.com"),
        depth=1,
        modules=["fake.discover", "fake.reputation"],
        scope=Scope.parse(["example.com"]),
    )
    assert [(r.module, r.target) for r in result.runs] == [
        (r.module, r.target) for r in direct.runs
    ]


async def test_deadline_fails_the_job(
    submit: Submit, fast: Settings, modules: Registry, session_factory: sessionmaker[Session]
) -> None:
    job = submit(module="fake.sleeper", options={"seconds": "1"})
    settings = fast.model_copy(update={"job_timeout": 0.2})
    await make_worker(settings, modules, session_factory).run_once()
    done = fetch(session_factory, job.id)
    assert done.status is JobStatus.FAILED
    assert done.error == "timed out after 0.2 s"
    assert done.result is None


async def test_heartbeat_moves_during_a_run(
    submit: Submit, fast: Settings, modules: Registry, session_factory: sessionmaker[Session]
) -> None:
    job = submit(module="fake.sleeper", options={"seconds": "0.3"})
    await make_worker(fast, modules, session_factory).run_once()
    done = fetch(session_factory, job.id)
    assert done.status is JobStatus.SUCCEEDED
    assert done.started_at is not None and done.heartbeat_at is not None
    assert done.heartbeat_at > done.started_at


async def test_scope_is_intersected_at_run_time(
    submit: Submit,
    fast: Settings,
    modules: Registry,
    session_factory: sessionmaker[Session],
    scope_file: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    job = submit(module="fake.active", scope=["shop.example.com"])
    scope_file.write_text("other.org\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="kale.server.worker"):
        await make_worker(fast, modules, session_factory).run_once()
    done = fetch(session_factory, job.id)
    assert done.status is JobStatus.SUCCEEDED
    assert done.result is not None
    assert done.result["error"]["code"] == "out_of_scope"
    assert "dropped from scope: shop.example.com" in caplog.text


async def test_scope_still_covering_the_target_runs_it(
    submit: Submit, fast: Settings, modules: Registry, session_factory: sessionmaker[Session]
) -> None:
    job = submit(module="fake.active", scope=["shop.example.com"])
    await make_worker(fast, modules, session_factory).run_once()
    done = fetch(session_factory, job.id)
    assert done.result is not None
    assert done.result["error"] is None
    assert done.result["summary"] == {"allow_private": False}


async def test_private_permission_is_rechecked_at_run_time(
    db: Session,
    modules: Registry,
    fast: Settings,
    token: Token,
    session_factory: sessionmaker[Session],
    scope_file: Path,
) -> None:
    scope_file.write_text("10.0.0.0/8\n", encoding="utf-8")
    job = submit_job(
        db,
        JOB_IN.validate_python(
            {
                "kind": "run",
                "module": "fake.active",
                "target": {"kind": "ip", "value": "10.1.2.3"},
                "allow_private": True,
                "scope": ["10.1.0.0/16"],
            }
        ),
        registry=modules,
        server_scope=Scope.parse(["10.0.0.0/8"], allow_private=True),
        settings=fast,
        token=token,
        upload=None,
        now=utcnow(),
    )
    await make_worker(fast, modules, session_factory).run_once()  # server no longer allows it
    done = fetch(session_factory, job.id)
    assert done.result is not None
    assert done.result["error"]["code"] == "out_of_scope"


async def test_broken_scope_file_fails_the_job(
    submit: Submit,
    fast: Settings,
    modules: Registry,
    session_factory: sessionmaker[Session],
    scope_file: Path,
) -> None:
    job = submit(module="fake.active")
    scope_file.unlink()
    await make_worker(fast, modules, session_factory).run_once()
    done = fetch(session_factory, job.id)
    assert done.status is JobStatus.FAILED
    assert done.error is not None
    assert done.error.startswith("server scope unavailable: cannot read scope file")


async def chunks(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def test_upload_is_deleted_on_success_and_on_failure(
    db: Session,
    submit: Submit,
    fast: Settings,
    modules: Registry,
    session_factory: sessionmaker[Session],
    scope_file: Path,
    ssh_log: Path,
) -> None:
    async def upload() -> Upload:
        return await store_upload(
            db,
            chunks(ssh_log.read_bytes()),
            original_name="auth.log",
            directory=fast.upload_dir,
            limit_bytes=2**20,
            now=utcnow(),
        )

    ok = await upload()
    good = submit(module="logs.auth", target={"kind": "file"}, upload=ok)
    worker = make_worker(fast, modules, session_factory)
    await worker.run_once()
    done = fetch(session_factory, good.id)
    assert done.status is JobStatus.SUCCEEDED
    assert done.result is not None
    assert any(f["rule_id"] == "logs.auth.brute_force" for f in done.result["findings"])
    assert not Path(ok.stored_path).exists()
    assert done.upload is not None and done.upload.deleted_at is not None

    doomed = await upload()
    bad = submit(module="logs.auth", target={"kind": "file"}, upload=doomed)
    scope_file.write_text("not a domain!\n", encoding="utf-8")
    await worker.run_once()
    failed = fetch(session_factory, bad.id)
    assert failed.status is JobStatus.FAILED
    assert not Path(doomed.stored_path).exists()
    assert failed.upload is not None and failed.upload.deleted_at is not None
    assert list(fast.upload_dir.iterdir()) == []


async def test_missing_upload_fails_the_job(
    db: Session,
    submit: Submit,
    fast: Settings,
    modules: Registry,
    session_factory: sessionmaker[Session],
) -> None:
    stored = await store_upload(
        db,
        chunks(b"x"),
        original_name="a",
        directory=fast.upload_dir,
        limit_bytes=10,
        now=utcnow(),
    )
    job = submit(module="logs.auth", target={"kind": "file"}, upload=stored)
    Path(stored.stored_path).unlink()
    await make_worker(fast, modules, session_factory).run_once()
    done = fetch(session_factory, job.id)
    assert done.status is JobStatus.FAILED
    assert done.error == "the uploaded file disappeared"


async def test_module_missing_on_the_worker_fails_the_job(
    submit: Submit, fast: Settings, session_factory: sessionmaker[Session]
) -> None:
    job = submit()
    await make_worker(fast, Registry([]), session_factory).run_once()
    done = fetch(session_factory, job.id)
    assert done.status is JobStatus.FAILED
    assert done.error == "UnknownModuleError: unknown module: fake.echo"


async def test_idle_run_once_returns_false(
    fast: Settings, modules: Registry, session_factory: sessionmaker[Session]
) -> None:
    assert not await make_worker(fast, modules, session_factory).run_once()


async def test_completion_is_audited(
    submit: Submit,
    fast: Settings,
    modules: Registry,
    session_factory: sessionmaker[Session],
    caplog: pytest.LogCaptureFixture,
) -> None:
    job = submit()
    with caplog.at_level(logging.INFO, logger="kale.server.audit"):
        await make_worker(fast, modules, session_factory).run_once()
    assert f"job finished id={job.id} status=succeeded duration=" in caplog.text


async def test_run_forever_cleans_orphans_and_stops(
    submit: Submit, fast: Settings, modules: Registry, session_factory: sessionmaker[Session]
) -> None:
    fast.upload_dir.mkdir(parents=True)
    stray = fast.upload_dir / "stray"
    stray.write_bytes(b"left behind")
    job = submit()
    stop = asyncio.Event()
    task = asyncio.create_task(make_worker(fast, modules, session_factory).run_forever(stop))
    for _ in range(100):
        await asyncio.sleep(0.02)
        if fetch(session_factory, job.id).status is JobStatus.SUCCEEDED:
            break
    assert fetch(session_factory, job.id).status is JobStatus.SUCCEEDED
    assert not stray.exists()
    stop.set()
    await asyncio.wait_for(task, 1)


async def test_database_errors_back_off(
    fast: Settings,
    modules: Registry,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = make_worker(fast, modules, session_factory)
    stop = asyncio.Event()
    waits: list[float] = []
    calls = 0

    async def broken() -> bool:
        nonlocal calls
        calls += 1
        if calls > 7:
            stop.set()
            return False
        raise OperationalError("SELECT 1", {}, Exception("database is down"))

    async def wait(seconds: float, stop: asyncio.Event) -> None:
        waits.append(seconds)

    monkeypatch.setattr(worker, "run_once", broken)
    monkeypatch.setattr(worker, "_wait", wait)
    await asyncio.wait_for(worker.run_forever(stop), 1)
    assert waits == [1, 2, 4, 8, 16, 30, 30, fast.worker_poll_seconds]  # then one idle wait


def test_worker_id_defaults_to_host_and_process(
    fast: Settings, modules: Registry, session_factory: sessionmaker[Session]
) -> None:
    worker = Worker(fast, modules, session_factory)
    host, pid = worker.worker_id.rsplit(":", 1)
    assert host and int(pid) > 0


async def test_signals_set_the_stop_event(monkeypatch: pytest.MonkeyPatch) -> None:
    loop = asyncio.get_running_loop()
    installed: dict[int, Any] = {}

    def no_loop_signals(sig: int, handler: Any) -> None:
        raise NotImplementedError  # as on Windows

    monkeypatch.setattr(loop, "add_signal_handler", no_loop_signals)
    monkeypatch.setattr(signal, "signal", lambda sig, h: installed.setdefault(sig, h))
    stop = asyncio.Event()
    install_signal_handlers(stop)
    assert set(installed) == {signal.SIGINT, signal.SIGTERM}
    installed[signal.SIGTERM](signal.SIGTERM, None)
    await asyncio.wait_for(stop.wait(), 1)

    on_loop: dict[int, Any] = {}
    monkeypatch.setattr(loop, "add_signal_handler", lambda sig, cb: on_loop.setdefault(sig, cb))
    other = asyncio.Event()
    install_signal_handlers(other)
    assert set(on_loop) == {signal.SIGINT, signal.SIGTERM}
    on_loop[signal.SIGINT]()
    assert other.is_set()
