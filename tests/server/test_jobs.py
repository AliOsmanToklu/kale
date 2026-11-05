from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import TypeAdapter
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kale.core import Registry, Scope, Unavailable
from kale.server.config import Settings
from kale.server.errors import BadRequest, Conflict, NotFound
from kale.server.jobs import cancel_job, get_job, list_jobs, submit_job
from kale.server.schemas import JobIn
from kale.server.tables import Job, JobKind, JobStatus, Role, Token, Upload
from kale.server.tokens import create_token
from kale.server.uploads import store_upload

T = datetime(2026, 11, 5, 12, tzinfo=UTC)
SERVER = Scope.parse(["example.com", "8.8.8.0/24"])
JOB_IN: TypeAdapter[Any] = TypeAdapter(JobIn)


@pytest.fixture
def token(db: Session) -> Token:
    return create_token(db, "ci", Role.RUNNER, now=T)[0]


def request(**fields: Any) -> Any:
    body: dict[str, Any] = {
        "kind": "run",
        "module": "fake.echo",
        "target": {"kind": "domain", "value": "shop.example.com"},
    }
    body.update(fields)
    if body["kind"] == "investigate":
        del body["module"]
    return JOB_IN.validate_python(body)


def submit(
    db: Session,
    registry: Registry,
    settings: Settings,
    token: Token,
    *,
    server_scope: Scope | None = SERVER,
    upload: Upload | None = None,
    now: datetime = T,
    **fields: Any,
) -> Job:
    return submit_job(
        db,
        request(**fields),
        registry=registry,
        server_scope=server_scope,
        settings=settings,
        token=token,
        upload=upload,
        now=now,
    )


def job_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(Job)) or 0


async def one_chunk() -> AsyncIterator[bytes]:
    yield b"Nov  5 12:00:00 host sshd[1]: Failed password for root\n"


async def an_upload(db: Session, settings: Settings) -> Upload:
    return await store_upload(
        db,
        one_chunk(),
        original_name="auth.log",
        directory=settings.upload_dir,
        limit_bytes=2**20,
        now=T,
    )


def test_run_job_is_queued_with_the_narrowed_scope(
    db: Session, registry: Registry, settings: Settings, token: Token
) -> None:
    job = submit(
        db, registry, settings, token, scope=["shop.example.com"], options={"count": "2"}, lang="tr"
    )
    db.expire_all()
    stored = get_job(db, job.id)
    assert stored.status is JobStatus.QUEUED
    assert stored.kind is JobKind.RUN
    assert stored.module == "fake.echo"
    assert stored.target == {"kind": "domain", "value": "shop.example.com", "source": ""}
    assert stored.options == {"count": "2"}
    assert stored.scope == {"entries": ["shop.example.com"], "allow_private": False}
    assert stored.lang == "tr"
    assert stored.created_by == token.id
    assert stored.created_at == T
    assert stored.attempts == 0


def test_without_scope_the_server_scope_is_used(
    db: Session, registry: Registry, settings: Settings, token: Token
) -> None:
    job = submit(db, registry, settings, token)
    assert job.scope == {"entries": ["example.com", "8.8.8.0/24"], "allow_private": False}
    private = Scope.parse(["10.0.0.0/8"], allow_private=True)
    job = submit(db, registry, settings, token, server_scope=private)
    assert job.scope == {"entries": ["10.0.0.0/8"], "allow_private": True}
    job = submit(db, registry, settings, token, server_scope=None)
    assert job.scope == {"entries": [], "allow_private": False}


@pytest.mark.parametrize(
    ("fields", "server_scope", "message"),
    [
        ({"scope": ["example.com"]}, Scope.parse(["shop.example.com"]), "example.com"),
        ({"scope": ["example.com"]}, None, "not covered by the server scope: example.com"),
        ({"scope": ["8.8.8.0/24"], "allow_private": True}, SERVER, "private addresses"),
        ({"allow_private": True}, SERVER, "private addresses"),
    ],
)
def test_wider_scope_is_rejected(
    db: Session,
    registry: Registry,
    settings: Settings,
    token: Token,
    fields: dict[str, Any],
    server_scope: Scope | None,
    message: str,
) -> None:
    with pytest.raises(BadRequest, match=message):
        submit(db, registry, settings, token, server_scope=server_scope, **fields)
    assert job_count(db) == 0


def test_wider_scope_message_lists_the_entry(
    db: Session, registry: Registry, settings: Settings, token: Token
) -> None:
    with pytest.raises(BadRequest, match=r"not covered by the server scope: example\.com$"):
        submit(
            db,
            registry,
            settings,
            token,
            server_scope=Scope.parse(["shop.example.com"]),
            scope=["example.com", "shop.example.com"],
        )


def test_unknown_and_unavailable_modules(
    db: Session, registry: Registry, settings: Settings, token: Token
) -> None:
    with pytest.raises(BadRequest, match=r"unknown module: fake.nope"):
        submit(db, registry, settings, token, module="fake.nope")
    missing = Registry([], [Unavailable("x.y", "missing dependency: z")])
    with pytest.raises(BadRequest, match=r"module x.y is unavailable: missing dependency: z"):
        submit(db, missing, settings, token, module="x.y")
    assert job_count(db) == 0


async def test_kind_must_be_accepted(
    db: Session, registry: Registry, settings: Settings, token: Token
) -> None:
    upload = await an_upload(db, settings)
    with pytest.raises(BadRequest, match=r"fake.echo does not accept file targets"):
        submit(db, registry, settings, token, target={"kind": "file"}, upload=upload)
    with pytest.raises(BadRequest, match=r"logs.auth does not accept domain targets"):
        submit(db, registry, settings, token, module="logs.auth")
    assert job_count(db) == 0


def test_options_are_validated(
    db: Session, registry: Registry, settings: Settings, token: Token
) -> None:
    with pytest.raises(BadRequest, match="unknown option"):
        submit(db, registry, settings, token, options={"colour": "red"})
    with pytest.raises(BadRequest, match="count"):
        submit(db, registry, settings, token, options={"count": "many"})
    assert job_count(db) == 0


def investigation(**fields: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "kind": "investigate",
        "target": {"kind": "domain", "value": "example.com"},
    }
    body.update(fields)
    return body


def test_investigate_job_is_queued(
    db: Session, registry: Registry, settings: Settings, token: Token
) -> None:
    job = submit(
        db,
        registry,
        settings,
        token,
        **investigation(
            depth=1,
            modules=["fake.discover"],
            options={"fake.discover": {"extra": "a.example.com"}},
            max_runs=7,
        ),
    )
    assert job.kind is JobKind.INVESTIGATE
    assert job.module is None
    assert job.options == {
        "depth": 1,
        "modules": ["fake.discover"],
        "max_runs": 7,
        "options": {"fake.discover": {"extra": "a.example.com"}},
    }


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"depth": 6}, "depth must be between 0 and 5"),
        ({"depth": -1}, "depth must be between 0 and 5"),
        ({"max_runs": 101}, "max_runs must be between 1 and 100"),
        ({"max_runs": 0}, "max_runs must be between 1 and 100"),
        ({"modules": ["fake.discover", "fake.nope"]}, "unknown module: fake.nope"),
        ({"options": {"fake.discover": {"colour": "red"}}}, "unknown option"),
        ({"options": {"fake.nope": {}}}, "unknown module: fake.nope"),
        ({"options": {"fake.echo": {"count": "many"}}}, "count"),
    ],
)
def test_investigate_limits(
    db: Session,
    registry: Registry,
    settings: Settings,
    token: Token,
    fields: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(BadRequest, match=message):
        submit(db, registry, settings, token, **investigation(**fields))
    assert job_count(db) == 0


async def test_file_target_needs_an_upload_and_vice_versa(
    db: Session, registry: Registry, settings: Settings, token: Token
) -> None:
    with pytest.raises(BadRequest, match="a file target needs an uploaded file"):
        submit(db, registry, settings, token, module="logs.auth", target={"kind": "file"})
    with pytest.raises(BadRequest, match="a file target needs an uploaded file"):
        submit(
            db,
            registry,
            settings,
            token,
            module="logs.auth",
            target={"kind": "file", "value": "/etc/passwd"},
        )
    upload = await an_upload(db, settings)
    with pytest.raises(BadRequest, match="an uploaded file needs a file target"):
        submit(db, registry, settings, token, upload=upload)
    with pytest.raises(BadRequest, match="takes no value"):
        submit(
            db,
            registry,
            settings,
            token,
            module="logs.auth",
            target={"kind": "file", "value": "/etc/passwd"},
            upload=upload,
        )
    job = submit(
        db, registry, settings, token, module="logs.auth", target={"kind": "file"}, upload=upload
    )
    assert job.upload_id == upload.id
    assert job.target["value"] == upload.stored_path
    assert job_count(db) == 1


@pytest.mark.parametrize(
    "target",
    [{"kind": "ip", "value": "999.1.1.1"}, {"kind": "domain"}, {"kind": "domain", "value": " "}],
)
def test_invalid_target_value(
    db: Session, registry: Registry, settings: Settings, token: Token, target: dict[str, Any]
) -> None:
    with pytest.raises(BadRequest, match="target"):
        submit(db, registry, settings, token, target=target)
    assert job_count(db) == 0


def test_audit_line(
    db: Session,
    registry: Registry,
    settings: Settings,
    token: Token,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="kale.server.audit"):
        job = submit(
            db, registry, settings, token, target={"kind": "domain", "value": "Example.COM"}
        )
    [record] = [r for r in caplog.records if r.name == "kale.server.audit"]
    line = record.getMessage()
    assert line == (
        f"job submitted id={job.id} token=ci kind=run module=fake.echo target=domain:example.com"
    )
    assert "kale_" not in line


async def test_cancel(db: Session, registry: Registry, settings: Settings, token: Token) -> None:
    upload = await an_upload(db, settings)
    job = submit(
        db, registry, settings, token, module="logs.auth", target={"kind": "file"}, upload=upload
    )
    cancelled = cancel_job(db, job.id, now=T + timedelta(seconds=5))
    assert cancelled.status is JobStatus.CANCELLED
    assert cancelled.finished_at == T + timedelta(seconds=5)
    assert not Path(upload.stored_path).exists()
    assert upload.deleted_at == T + timedelta(seconds=5)
    with pytest.raises(Conflict, match="only queued jobs can be cancelled"):
        cancel_job(db, job.id, now=T)

    running = submit(db, registry, settings, token)
    running.status = JobStatus.RUNNING
    db.commit()
    with pytest.raises(Conflict, match="only queued jobs can be cancelled"):
        cancel_job(db, running.id, now=T)
    with pytest.raises(NotFound):
        cancel_job(db, "nope", now=T)


def test_list_and_page(db: Session, registry: Registry, settings: Settings, token: Token) -> None:
    jobs = [submit(db, registry, settings, token, now=T + timedelta(seconds=i)) for i in range(3)]
    jobs[0].status = JobStatus.SUCCEEDED
    db.commit()
    assert [j.id for j in list_jobs(db, status=None, limit=2, before=None)] == [
        jobs[2].id,
        jobs[1].id,
    ]
    before = T + timedelta(seconds=1)
    assert [j.id for j in list_jobs(db, status=None, limit=50, before=before)] == [jobs[0].id]
    naive = before.replace(tzinfo=None)
    assert [j.id for j in list_jobs(db, status=None, limit=50, before=naive)] == [jobs[0].id]
    queued = list_jobs(db, status=JobStatus.QUEUED, limit=50, before=None)
    assert [j.id for j in queued] == [jobs[2].id, jobs[1].id]


def test_get_missing(db: Session) -> None:
    with pytest.raises(NotFound, match="no job nope"):
        get_job(db, "nope")
