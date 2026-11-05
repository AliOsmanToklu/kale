"""The job service: validate and queue jobs, claim and finish them, cancel them.

Nothing here knows about HTTP, so the API, the CLI and a web UI share one set of rules.
Every function takes ``now`` instead of reading the clock.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from pydantic import JsonValue, ValidationError
from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session

from kale.core import (
    InvalidInputError,
    Kind,
    Module,
    Observable,
    Registry,
    Scope,
    UnknownModuleError,
)
from kale.core.module import resolve_options
from kale.core.pipeline import MAX_DEPTH, check_options
from kale.server.config import Settings
from kale.server.errors import BadRequest, Conflict, NotFound
from kale.server.schemas import InvestigateJobIn, RunJobIn, TargetIn
from kale.server.tables import Job, JobKind, JobStatus, Token, Upload
from kale.server.uploads import delete_upload

audit = logging.getLogger("kale.server.audit")


def _printable(text: str) -> str:
    """``text`` safe for a log line: control characters escaped, so none can fake a line."""
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in text)


def _module(registry: Registry, name: str) -> Module:
    try:
        return registry.get(name)
    except UnknownModuleError as exc:
        reason = registry.reason_unavailable(name)
        if reason:
            raise BadRequest(f"module {name} is unavailable: {reason}") from None
        raise BadRequest(str(exc)) from None


def _target(target: TargetIn, upload: Upload | None) -> Observable:
    if target.kind is Kind.FILE:
        if upload is None:
            raise BadRequest("a file target needs an uploaded file")
        if target.value is not None:
            raise BadRequest("a file target takes no value: its value is the uploaded file")
        return Observable(kind=Kind.FILE, value=upload.stored_path)
    if upload is not None:
        raise BadRequest("an uploaded file needs a file target")
    if target.value is None:
        raise BadRequest(f"a {target.kind} target needs a value")
    try:
        return Observable(kind=target.kind, value=target.value)
    except ValidationError as exc:
        reason = exc.errors()[0]["msg"].removeprefix("Value error, ")
        raise BadRequest(f"invalid {target.kind} target: {reason}") from None


def _scope(request: RunJobIn | InvestigateJobIn, server: Scope | None) -> dict[str, Any]:
    """The job's scope: the server scope, or the narrower one the request asks for."""
    allows_private = server is not None and server.allow_private
    if request.allow_private and not allows_private:
        raise BadRequest("private addresses are not allowed by the server")
    if request.scope is None:
        if server is None:
            return {"entries": [], "allow_private": False}
        return {"entries": server.entries(), "allow_private": server.allow_private}
    try:
        narrowed = (server or Scope()).narrow(request.scope, allow_private=request.allow_private)
    except InvalidInputError as exc:
        raise BadRequest(str(exc)) from None
    return {"entries": narrowed.entries(), "allow_private": narrowed.allow_private}


def _run_options(registry: Registry, request: RunJobIn, target: Observable) -> dict[str, Any]:
    module = _module(registry, request.module)
    if target.kind not in module.spec.accepts:
        raise BadRequest(f"{request.module} does not accept {target.kind} targets")
    try:
        resolve_options(module.spec, request.options)
    except InvalidInputError as exc:
        raise BadRequest(str(exc)) from None
    return dict(request.options)


def _investigate_options(
    registry: Registry, request: InvestigateJobIn, settings: Settings
) -> dict[str, Any]:
    if not 0 <= request.depth <= MAX_DEPTH:
        raise BadRequest(f"depth must be between 0 and {MAX_DEPTH}")
    if not 1 <= request.max_runs <= settings.max_runs:
        raise BadRequest(f"max_runs must be between 1 and {settings.max_runs}")
    for name in request.modules or ():
        _module(registry, name)
    for name in request.options:
        _module(registry, name)
    try:
        check_options(registry, request.options)
        for name, values in request.options.items():
            resolve_options(registry.get(name).spec, values)  # the values, not only the names
    except InvalidInputError as exc:
        raise BadRequest(str(exc)) from None
    return {
        "depth": request.depth,
        "modules": request.modules,
        "max_runs": request.max_runs,
        "options": request.options,
    }


def submit_job(
    db: Session,
    request: RunJobIn | InvestigateJobIn,
    *,
    registry: Registry,
    server_scope: Scope | None,
    settings: Settings,
    token: Token,
    upload: Upload | None,
    now: datetime,
) -> Job:
    """Validate ``request`` completely and queue it; a rejected request adds nothing."""
    target = _target(request.target, upload)
    if isinstance(request, RunJobIn):
        kind, module = JobKind.RUN, request.module
        options = _run_options(registry, request, target)
    else:
        kind, module = JobKind.INVESTIGATE, None
        options = _investigate_options(registry, request, settings)
    job = Job(
        kind=kind,
        module=module,
        target=target.model_dump(mode="json"),
        options=options,
        scope=_scope(request, server_scope),
        lang=request.lang,
        status=JobStatus.QUEUED,
        created_by=token.id,
        created_at=now,
        upload_id=upload.id if upload else None,
    )
    db.add(job)
    db.commit()
    audit.info(
        "job submitted id=%s token=%s kind=%s module=%s target=%s:%s",
        job.id,
        _printable(token.name),
        kind,
        module or "-",
        target.kind,
        _printable(target.value),
    )
    return job


def get_job(db: Session, job_id: str) -> Job:
    job = db.get(Job, job_id)
    if job is None:
        raise NotFound(f"no job {job_id}")
    return job


def list_jobs(
    db: Session, *, status: JobStatus | None, limit: int, before: datetime | None
) -> list[Job]:
    """Newest first. ``before`` pages back in time; a naive value counts as UTC."""
    query = select(Job).order_by(Job.created_at.desc(), Job.id.desc()).limit(limit)
    if status is not None:
        query = query.where(Job.status == status)
    if before is not None:
        if before.tzinfo is None:
            before = before.replace(tzinfo=UTC)
        query = query.where(Job.created_at < before)
    return list(db.scalars(query).unique())


def _update(db: Session, job_id: str, *conditions: Any, **values: Any) -> bool:
    """Change one job only if it still matches ``conditions``; ``True`` when it did.

    The condition is checked by the database inside the UPDATE, so of two processes
    acting on the same job at the same moment exactly one wins. Not committed.
    """
    statement = (
        update(Job)
        .where(Job.id == job_id, *conditions)
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    return cast(CursorResult[Any], db.execute(statement)).rowcount == 1


def cancel_job(db: Session, job_id: str, *, now: datetime) -> Job:
    """Cancel a queued job and delete its file. Running modules cannot be stopped safely."""
    job = get_job(db, job_id)
    if not _update(
        db,
        job_id,
        Job.status == JobStatus.QUEUED,
        status=JobStatus.CANCELLED,
        finished_at=now,
    ):
        db.rollback()
        raise Conflict("only queued jobs can be cancelled")
    db.commit()
    db.refresh(job)
    if job.upload is not None:
        delete_upload(db, job.upload, now=now)
    return job


# How many queued jobs a worker looks at per claim: when another worker takes the
# oldest one first, the next is tried without a new query.
CLAIM_BATCH = 5


def _claim(db: Session, job_id: str, *, worker_id: str, now: datetime) -> bool:
    claimed = _update(
        db,
        job_id,
        Job.status == JobStatus.QUEUED,
        status=JobStatus.RUNNING,
        worker_id=worker_id,
        started_at=now,
        heartbeat_at=now,
        attempts=Job.attempts + 1,
    )
    if claimed:
        db.commit()
    else:
        db.rollback()  # end the write transaction at once: other workers wait for it
    return claimed


def claim_next(db: Session, *, worker_id: str, now: datetime) -> Job | None:
    """Take the oldest queued job for ``worker_id``, or ``None`` when there is none."""
    candidates = list(
        db.scalars(
            select(Job.id)
            .where(Job.status == JobStatus.QUEUED)
            .order_by(Job.created_at, Job.id)
            .limit(CLAIM_BATCH)
        )
    )
    db.rollback()  # the read must not hold its snapshot while this worker writes
    for job_id in candidates:
        if _claim(db, job_id, worker_id=worker_id, now=now):
            return db.get(Job, job_id, populate_existing=True)
    return None


def _running(worker_id: str | None) -> tuple[Any, ...]:
    """Conditions for touching a running job; with ``worker_id``, only that worker's.

    A worker whose heartbeat went stale may still be running a job another worker has
    recovered and claimed since; it must not overwrite that worker's job.
    """
    running = Job.status == JobStatus.RUNNING
    return (running,) if worker_id is None else (running, Job.worker_id == worker_id)


def heartbeat(db: Session, job_id: str, *, now: datetime, worker_id: str | None = None) -> bool:
    """Refresh a running job's heartbeat; ``False`` when it is no longer running (here)."""
    changed = _update(db, job_id, *_running(worker_id), heartbeat_at=now)
    db.commit()
    return changed


def complete_job(
    db: Session,
    job_id: str,
    result: dict[str, JsonValue],
    *,
    now: datetime,
    worker_id: str | None = None,
) -> bool:
    """Store the result; ``False`` when the job is no longer running (here)."""
    changed = _update(
        db,
        job_id,
        *_running(worker_id),
        status=JobStatus.SUCCEEDED,
        result=result,
        error=None,
        finished_at=now,
    )
    db.commit()
    return changed


def fail_job(
    db: Session, job_id: str, error: str, *, now: datetime, worker_id: str | None = None
) -> bool:
    """Fail the job with ``error``; ``False`` when it is no longer running (here)."""
    changed = _update(
        db,
        job_id,
        *_running(worker_id),
        status=JobStatus.FAILED,
        error=error,
        finished_at=now,
    )
    db.commit()
    return changed


def recover_stale(db: Session, *, now: datetime, stale_seconds: float, max_attempts: int) -> int:
    """Put back running jobs whose worker stopped sending heartbeats; return how many.

    A job that has already used ``max_attempts`` claims fails instead: a sample that
    kills the worker process must not loop forever. Its file is deleted with it.
    """
    cutoff = now - timedelta(seconds=stale_seconds)
    stale = Job.status == JobStatus.RUNNING, Job.heartbeat_at < cutoff
    rows = db.execute(select(Job.id, Job.attempts, Job.upload_id).where(*stale)).all()
    db.rollback()
    recovered = 0
    for job_id, attempts, upload_id in rows:
        if attempts >= max_attempts:
            changed = _update(
                db,
                job_id,
                *stale,
                status=JobStatus.FAILED,
                error=f"worker stopped {attempts} times while running this job",
                finished_at=now,
            )
        else:
            changed = _update(
                db,
                job_id,
                *stale,
                status=JobStatus.QUEUED,
                worker_id=None,
                started_at=None,
                heartbeat_at=None,
            )
        db.commit()
        if not changed:
            continue
        recovered += 1
        upload = db.get(Upload, upload_id) if upload_id and attempts >= max_attempts else None
        if upload is not None:
            delete_upload(db, upload, now=now)
    return recovered
