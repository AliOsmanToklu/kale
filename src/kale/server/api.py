"""The ``/api/v1`` routes: parse the request, call the service layer, shape the answer."""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import TypeAdapter, ValidationError
from sqlalchemy.orm import Session

from kale.core import Investigation, ModuleResult, Registry, Scope
from kale.report import render_investigation_text, render_text
from kale.server.auth import get_db, require
from kale.server.config import Settings
from kale.server.db import utcnow
from kale.server.errors import Conflict, TooLarge
from kale.server.jobs import cancel_job, get_job, list_jobs, submit_job
from kale.server.multipart import InvalidMultipart, MultipartReader
from kale.server.schemas import (
    ErrorOut,
    JobAccepted,
    JobIn,
    JobList,
    JobOut,
    JobSummary,
    ModuleOut,
    ModulesOut,
    ScopeOut,
    UnavailableOut,
)
from kale.server.tables import JobKind, JobStatus, Role, Token, Upload
from kale.server.uploads import store_upload

JOB_IN: TypeAdapter[Any] = TypeAdapter(JobIn)
MB = 1024 * 1024
JSON_LIMIT = MB  # the JSON body, or the job part of a multipart body
UNSUPPORTED = "send the job as application/json, or as multipart/form-data with a file"

Reader = Annotated[Token, Depends(require(Role.READER))]
Runner = Annotated[Token, Depends(require(Role.RUNNER))]
Db = Annotated[Session, Depends(get_db)]


@dataclass(frozen=True, slots=True)
class Service:
    """What the routes need besides the request; kept on ``app.state.service``."""

    settings: Settings
    registry: Registry
    scope: Scope | None
    environ: Mapping[str, str]


def service(request: Request) -> Service:
    found: Service = request.app.state.service
    return found


Svc = Annotated[Service, Depends(service)]

ERRORS: dict[int | str, dict[str, Any]] = {
    code: {"model": ErrorOut} for code in (400, 401, 403, 404, 409, 413, 415, 422)
}

router = APIRouter(prefix="/api/v1", responses=ERRORS)


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/modules")
def modules(_: Reader, svc: Svc) -> ModulesOut:
    return ModulesOut(
        modules=[ModuleOut.of(m.spec, svc.environ) for m in svc.registry.modules],
        unavailable=[
            UnavailableOut(name=u.name, reason=u.reason) for u in svc.registry.unavailable
        ],
    )


@router.get("/scope")
def scope(_: Reader, svc: Svc) -> ScopeOut:
    server = svc.scope or Scope()
    return ScopeOut(
        domains=sorted(server.domains),
        networks=[str(network) for network in server.networks],
        allow_private=server.allow_private,
    )


def _invalid(error: ValidationError) -> RequestValidationError:
    return RequestValidationError(error.errors(include_url=False))


def _parse_job(raw: str | bytes) -> Any:
    try:
        return JOB_IN.validate_json(raw)
    except ValidationError as exc:
        raise _invalid(exc) from None


@router.post(
    "/jobs",
    status_code=202,
    response_model=JobAccepted,
    summary="Submit a module run or an investigation",
    description=(
        "Send the job as JSON, or as multipart/form-data with the job JSON in a `job` part "
        'and the file in a `file` part when the target is `{"kind": "file"}`.'
    ),
)
async def create_job(request: Request, token: Runner, db: Db, svc: Svc) -> JSONResponse:
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    common: dict[str, Any] = {
        "registry": svc.registry,
        "server_scope": svc.scope,
        "settings": svc.settings,
        "token": token,
    }
    if media_type == "application/json":
        job = submit_job(db, _parse_job(await request.body()), upload=None, now=utcnow(), **common)
    elif media_type == "multipart/form-data":
        job = await _file_job(request, db, svc, common)
    else:
        return JSONResponse({"detail": UNSUPPORTED}, status_code=415)
    body = JobAccepted(id=job.id, status=job.status).model_dump(mode="json")
    return JSONResponse(body, status_code=202, headers={"Location": f"/api/v1/jobs/{job.id}"})


def _bad_body(message: str) -> RequestValidationError:
    return RequestValidationError([{"loc": (), "msg": message}])


async def _file_job(request: Request, db: Session, svc: Service, common: dict[str, Any]) -> Any:
    """Queue a job from a ``job`` part and a ``file`` part, in either order.

    The file streams straight into the quarantine. When anything goes wrong after that,
    from a broken body to a rejected job, neither the file nor a row stays behind.
    """
    try:
        reader = MultipartReader(request.stream(), request.headers["content-type"])
    except InvalidMultipart as exc:
        raise _bad_body(str(exc)) from None
    parsed: Any = None
    upload: Upload | None = None
    try:
        while (part := await reader.next_part()) is not None:
            if part.name == "job" and parsed is None:
                text = await reader.read(JSON_LIMIT)
                if text is None:
                    raise TooLarge("the job part is over the 1 MB limit")
                parsed = _parse_job(text)  # before the file, when the job comes first
            elif part.name == "file" and upload is None:
                upload = await store_upload(
                    db,
                    reader.data(),
                    original_name=part.filename,
                    directory=svc.settings.upload_dir,
                    limit_bytes=svc.settings.max_upload_mb * MB,
                    now=utcnow(),
                )
            else:
                raise _bad_body(f"unexpected part {part.name!r}: send one 'job' and one 'file'")
        if parsed is None or upload is None:
            raise _bad_body("a multipart job needs a 'job' part and a 'file' part")
        return submit_job(db, parsed, upload=upload, now=utcnow(), **common)
    except InvalidMultipart as exc:
        _discard(db, upload)
        raise _bad_body(str(exc)) from None
    except BaseException:
        _discard(db, upload)
        raise


def _discard(db: Session, upload: Upload | None) -> None:
    db.rollback()
    if upload is not None:
        with contextlib.suppress(OSError):
            Path(upload.stored_path).unlink(missing_ok=True)


@router.get("/jobs")
def jobs(
    _: Reader,
    db: Db,
    status: JobStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before: Annotated[
        datetime | None, Query(description="ISO timestamp: only jobs created before it")
    ] = None,
) -> JobList:
    found = list_jobs(db, status=status, limit=limit, before=before)
    return JobList(jobs=[JobSummary.of(job) for job in found])


@router.get("/jobs/{job_id}")
def job(job_id: str, _: Reader, db: Db) -> JobOut:
    return JobOut.of(get_job(db, job_id))


@router.get("/jobs/{job_id}/report", response_class=PlainTextResponse)
def report(job_id: str, _: Reader, db: Db, format: Literal["text"] = "text") -> PlainTextResponse:
    found = get_job(db, job_id)
    if found.result is None:
        raise Conflict(f"job {job_id} has no result (status: {found.status})")
    if found.kind is JobKind.RUN:
        text = render_text(ModuleResult.model_validate(found.result))
    else:
        text = render_investigation_text(Investigation.model_validate(found.result))
    return PlainTextResponse(text)


@router.post("/jobs/{job_id}/cancel")
def cancel(job_id: str, _: Runner, db: Db) -> JobOut:
    return JobOut.of(cancel_job(db, job_id, now=utcnow()))
