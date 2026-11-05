"""Request and response bodies of the API."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from kale.core import Kind, ModuleSpec, Severity
from kale.server.tables import Job, JobKind, JobStatus


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TargetIn(_In):
    kind: Kind
    # Omitted for a file target: the file comes in the request's "file" part.
    value: str | None = None


class RunJobIn(_In):
    kind: Literal["run"]
    module: str
    target: TargetIn
    options: dict[str, str] = {}
    # Omitted: the whole server scope. Given: it may only narrow the server scope.
    scope: list[str] | None = None
    allow_private: bool = False
    lang: Literal["en", "tr"] = "en"


class InvestigateJobIn(_In):
    kind: Literal["investigate"]
    target: TargetIn
    depth: int = 2
    modules: list[str] | None = None
    options: dict[str, dict[str, str]] = {}
    max_runs: int = 50
    scope: list[str] | None = None
    allow_private: bool = False
    lang: Literal["en", "tr"] = "en"


JobIn = Annotated[RunJobIn | InvestigateJobIn, Field(discriminator="kind")]


# Responses


class JobAccepted(BaseModel):
    id: str
    status: JobStatus


class UploadOut(BaseModel):
    """What is kept about an uploaded file. Its contents are never served."""

    name: str
    size: int
    sha256: str


class JobOut(BaseModel):
    id: str
    kind: JobKind
    module: str | None
    target: dict[str, JsonValue]
    status: JobStatus
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    attempts: int
    # Infrastructure failures only; a module's own error is inside the result.
    error: str | None
    # A ModuleResult (schemas/result.v1.json) or an Investigation, once succeeded.
    result: dict[str, JsonValue] | None
    upload: UploadOut | None

    @classmethod
    def of(cls, job: Job) -> JobOut:
        upload = job.upload
        return cls(
            id=job.id,
            kind=job.kind,
            module=job.module,
            target=job.target,
            status=job.status,
            created_at=job.created_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            attempts=job.attempts,
            error=job.error,
            result=job.result,
            upload=UploadOut(name=upload.original_name, size=upload.size, sha256=upload.sha256)
            if upload
            else None,
        )


class JobSummary(BaseModel):
    id: str
    kind: JobKind
    module: str | None
    target: dict[str, JsonValue]
    status: JobStatus
    created_at: datetime
    finished_at: datetime | None
    worst_severity: Severity | None
    # Findings per severity; severities without findings are left out.
    counts: dict[Severity, int]

    @classmethod
    def of(cls, job: Job) -> JobSummary:
        found = [Severity(s) for s in _severities(job.result)]
        return cls(
            id=job.id,
            kind=job.kind,
            module=job.module,
            target=job.target,
            status=job.status,
            created_at=job.created_at,
            finished_at=job.finished_at,
            worst_severity=min(found, key=lambda s: s.rank, default=None),
            counts={s: found.count(s) for s in Severity if s in found},
        )


def _severities(result: dict[str, Any] | None) -> list[str]:
    if result is None:
        return []
    runs = result.get("runs", [result])  # an Investigation, or a single ModuleResult
    return [finding["severity"] for run in runs for finding in run.get("findings", ())]


class JobList(BaseModel):
    jobs: list[JobSummary]


class OptionOut(BaseModel):
    type: str
    default: str | int | float | bool
    help: str
    choices: list[str]
    minimum: float | None
    maximum: float | None


class ModuleOut(BaseModel):
    name: str
    version: str
    summary: str
    category: str
    accepts: list[Kind]
    active: bool
    timeout: float
    options: dict[str, OptionOut]
    # Whether each service key is set in the server's environment; never the value.
    secrets_configured: dict[str, bool]

    @classmethod
    def of(cls, spec: ModuleSpec, environ: Mapping[str, str]) -> ModuleOut:
        return cls(
            name=spec.name,
            version=spec.version,
            summary=spec.summary,
            category=spec.category,
            accepts=sorted(spec.accepts),
            active=spec.active,
            timeout=spec.timeout,
            options={
                name: OptionOut(
                    type=option.type,
                    default=option.default,
                    help=option.help,
                    choices=list(option.choices),
                    minimum=option.minimum,
                    maximum=option.maximum,
                )
                for name, option in spec.options.items()
            },
            secrets_configured={
                name: bool(environ.get(name))
                for name in sorted(spec.secrets | spec.optional_secrets)
            },
        )


class UnavailableOut(BaseModel):
    name: str
    reason: str


class ModulesOut(BaseModel):
    modules: list[ModuleOut]
    unavailable: list[UnavailableOut]


class ScopeOut(BaseModel):
    domains: list[str]
    networks: list[str]
    allow_private: bool


class ErrorOut(BaseModel):
    detail: str
