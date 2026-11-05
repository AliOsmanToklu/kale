from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import TypeAdapter
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from kale.core import Kind, Observable, Registry, run_module
from kale.server.app import create_app
from kale.server.auth import get_db
from kale.server.config import ConfigError, Settings
from kale.server.db import make_engine, utcnow
from kale.server.jobs import claim_next, complete_job, submit_job
from kale.server.migrate import SchemaOutdated, upgrade_database
from kale.server.schemas import JobIn
from kale.server.tables import Job, Role, Token, Upload
from kale.server.tokens import create_token, revoke_token
from tests.fakes import EchoModule

MB = 1024 * 1024
RUN: dict[str, Any] = {
    "kind": "run",
    "module": "fake.echo",
    "target": {"kind": "domain", "value": "shop.example.com"},
}
LOG_JOB = json.dumps({"kind": "run", "module": "logs.auth", "target": {"kind": "file"}})


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.txt"
    path.write_text("example.com\n8.8.8.0/24\n", encoding="utf-8")
    return path


@pytest.fixture
def api_settings(settings: Settings, scope_file: Path) -> Settings:
    return settings.model_copy(update={"scope_file": scope_file})


def client_for(
    settings: Settings,
    registry: Registry,
    session_factory: sessionmaker[Session],
    **kwargs: Any,
) -> TestClient:
    app = create_app(
        settings,
        registry=registry,
        session_factory=session_factory,
        environ=kwargs.pop("environ", {}),
    )
    return TestClient(app, **kwargs)


@pytest.fixture
def client(
    api_settings: Settings, registry: Registry, session_factory: sessionmaker[Session]
) -> Iterator[TestClient]:
    with client_for(api_settings, registry, session_factory) as client:
        yield client


@pytest.fixture
def runner(db: Session) -> dict[str, str]:
    return bearer(create_token(db, "ci", Role.RUNNER, now=utcnow())[1])


@pytest.fixture
def reader(db: Session) -> dict[str, str]:
    return bearer(create_token(db, "dash", Role.READER, now=utcnow())[1])


def bearer(raw: str, scheme: str = "Bearer") -> dict[str, str]:
    return {"Authorization": f"{scheme} {raw}"}


def count(db: Session, table: type[Job] | type[Upload]) -> int:
    db.expire_all()
    return db.scalar(select(func.count()).select_from(table)) or 0


def test_health_needs_no_token(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_auth_failures_are_401(client: TestClient, db: Session) -> None:
    _, raw = create_token(db, "old", Role.RUNNER, now=utcnow())
    revoke_token(db, "old", now=utcnow())
    for headers in (
        {},
        {"Authorization": "Basic x"},
        {"Authorization": "Bearer"},
        bearer("kale_unknown"),
        bearer(raw),
    ):
        response = client.get("/api/v1/jobs", headers=headers)
        assert response.status_code == 401, headers
        assert response.headers["www-authenticate"] == "Bearer"
        assert set(response.json()) == {"detail"}


def test_bearer_scheme_is_case_insensitive(client: TestClient, db: Session) -> None:
    _, raw = create_token(db, "ci", Role.READER, now=utcnow())
    for scheme in ("bearer", "BEARER", "Bearer"):
        assert client.get("/api/v1/jobs", headers=bearer(raw, scheme)).status_code == 200


def test_reader_cannot_submit(client: TestClient, reader: dict[str, str]) -> None:
    response = client.post("/api/v1/jobs", json=RUN, headers=reader)
    assert response.status_code == 403
    assert "runner" in response.json()["detail"]


def test_submit_run_job(client: TestClient, runner: dict[str, str]) -> None:
    response = client.post("/api/v1/jobs", json=RUN, headers=runner)
    assert response.status_code == 202
    body = response.json()
    assert body == {"id": body["id"], "status": "queued"}
    assert response.headers["location"] == f"/api/v1/jobs/{body['id']}"
    job = client.get(response.headers["location"], headers=runner).json()
    assert job["status"] == "queued"
    assert (job["kind"], job["module"]) == ("run", "fake.echo")
    assert job["target"]["value"] == "shop.example.com"
    assert job["result"] is None and job["upload"] is None


@pytest.mark.parametrize(
    ("body", "status", "detail"),
    [
        ({**RUN, "module": "fake.nope"}, 400, "unknown module: fake.nope"),
        ({**RUN, "scope": ["other.org"]}, 400, "not covered by the server scope: other.org"),
        ({**RUN, "options": {"colour": "red"}}, 400, "unknown option"),
        ({"kind": "run"}, 422, "module"),
        ({**RUN, "kind": "bogus"}, 422, "kind"),
        ({**RUN, "extra": 1}, 422, "extra"),
        ({**RUN, "target": {"kind": "planet", "value": "x"}}, 422, "target.kind"),
    ],
)
def test_rule_errors_are_400_and_schema_errors_422(
    client: TestClient, runner: dict[str, str], body: dict[str, Any], status: int, detail: str
) -> None:
    response = client.post("/api/v1/jobs", json=body, headers=runner)
    assert response.status_code == status
    assert detail in response.json()["detail"]


def test_malformed_json_is_422(client: TestClient, runner: dict[str, str]) -> None:
    response = client.post(
        "/api/v1/jobs",
        content=b"{not json",
        headers={**runner, "Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert isinstance(response.json()["detail"], str)


def test_other_content_types_are_415(client: TestClient, runner: dict[str, str]) -> None:
    response = client.post(
        "/api/v1/jobs", content=b"kind=run", headers={**runner, "Content-Type": "text/plain"}
    )
    assert response.status_code == 415


def test_file_job(client: TestClient, runner: dict[str, str], ssh_log: Path, db: Session) -> None:
    data = ssh_log.read_bytes()
    response = client.post(
        "/api/v1/jobs",
        data={"job": LOG_JOB},
        files={"file": ("../../auth.log", data, "text/plain")},
        headers=runner,
    )
    assert response.status_code == 202, response.text
    job = client.get(response.headers["location"], headers=runner).json()
    assert job["upload"]["name"] == "auth.log"
    assert job["upload"]["size"] == len(data)
    assert len(job["upload"]["sha256"]) == 64
    assert count(db, Upload) == 1


def test_multipart_needs_both_parts(client: TestClient, runner: dict[str, str]) -> None:
    response = client.post(
        "/api/v1/jobs", files={"file": ("a.log", b"x", "text/plain")}, headers=runner
    )
    assert response.status_code == 422
    response = client.post("/api/v1/jobs", data={"job": LOG_JOB}, files={}, headers=runner)
    assert response.status_code in (415, 422)


def test_multipart_job_part_is_validated(
    client: TestClient, runner: dict[str, str], api_settings: Settings
) -> None:
    response = client.post(
        "/api/v1/jobs",
        data={"job": "{bad"},
        files={"file": ("a.log", b"x", "text/plain")},
        headers=runner,
    )
    assert response.status_code == 422
    assert not api_settings.upload_dir.exists() or not any(api_settings.upload_dir.iterdir())


def small_upload_client(
    api_settings: Settings, registry: Registry, session_factory: sessionmaker[Session]
) -> TestClient:
    settings = api_settings.model_copy(update={"max_upload_mb": 1})
    return client_for(settings, registry, session_factory)


def upload_dir_is_empty(settings: Settings) -> bool:
    return not settings.upload_dir.exists() or not any(settings.upload_dir.iterdir())


def test_upload_over_limit_is_413(
    api_settings: Settings,
    registry: Registry,
    session_factory: sessionmaker[Session],
    runner: dict[str, str],
    db: Session,
) -> None:
    with small_upload_client(api_settings, registry, session_factory) as client:
        at_limit = client.post(
            "/api/v1/jobs",
            data={"job": LOG_JOB},
            files={"file": ("a.log", b"x" * MB, "text/plain")},
            headers=runner,
        )
        assert at_limit.status_code == 202
        over = client.post(
            "/api/v1/jobs",
            data={"job": LOG_JOB},
            files={"file": ("a.log", b"x" * (MB + 1), "text/plain")},
            headers=runner,
        )
    assert over.status_code == 413
    assert over.json() == {"detail": "the file is over the 1 MB limit"}
    assert count(db, Upload) == 1
    assert len(list(api_settings.upload_dir.iterdir())) == 1


def test_rejected_file_job_leaves_nothing(
    client: TestClient, runner: dict[str, str], api_settings: Settings, db: Session
) -> None:
    job = json.dumps({"kind": "run", "module": "fake.echo", "target": {"kind": "file"}})
    response = client.post(
        "/api/v1/jobs",
        data={"job": job},
        files={"file": ("a.log", b"data", "text/plain")},
        headers=runner,
    )
    assert response.status_code == 400
    assert "does not accept file targets" in response.json()["detail"]
    assert upload_dir_is_empty(api_settings)
    assert count(db, Upload) == 0
    assert count(db, Job) == 0


def test_chunked_upload_over_limit_is_413(
    api_settings: Settings,
    registry: Registry,
    session_factory: sessionmaker[Session],
    runner: dict[str, str],
    db: Session,
) -> None:
    boundary = "kaleboundary"

    def body() -> Iterator[bytes]:
        yield (
            f'--{boundary}\r\nContent-Disposition: form-data; name="job"\r\n\r\n{LOG_JOB}\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="a.log"\r\n'
            "Content-Type: text/plain\r\n\r\n"
        ).encode()
        for _ in range(3):
            yield b"x" * MB
        yield f"\r\n--{boundary}--\r\n".encode()

    with small_upload_client(api_settings, registry, session_factory) as client:
        response = client.post(
            "/api/v1/jobs",
            content=body(),
            headers={**runner, "Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
    assert response.status_code == 413
    assert response.json() == {"detail": "request body too large"}
    assert upload_dir_is_empty(api_settings)
    assert count(db, Upload) == 0


def test_json_body_over_1_mb_is_413(client: TestClient, runner: dict[str, str]) -> None:
    body = {**RUN, "options": {"severity": "x" * MB}}
    response = client.post("/api/v1/jobs", json=body, headers=runner)
    assert response.status_code == 413
    assert response.headers["x-content-type-options"] == "nosniff"


def test_list_jobs(client: TestClient, runner: dict[str, str]) -> None:
    ids = [client.post("/api/v1/jobs", json=RUN, headers=runner).json()["id"] for _ in range(3)]
    listed = client.get("/api/v1/jobs", params={"limit": 2}, headers=runner).json()["jobs"]
    assert [j["id"] for j in listed] == [ids[2], ids[1]]
    assert listed[0]["status"] == "queued"
    assert listed[0]["worst_severity"] is None and listed[0]["counts"] == {}
    client.post(f"/api/v1/jobs/{ids[0]}/cancel", headers=runner)
    cancelled = client.get("/api/v1/jobs", params={"status": "cancelled"}, headers=runner)
    assert [j["id"] for j in cancelled.json()["jobs"]] == [ids[0]]
    assert client.get("/api/v1/jobs", params={"limit": 201}, headers=runner).status_code == 422
    assert client.get("/api/v1/jobs", params={"limit": 0}, headers=runner).status_code == 422
    assert client.get("/api/v1/jobs", params={"status": "x"}, headers=runner).status_code == 422


def test_naive_before_is_utc(
    client: TestClient,
    runner: dict[str, str],
    db: Session,
    registry: Registry,
    api_settings: Settings,
) -> None:
    token = db.scalars(select(Token)).one()
    adapter: TypeAdapter[Any] = TypeAdapter(JobIn)
    for hour in (11, 13):
        submit_job(
            db,
            adapter.validate_python(RUN),
            registry=registry,
            server_scope=None,
            settings=api_settings,
            token=token,
            upload=None,
            now=datetime(2026, 11, 5, hour, tzinfo=UTC),
        )
    naive = client.get("/api/v1/jobs", params={"before": "2026-11-05T12:00:00"}, headers=runner)
    aware = client.get("/api/v1/jobs", params={"before": "2026-11-05T12:00:00Z"}, headers=runner)
    assert naive.status_code == aware.status_code == 200
    assert naive.json() == aware.json()
    assert [j["created_at"][:13] for j in naive.json()["jobs"]] == ["2026-11-05T11"]


async def test_report(client: TestClient, runner: dict[str, str], db: Session) -> None:
    job_id = client.post(
        "/api/v1/jobs", json={**RUN, "options": {"severity": "high"}}, headers=runner
    ).json()["id"]
    early = client.get(f"/api/v1/jobs/{job_id}/report", headers=runner)
    assert early.status_code == 409
    claimed = claim_next(db, worker_id="t", now=utcnow())
    assert claimed is not None and claimed.id == job_id
    result = await run_module(
        EchoModule(),
        Observable(kind=Kind.DOMAIN, value="shop.example.com"),
        options={"severity": "high"},
    )
    complete_job(db, job_id, result.model_dump(mode="json"), now=utcnow())
    report = client.get(f"/api/v1/jobs/{job_id}/report", params={"format": "text"}, headers=runner)
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("text/plain")
    assert report.text.startswith("fake.echo")
    summary = client.get("/api/v1/jobs", headers=runner).json()["jobs"][0]
    assert summary["worst_severity"] == "high"
    assert summary["counts"] == {"high": 1}
    assert client.get(f"/api/v1/jobs/{job_id}/report?format=pdf", headers=runner).status_code == 422


def test_cancel(client: TestClient, runner: dict[str, str], reader: dict[str, str]) -> None:
    job_id = client.post("/api/v1/jobs", json=RUN, headers=runner).json()["id"]
    assert client.post(f"/api/v1/jobs/{job_id}/cancel", headers=reader).status_code == 403
    response = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=runner)
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    again = client.post(f"/api/v1/jobs/{job_id}/cancel", headers=runner)
    assert again.status_code == 409
    assert again.json() == {"detail": "only queued jobs can be cancelled"}


def test_missing_job_is_404(client: TestClient, reader: dict[str, str]) -> None:
    response = client.get("/api/v1/jobs/nope", headers=reader)
    assert response.status_code == 404
    assert response.json() == {"detail": "no job nope"}


def test_modules_show_only_whether_secrets_are_set(
    api_settings: Settings,
    registry: Registry,
    session_factory: sessionmaker[Session],
    reader: dict[str, str],
) -> None:
    registry.unavailable.append(_unavailable())
    environ = {"FAKE_OPTIONAL_KEY": "s3cret"}
    with client_for(api_settings, registry, session_factory, environ=environ) as client:
        response = client.get("/api/v1/modules", headers=reader)
    assert response.status_code == 200
    assert "s3cret" not in response.text
    body = response.json()
    modules = {m["name"]: m for m in body["modules"]}
    assert modules["fake.optional_secret"]["secrets_configured"] == {"FAKE_OPTIONAL_KEY": True}
    echo = modules["fake.echo"]
    assert echo["secrets_configured"] == {}
    assert echo["accepts"] == ["domain", "ip", "url"]
    assert echo["active"] is False
    assert echo["options"]["count"] == {
        "type": "int",
        "default": 1,
        "help": "number of findings",
        "choices": [],
        "minimum": 0,
        "maximum": None,
    }
    assert modules["fake.active"]["active"] is True
    assert body["unavailable"] == [{"name": "x.y", "reason": "missing dependency: z"}]


def _unavailable() -> Any:
    from kale.core import Unavailable

    return Unavailable("x.y", "missing dependency: z")


def test_scope_endpoint(client: TestClient, reader: dict[str, str]) -> None:
    response = client.get("/api/v1/scope", headers=reader)
    assert response.json() == {
        "domains": ["example.com"],
        "networks": ["8.8.8.0/24"],
        "allow_private": False,
    }


def test_scope_endpoint_without_a_scope(
    settings: Settings,
    registry: Registry,
    session_factory: sessionmaker[Session],
    reader: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="kale.server.app"):
        client = client_for(settings, registry, session_factory)
    assert "no server scope: active modules are disabled" in caplog.text
    with client:
        response = client.get("/api/v1/scope", headers=reader)
    assert response.json() == {"domains": [], "networks": [], "allow_private": False}


def test_uploads_are_never_served(client: TestClient, reader: dict[str, str]) -> None:
    assert client.get("/api/v1/uploads/abc", headers=reader).status_code == 404
    paths = [getattr(route, "path", "") for route in client.app.routes]  # type: ignore[attr-defined]
    assert not any("upload" in path for path in paths)


def test_security_headers(client: TestClient, reader: dict[str, str]) -> None:
    for response in (
        client.get("/api/v1/health"),
        client.get("/api/v1/jobs"),
        client.get("/api/v1/jobs", headers=reader),
        client.get("/api/openapi.json"),
    ):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "content-security-policy" not in response.headers
    docs = client.get("/api/docs")
    assert docs.status_code == 200
    csp = docs.headers["content-security-policy"]
    assert csp.startswith("default-src 'none'; script-src https://cdn.jsdelivr.net 'sha256-")
    assert "style-src https://cdn.jsdelivr.net 'unsafe-inline'" in csp
    assert "img-src https://fastapi.tiangolo.com data:" in csp
    assert "connect-src 'self'" in csp
    assert "/api/openapi.json" in docs.text


def test_openapi_documents_both_bodies(client: TestClient) -> None:
    spec = client.get("/api/openapi.json").json()
    body = spec["paths"]["/api/v1/jobs"]["post"]["requestBody"]["content"]
    assert set(body) == {"application/json", "multipart/form-data"}
    assert {"RunJobIn", "InvestigateJobIn", "JobIn"} <= set(spec["components"]["schemas"])
    assert "/docs" not in spec["paths"] and "/redoc" not in str(spec["paths"])


def test_unexpected_error_is_a_generic_500(
    api_settings: Settings,
    registry: Registry,
    session_factory: sessionmaker[Session],
    reader: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = client_for(api_settings, registry, session_factory, raise_server_exceptions=False)

    def broken() -> Iterator[Session]:
        raise RuntimeError("secret detail")
        yield  # pragma: no cover

    client.app.dependency_overrides[get_db] = broken  # type: ignore[attr-defined]
    with client, caplog.at_level(logging.ERROR, logger="kale.server.app"):
        response = client.get("/api/v1/jobs", headers=reader)
    assert response.status_code == 500
    request_id = response.headers["x-request-id"]
    assert response.json() == {"detail": f"internal error (request {request_id})"}
    assert "secret detail" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert request_id in caplog.text and "secret detail" in caplog.text


def test_request_id_is_sanitized(client: TestClient) -> None:
    kept = client.get("/api/v1/health", headers={"X-Request-ID": "abc-123.x_Y"})
    assert kept.headers["x-request-id"] == "abc-123.x_Y"
    for bad in ("bad id", "x" * 65, "a/b"):
        replaced = client.get("/api/v1/health", headers={"X-Request-ID": bad})
        assert re.fullmatch(r"[0-9a-f]{32}", replaced.headers["x-request-id"])
    assert re.fullmatch(r"[0-9a-f]{32}", client.get("/api/v1/health").headers["x-request-id"])


def test_create_app_fails_closed(
    tmp_path: Path, api_settings: Settings, registry: Registry, scope_file: Path
) -> None:
    fresh = tmp_path / "fresh.db"
    settings = api_settings.model_copy(update={"database_url": f"sqlite:///{fresh}"})
    with pytest.raises(SchemaOutdated, match="kale db upgrade"):
        create_app(settings, registry=registry)
    engine = make_engine(settings.database_url)
    try:
        upgrade_database(engine)
    finally:
        engine.dispose()
    scope_file.write_text("not a domain!\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid scope entry"):
        create_app(settings, registry=registry)


def test_create_app_builds_its_own_engine(
    api_settings: Settings, registry: Registry, engine: Any
) -> None:
    with TestClient(create_app(api_settings, registry=registry)) as client:
        assert client.get("/api/v1/health").status_code == 200
