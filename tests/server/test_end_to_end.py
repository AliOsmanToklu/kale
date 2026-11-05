"""Submit through the API, process with the worker, read the result back over HTTP."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from kale.core import Investigation, Kind, Observable, Registry, Scope, investigate, run_module
from kale.server.app import create_app
from kale.server.config import Settings
from kale.server.db import utcnow
from kale.server.tables import Role, Upload
from kale.server.tokens import create_token
from kale.server.worker import Worker
from tests.fakes import EchoModule

Service = tuple[TestClient, Worker, dict[str, str]]


@pytest.fixture
def scoped(settings: Settings, tmp_path: Path) -> Settings:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n", encoding="utf-8")
    return settings.model_copy(update={"scope_file": scope_file})


def service(
    settings: Settings, registry: Registry, session_factory: sessionmaker[Session], db: Session
) -> Iterator[Service]:
    app = create_app(settings, registry=registry, session_factory=session_factory, environ={})
    worker = Worker(settings, registry, session_factory, environ={})
    _, raw = create_token(db, "ci", Role.RUNNER, now=utcnow())
    with TestClient(app) as client:
        yield client, worker, {"Authorization": f"Bearer {raw}"}


@pytest.fixture
def scoped_service(
    scoped: Settings, registry: Registry, session_factory: sessionmaker[Session], db: Session
) -> Iterator[Service]:
    yield from service(scoped, registry, session_factory, db)


@pytest.fixture
def unscoped_service(
    settings: Settings, registry: Registry, session_factory: sessionmaker[Session], db: Session
) -> Iterator[Service]:
    yield from service(settings, registry, session_factory, db)


async def submit_and_run(svc: Service, **request: Any) -> dict[str, Any]:
    client, worker, auth = svc
    response = client.post("/api/v1/jobs", headers=auth, **request)
    assert response.status_code == 202, response.text
    assert await worker.run_once()
    job: dict[str, Any] = client.get(response.headers["location"], headers=auth).json()
    return job


async def test_domain_job_round_trip(scoped_service: Service) -> None:
    job = await submit_and_run(
        scoped_service,
        json={
            "kind": "run",
            "module": "fake.echo",
            "target": {"kind": "domain", "value": "example.com"},
            "options": {"count": "3", "severity": "medium"},
        },
    )
    assert job["status"] == "succeeded"
    direct = await run_module(
        EchoModule(),
        Observable(kind=Kind.DOMAIN, value="example.com"),
        options={"count": "3", "severity": "medium"},
    )
    assert job["result"]["findings"] == direct.model_dump(mode="json")["findings"]
    client, _, auth = scoped_service
    report = client.get(f"/api/v1/jobs/{job['id']}/report", headers=auth)
    assert report.text.startswith("fake.echo")


async def test_investigation_round_trip(scoped_service: Service, registry: Registry) -> None:
    job = await submit_and_run(
        scoped_service,
        json={
            "kind": "investigate",
            "target": {"kind": "domain", "value": "example.com"},
            "depth": 2,
            "modules": ["fake.discover", "fake.reputation"],
        },
    )
    assert job["status"] == "succeeded"
    result = Investigation.model_validate(job["result"])
    direct = await investigate(
        registry,
        Observable(kind=Kind.DOMAIN, value="example.com"),
        depth=2,
        modules=["fake.discover", "fake.reputation"],
        scope=Scope.parse(["example.com"]),
    )

    def runs(investigation: Investigation) -> list[tuple[str, str, list[str]]]:
        return [
            (run.module, str(run.target), [f.rule_id for f in run.findings])
            for run in investigation.runs
        ]

    assert runs(result) == runs(direct)
    assert len(result.runs) > 1


async def test_log_file_round_trip(
    scoped_service: Service, scoped: Settings, ssh_log: Path, db: Session
) -> None:
    job = await submit_and_run(
        scoped_service,
        data={
            "job": json.dumps({"kind": "run", "module": "logs.auth", "target": {"kind": "file"}})
        },
        files={"file": ("auth.log", ssh_log.read_bytes(), "text/plain")},
    )
    assert job["status"] == "succeeded"
    assert "logs.auth.brute_force" in {f["rule_id"] for f in job["result"]["findings"]}
    db.expire_all()
    upload = db.query(Upload).one()
    assert upload.deleted_at is not None
    assert list(scoped.upload_dir.iterdir()) == []


async def test_active_module_needs_the_server_scope(unscoped_service: Service) -> None:
    job = await submit_and_run(
        unscoped_service,
        json={
            "kind": "run",
            "module": "fake.active",
            "target": {"kind": "domain", "value": "example.com"},
        },
    )
    assert job["status"] == "succeeded"
    assert job["result"]["error"]["code"] == "out_of_scope"
