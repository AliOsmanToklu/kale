from __future__ import annotations

import threading
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from kale.server.jobs import (
    claim_next,
    complete_job,
    fail_job,
    get_job,
    heartbeat,
    recover_stale,
)
from kale.server.tables import Job, JobKind, JobStatus, Role, Token, Upload
from kale.server.tokens import create_token
from kale.server.uploads import store_upload

T = datetime(2026, 11, 5, 12, tzinfo=UTC)


def queue(db: Session, *offsets: float, upload: Upload | None = None) -> list[str]:
    token = db.query(Token).one_or_none() or create_token(db, "ci", Role.RUNNER, now=T)[0]
    jobs = [
        Job(
            kind=JobKind.RUN,
            module="fake.echo",
            target={"kind": "domain", "value": "example.com", "source": ""},
            options={},
            scope={"entries": [], "allow_private": False},
            lang="en",
            created_by=token.id,
            created_at=T + timedelta(seconds=offset),
            upload_id=upload.id if upload else None,
        )
        for offset in offsets
    ]
    db.add_all(jobs)
    db.commit()
    return [job.id for job in jobs]


def test_claims_the_oldest(db: Session) -> None:
    newer, older = queue(db, 5, 1)
    now = T + timedelta(minutes=1)
    job = claim_next(db, worker_id="host:1", now=now)
    assert job is not None
    assert job.id == older
    assert job.status is JobStatus.RUNNING
    assert job.attempts == 1
    assert job.worker_id == "host:1"
    assert job.started_at == job.heartbeat_at == now
    assert get_job(db, newer).status is JobStatus.QUEUED


def test_two_sessions_never_claim_the_same_job(session_factory: sessionmaker[Session]) -> None:
    with session_factory() as setup:
        ids = queue(setup, 1, 2)
    with session_factory() as first, session_factory() as second:
        a = claim_next(first, worker_id="a", now=T)
        b = claim_next(second, worker_id="b", now=T)
        assert a is not None and b is not None
        assert {a.id, b.id} == set(ids)
        assert claim_next(first, worker_id="a", now=T) is None
        assert claim_next(second, worker_id="b", now=T) is None


def test_conditional_update_has_one_winner(session_factory: sessionmaker[Session]) -> None:
    """Both sessions saw the job as queued; only one update may match it."""
    with session_factory() as setup:
        [job_id] = queue(setup, 1)
    with session_factory() as first, session_factory() as second:
        stale = second.get(Job, job_id)  # loaded while still queued
        assert stale is not None and stale.status is JobStatus.QUEUED
        assert claim_next(first, worker_id="a", now=T) is not None
        from kale.server.jobs import _claim

        assert not _claim(second, job_id, worker_id="b", now=T)
        assert claim_next(second, worker_id="b", now=T) is None
        winner = second.get(Job, job_id, populate_existing=True)
        assert winner is not None and winner.worker_id == "a" and winner.attempts == 1


def test_many_workers_share_one_sqlite_queue(session_factory: sessionmaker[Session]) -> None:
    """Each job is claimed exactly once, and no worker fails on a locked database."""
    with session_factory() as setup:
        ids = queue(setup, *range(40))
    start = threading.Barrier(6)

    def work(worker: int) -> list[str]:
        claimed: list[str] = []
        with session_factory() as db:
            start.wait()
            while job := claim_next(db, worker_id=f"w{worker}", now=T):
                claimed.append(job.id)
        return claimed

    with ThreadPoolExecutor(6) as pool:
        results = list(pool.map(work, range(6)))
    claimed = [job_id for result in results for job_id in result]
    assert sorted(claimed) == sorted(ids)


def test_cancelled_jobs_are_never_claimed(db: Session) -> None:
    [job_id] = queue(db, 1)
    get_job(db, job_id).status = JobStatus.CANCELLED
    db.commit()
    assert claim_next(db, worker_id="a", now=T) is None


def test_heartbeat(db: Session) -> None:
    queue(db, 1)
    job = claim_next(db, worker_id="a", now=T)
    assert job is not None
    heartbeat(db, job.id, now=T + timedelta(seconds=15))
    db.expire_all()
    assert get_job(db, job.id).heartbeat_at == T + timedelta(seconds=15)


async def one_chunk() -> AsyncIterator[bytes]:
    yield b"data"


async def test_recover_stale(db: Session, tmp_path: Path) -> None:
    upload = await store_upload(
        db, one_chunk(), original_name="x", directory=tmp_path / "u", limit_bytes=10, now=T
    )
    stale_id, poison_id, fresh_id = queue(db, 1, 2, 3)
    [poison_upload_job] = queue(db, 4, upload=upload)
    now = T + timedelta(hours=1)
    for job_id, attempts, beat in [
        (stale_id, 1, now - timedelta(seconds=121)),
        (poison_id, 3, now - timedelta(seconds=121)),
        (fresh_id, 1, now - timedelta(seconds=10)),
        (poison_upload_job, 3, now - timedelta(seconds=500)),
    ]:
        job = get_job(db, job_id)
        job.status, job.attempts, job.heartbeat_at, job.worker_id = (
            JobStatus.RUNNING,
            attempts,
            beat,
            "dead:1",
        )
    db.commit()

    assert recover_stale(db, now=now, stale_seconds=120, max_attempts=3) == 3
    db.expire_all()
    stale = get_job(db, stale_id)
    assert (stale.status, stale.attempts, stale.worker_id) == (JobStatus.QUEUED, 1, None)
    poison = get_job(db, poison_id)
    assert poison.status is JobStatus.FAILED
    assert poison.error == "worker stopped 3 times while running this job"
    assert poison.finished_at == now
    assert get_job(db, fresh_id).status is JobStatus.RUNNING
    assert get_job(db, poison_upload_job).status is JobStatus.FAILED
    assert not Path(upload.stored_path).exists()
    assert recover_stale(db, now=now, stale_seconds=120, max_attempts=3) == 0


def test_complete_and_fail(db: Session) -> None:
    queue(db, 1, 2)
    first = claim_next(db, worker_id="a", now=T)
    second = claim_next(db, worker_id="a", now=T)
    assert first is not None and second is not None
    done = T + timedelta(seconds=9)
    complete_job(db, first.id, {"module": "fake.echo", "findings": []}, now=done)
    fail_job(db, second.id, "timed out after 0.2 s", now=done)
    db.expire_all()
    succeeded = get_job(db, first.id)
    assert (succeeded.status, succeeded.finished_at, succeeded.error) == (
        JobStatus.SUCCEEDED,
        done,
        None,
    )
    assert succeeded.result == {"module": "fake.echo", "findings": []}
    failed = get_job(db, second.id)
    assert (failed.status, failed.finished_at, failed.result) == (JobStatus.FAILED, done, None)
    assert failed.error == "timed out after 0.2 s"
