from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Iterable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kale.server.errors import TooLarge
from kale.server.tables import Job, JobKind, JobStatus, Role, Upload
from kale.server.tokens import create_token
from kale.server.uploads import clean_orphans, delete_upload, display_name, store_upload

T = datetime(2026, 11, 5, 12, tzinfo=UTC)
MB = 1024 * 1024


async def chunked(data: bytes, size: int = 7) -> AsyncIterator[bytes]:
    for start in range(0, len(data), size):
        yield data[start : start + size]


async def pieces(parts: Iterable[bytes]) -> AsyncIterator[bytes]:
    for part in parts:
        yield part


async def test_stored_under_a_server_name(db: Session, tmp_path: Path) -> None:
    directory = tmp_path / "quarantine"
    data = b"Nov  5 12:00:00 host sshd[1]: Failed password\n"
    upload = await store_upload(
        db, chunked(data), original_name="auth.log", directory=directory, limit_bytes=MB, now=T
    )
    stored = Path(upload.stored_path)
    assert stored.parent == directory.resolve()
    assert len(stored.name) == 32 and int(stored.name, 16) >= 0
    assert stored.name != "auth.log"
    assert stored.read_bytes() == data
    assert upload.size == len(data)
    assert upload.sha256 == hashlib.sha256(data).hexdigest()
    assert (upload.original_name, upload.created_at, upload.deleted_at) == ("auth.log", T, None)
    assert db.scalar(select(func.count()).select_from(Upload)) == 1


async def test_limit_is_exact(db: Session, tmp_path: Path) -> None:
    at_limit = await store_upload(
        db, pieces([b"x" * MB]), original_name="a", directory=tmp_path / "ok", limit_bytes=MB, now=T
    )
    assert at_limit.size == MB

    directory = tmp_path / "over"
    with pytest.raises(TooLarge, match="over the 1 MB limit"):
        await store_upload(
            db,
            chunked(b"x" * (MB + 1)),
            original_name="b",
            directory=directory,
            limit_bytes=MB,
            now=T,
        )
    assert list(directory.iterdir()) == []


async def test_a_failing_stream_leaves_nothing(db: Session, tmp_path: Path) -> None:
    async def broken() -> AsyncIterator[bytes]:
        yield b"part"
        raise ConnectionResetError("client went away")

    with pytest.raises(ConnectionResetError):
        await store_upload(
            db, broken(), original_name="c", directory=tmp_path / "q", limit_bytes=MB, now=T
        )
    assert list((tmp_path / "q").iterdir()) == []


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\x\\evil.exe", "evil.exe"),
        ("a\x00b\x1b[31m.log", "ab[31m.log"),
        ("report\u202egpj.exe", "reportgpj.exe"),
        ("logs/..", "upload"),
        ("", "upload"),
        (None, "upload"),
        ("a" * 300, "a" * 255),
    ],
)
def test_display_name_is_sanitized(raw: str | None, expected: str) -> None:
    assert display_name(raw) == expected


async def test_delete_is_idempotent(db: Session, tmp_path: Path) -> None:
    upload = await store_upload(
        db, pieces([b"data"]), original_name="a", directory=tmp_path, limit_bytes=MB, now=T
    )
    delete_upload(db, upload, now=T)
    delete_upload(db, upload, now=T)
    assert not Path(upload.stored_path).exists()
    assert upload.deleted_at == T


async def test_a_file_that_cannot_be_deleted_stays_marked_undeleted(
    db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    upload = await store_upload(
        db, pieces([b"data"]), original_name="a", directory=tmp_path, limit_bytes=MB, now=T
    )

    def locked(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(13, "in use")

    monkeypatch.setattr(Path, "unlink", locked)
    delete_upload(db, upload, now=T)
    assert upload.deleted_at is None
    assert "cannot delete upload" in caplog.text


async def test_clean_orphans(db: Session, tmp_path: Path) -> None:
    directory = tmp_path / "uploads"
    token, _ = create_token(db, "ci", Role.RUNNER, now=T)

    async def job_with_upload(status: JobStatus) -> Upload:
        upload = await store_upload(
            db, pieces([b"data"]), original_name="a", directory=directory, limit_bytes=MB, now=T
        )
        db.add(
            Job(
                kind=JobKind.RUN,
                module="logs.auth",
                target={"kind": "file", "value": upload.stored_path},
                options={},
                scope={"entries": [], "allow_private": False},
                lang="en",
                status=status,
                created_by=token.id,
                created_at=T,
                upload_id=upload.id,
            )
        )
        db.commit()
        return upload

    queued = await job_with_upload(JobStatus.QUEUED)
    running = await job_with_upload(JobStatus.RUNNING)
    finished = await job_with_upload(JobStatus.SUCCEEDED)
    stray = directory / "stray"
    stray.write_bytes(b"left behind")

    assert clean_orphans(db, directory) == 2
    assert Path(queued.stored_path).exists() and Path(running.stored_path).exists()
    assert not Path(finished.stored_path).exists()
    assert not stray.exists()
    assert clean_orphans(db, tmp_path / "missing") == 0
