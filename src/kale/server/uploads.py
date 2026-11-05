"""The upload quarantine: files a job needs, kept only while the job is waiting or running.

A file is stored under a name the server generates; the client's file name is only ever
displayed. The size limit counts the bytes actually received, whatever the request
headers claim. No endpoint serves a stored file and nothing here executes one.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import unicodedata
import uuid
from collections.abc import AsyncIterable
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from kale.server.errors import TooLarge
from kale.server.tables import Job, JobStatus, Upload

log = logging.getLogger(__name__)

MAX_NAME = 255
# Bytes collected before a write, so the event loop hands the disk large pieces.
WRITE_SIZE = 1024 * 1024


def display_name(raw: str | None) -> str:
    """A client's file name made safe to show: base name only, no control characters."""
    name = (raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch) not in ("Cc", "Cf"))
    name = name.strip()[:MAX_NAME]
    return name if name not in ("", ".", "..") else "upload"


async def store_upload(
    db: Session,
    chunks: AsyncIterable[bytes],
    *,
    original_name: str | None,
    directory: Path,
    limit_bytes: int,
    now: datetime,
) -> Upload:
    """Stream ``chunks`` into the quarantine and add the ``Upload`` row (not committed).

    Over ``limit_bytes`` the partial file is deleted and ``TooLarge`` is raised; any
    other failure deletes it too before the exception propagates.
    """
    directory = await asyncio.to_thread(directory.resolve)
    await asyncio.to_thread(directory.mkdir, mode=0o700, parents=True, exist_ok=True)
    path = directory / uuid.uuid4().hex
    digest = hashlib.sha256()
    size = 0
    buffer = bytearray()
    try:
        handle = await asyncio.to_thread(path.open, "xb")  # never overwrites a file
        try:
            async for chunk in chunks:
                size += len(chunk)
                if size > limit_bytes:
                    raise TooLarge(f"the file is over the {limit_bytes / 2**20:g} MB limit")
                digest.update(chunk)
                buffer += chunk
                if len(buffer) >= WRITE_SIZE:
                    await asyncio.to_thread(handle.write, bytes(buffer))
                    buffer.clear()
            await asyncio.to_thread(handle.write, bytes(buffer))
        finally:
            handle.close()
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    upload = Upload(
        stored_path=str(path),
        original_name=display_name(original_name),
        size=size,
        sha256=digest.hexdigest(),
        created_at=now,
    )
    db.add(upload)
    db.flush()
    return upload


def delete_upload(db: Session, upload: Upload, *, now: datetime) -> None:
    """Delete the stored file and mark the row; doing it twice is harmless.

    A file that cannot be deleted (still open elsewhere, say) is logged and left
    for ``clean_orphans`` at the next worker start.
    """
    try:
        Path(upload.stored_path).unlink(missing_ok=True)
    except OSError as exc:
        log.warning("cannot delete upload %s: %s", upload.id, exc)
        return
    if upload.deleted_at is None:
        upload.deleted_at = now
        db.commit()


def clean_orphans(db: Session, directory: Path) -> int:
    """Delete files no waiting or running job needs; return how many were deleted."""
    if not directory.is_dir():
        return 0
    needed = set(
        db.scalars(
            select(Upload.stored_path)
            .join(Job, Job.upload_id == Upload.id)
            .where(
                Upload.deleted_at.is_(None),
                Job.status.in_((JobStatus.QUEUED, JobStatus.RUNNING)),
            )
        )
    )
    deleted = 0
    for path in directory.resolve().iterdir():
        if path.is_file() and str(path) not in needed:
            try:
                path.unlink()
            except OSError as exc:
                log.warning("cannot delete orphaned upload %s: %s", path.name, exc)
                continue
            deleted += 1
    return deleted
