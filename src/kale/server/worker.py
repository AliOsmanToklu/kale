"""``kale worker``: claim queued jobs and run them, one at a time.

Any number of workers can share the queue. A job runs under the job deadline, with a
heartbeat that lets other workers recover it if this process dies. Its scope is
intersected with the server scope as it is now, so a target the operator removed after
the job was queued is not touched. Its uploaded file is deleted whatever the outcome.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import socket
import time
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from kale.core import Investigation, ModuleResult, Observable, Registry, Scope, investigate
from kale.core.engine import run_module
from kale.server.config import ConfigError, Settings, load_scope
from kale.server.db import utcnow
from kale.server.jobs import (
    audit,
    claim_next,
    complete_job,
    fail_job,
    heartbeat,
    recover_stale,
)
from kale.server.tables import Job, JobKind, JobStatus
from kale.server.uploads import clean_orphans, delete_upload

log = logging.getLogger(__name__)

# Waits after a database error: 1, 2, 4 ... seconds, at most this long.
MAX_BACKOFF = 30.0


class _JobFailed(Exception):
    """An infrastructure problem that fails the job with this message."""


class Worker:
    def __init__(
        self,
        settings: Settings,
        registry: Registry,
        session_factory: sessionmaker[Session],
        *,
        worker_id: str | None = None,
        clock: Callable[[], datetime] = utcnow,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.session_factory = session_factory
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}"
        self.clock = clock
        self.environ = environ

    async def run_once(self) -> bool:
        """Recover stale jobs, then claim and process one job; ``False`` when idle."""
        with self.session_factory() as db:
            recover_stale(
                db,
                now=self.clock(),
                stale_seconds=self.settings.stale_seconds,
                max_attempts=self.settings.job_attempts,
            )
            job = claim_next(db, worker_id=self.worker_id, now=self.clock())
            if job is None:
                return False
            await self._process(db, job)
            return True

    async def run_forever(self, stop: asyncio.Event) -> None:
        """Process jobs until ``stop`` is set; the job in progress is always finished."""
        with self.session_factory() as db:
            removed = clean_orphans(db, self.settings.upload_dir)
        if removed:
            log.info("deleted %d orphaned upload(s)", removed)
        backoff = 1.0
        while not stop.is_set():
            try:
                busy = await self.run_once()
            except OperationalError as exc:
                log.warning("database error, retrying in %g s: %s", backoff, exc)
                await self._wait(backoff, stop)
                backoff = min(backoff * 2, MAX_BACKOFF)
                continue
            backoff = 1.0
            if not busy:
                await self._wait(self.settings.worker_poll_seconds, stop)

    async def _wait(self, seconds: float, stop: asyncio.Event) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), seconds)

    async def _process(self, db: Session, job: Job) -> None:
        started = time.monotonic()
        status = JobStatus.FAILED
        try:
            result = await self._run(job)
            complete_job(db, job.id, result.model_dump(mode="json"), now=self.clock())
            status = JobStatus.SUCCEEDED
        except _JobFailed as exc:
            self._fail(db, job, str(exc))
        except TimeoutError:
            self._fail(db, job, f"timed out after {self.settings.job_timeout:g} s")
        except Exception as exc:
            log.exception("job %s failed", job.id)
            self._fail(db, job, f"{type(exc).__name__}: {exc}")
        finally:
            if job.upload is not None:
                delete_upload(db, job.upload, now=self.clock())
            audit.info(
                "job finished id=%s status=%s duration=%.1fs",
                job.id,
                status,
                time.monotonic() - started,
            )

    def _fail(self, db: Session, job: Job, error: str) -> None:
        db.rollback()
        fail_job(db, job.id, error, now=self.clock())

    async def _run(self, job: Job) -> ModuleResult | Investigation:
        try:
            server = await asyncio.to_thread(load_scope, self.settings)
        except ConfigError as exc:
            raise _JobFailed(f"server scope unavailable: {exc}") from None
        scope = self._scope(job, server)
        target = Observable.model_validate(job.target)
        if job.upload is not None:
            present = await asyncio.to_thread(Path(job.upload.stored_path).is_file)
            if not present:
                raise _JobFailed("the uploaded file disappeared")
        beating = asyncio.create_task(self._heartbeat(job.id))
        try:
            async with asyncio.timeout(self.settings.job_timeout):
                return await self._execute(job, target, scope)
        finally:
            beating.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await beating

    def _scope(self, job: Job, server: Scope | None) -> Scope | None:
        """The stored scope, keeping only what the current server scope still covers."""
        entries: list[str] = job.scope["entries"]
        kept = [entry for entry in entries if server is not None and server.covers(entry)]
        for entry in entries:
            if entry not in kept:
                log.warning("job %s: dropped from scope: %s", job.id, entry)
        if server is None or not kept:
            return None
        allow_private = bool(job.scope["allow_private"]) and server.allow_private
        return Scope.parse(kept, allow_private=allow_private)

    async def _execute(
        self, job: Job, target: Observable, scope: Scope | None
    ) -> ModuleResult | Investigation:
        if job.kind is JobKind.RUN:
            module = self.registry.get(job.module or "")
            return await run_module(
                module,
                target,
                options=job.options,
                scope=scope,
                lang=job.lang,
                environ=self.environ,
            )
        options = job.options
        return await investigate(
            self.registry,
            target,
            depth=options["depth"],
            scope=scope,
            modules=options["modules"],
            options=options["options"],
            max_runs=options["max_runs"],
            lang=job.lang,
            environ=self.environ,
        )

    async def _heartbeat(self, job_id: str) -> None:
        while True:
            await asyncio.sleep(self.settings.heartbeat_seconds)
            await asyncio.to_thread(self._beat, job_id)

    def _beat(self, job_id: str) -> None:
        with self.session_factory() as db:
            heartbeat(db, job_id, now=self.clock())


def install_signal_handlers(stop: asyncio.Event) -> None:
    """Let SIGINT and SIGTERM stop the claiming of new jobs instead of killing the job."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows: no signal handlers on the event loop
            signal.signal(sig, lambda _sig, _frame: loop.call_soon_threadsafe(stop.set))
