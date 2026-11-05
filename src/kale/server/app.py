"""``create_app``: the API with its error handling, request ids, headers and start-up checks."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, MutableMapping
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import TypeAdapter
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from starlette.datastructures import Headers, MutableHeaders

from kale import __version__
from kale.core import Registry
from kale.server.api import Service, router
from kale.server.config import Settings, load_scope
from kale.server.db import make_engine, make_session_factory
from kale.server.errors import BadRequest, Conflict, NotFound, ServiceError, TooLarge
from kale.server.migrate import ensure_current
from kale.server.schemas import JobIn

log = logging.getLogger(__name__)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

DOCS_URL = "/api/docs"
OPENAPI_URL = "/api/openapi.json"
JSON_LIMIT = 1024 * 1024
REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")
REQUEST_ID_KEY = "kale.request_id"
STATUS = {BadRequest: 400, NotFound: 404, Conflict: 409, TooLarge: 413}


class _BodyTooLarge(Exception):
    pass


class BodyLimit:
    """Refuse bodies over the limit, counting the bytes received, not ``Content-Length``."""

    def __init__(self, app: ASGIApp, *, json_limit: int, multipart_limit: int) -> None:
        self.app = app
        self.json_limit = json_limit
        self.multipart_limit = multipart_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        multipart = headers.get("content-type", "").lower().startswith("multipart/form-data")
        limit = self.multipart_limit if multipart else self.json_limit
        declared = headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            await _too_large(send)
            return
        received = 0
        started = False

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _BodyTooLarge:
            if started:  # pragma: no cover - routes read the whole body before answering
                raise
            await _too_large(send)


async def _too_large(send: Send) -> None:
    response = JSONResponse({"detail": "request body too large"}, status_code=413)
    await send({"type": "http.response.start", "status": 413, "headers": response.raw_headers})
    await send({"type": "http.response.body", "body": response.body})


class SecurityHeaders:
    """Request ids, ``nosniff`` everywhere, and a CSP for the Swagger page."""

    def __init__(self, app: ASGIApp, *, docs_csp: str) -> None:
        self.app = app
        self.docs_csp = docs_csp

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = Headers(scope=scope).get("x-request-id", "")
        request_id = incoming if REQUEST_ID.fullmatch(incoming) else uuid.uuid4().hex
        scope[REQUEST_ID_KEY] = request_id

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                headers["X-Content-Type-Options"] = "nosniff"
                if scope["path"] == DOCS_URL:
                    headers["Content-Security-Policy"] = self.docs_csp
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _docs_page() -> tuple[HTMLResponse, str]:
    """The Swagger page and a CSP that allows exactly its inline bootstrap script."""
    page = get_swagger_ui_html(openapi_url=OPENAPI_URL, title="kale API")
    body = bytes(page.body).decode()
    hashes = " ".join(
        "'sha256-" + base64.b64encode(hashlib.sha256(script.encode()).digest()).decode() + "'"
        for script in re.findall(r"<script>(.*?)</script>", body, flags=re.DOTALL)
    )
    csp = (
        f"default-src 'none'; script-src https://cdn.jsdelivr.net {hashes}; "
        "style-src https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src https://fastapi.tiangolo.com data:; connect-src 'self'"
    )
    return page, csp


def _detail(exc: RequestValidationError) -> str:
    errors = exc.errors()
    if not errors:  # pragma: no cover - pydantic always reports at least one error
        return "invalid request"
    first = errors[0]
    loc = [str(part) for part in first.get("loc", ()) if part not in ("body", "query", "path")]
    if loc and loc[0] in ("run", "investigate"):  # the union tag pydantic puts first
        loc = loc[1:]
    return f"{'.'.join(loc)}: {first['msg']}" if loc else str(first["msg"])


def _install_openapi(app: FastAPI) -> None:
    """Document both bodies of ``POST /jobs``, which the route reads itself."""

    def openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title, version=app.version, description=app.description, routes=app.routes
        )
        job = TypeAdapter(JobIn).json_schema(ref_template="#/components/schemas/{model}")
        components = schema.setdefault("components", {}).setdefault("schemas", {})
        components.update(job.pop("$defs", {}))
        components["JobIn"] = job
        schema["paths"]["/api/v1/jobs"]["post"]["requestBody"] = {
            "required": True,
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/JobIn"}},
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["job", "file"],
                        "properties": {
                            "job": {"type": "string", "description": "the job as JSON"},
                            "file": {"type": "string", "format": "binary"},
                        },
                    }
                },
            },
        }
        app.openapi_schema = schema
        return schema

    app.openapi = openapi  # type: ignore[method-assign]


def create_app(
    settings: Settings,
    *,
    registry: Registry | None = None,
    session_factory: sessionmaker[Session] | None = None,
    environ: Mapping[str, str] | None = None,
) -> FastAPI:
    """Build the API. Refuses an outdated database and a broken scope file (fail closed)."""
    owned: Engine | None = None
    if session_factory is None:
        owned = make_engine(settings.database_url)
        session_factory = make_session_factory(owned)
    engine: Engine = session_factory.kw["bind"]
    try:
        ensure_current(engine)
        scope = load_scope(settings)
    except BaseException:
        if owned is not None:
            owned.dispose()
        raise
    if scope is None:
        log.warning("no server scope: active modules are disabled")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if owned is not None:
            owned.dispose()

    app = FastAPI(
        title="kale API",
        version=__version__,
        description="Queue kale module runs and investigations, and read their results.",
        docs_url=None,
        redoc_url=None,
        openapi_url=OPENAPI_URL,
        lifespan=lifespan,
    )
    app.state.session_factory = session_factory
    app.state.service = Service(
        settings=settings,
        registry=registry if registry is not None else Registry.discover(),
        scope=scope,
        environ=os.environ if environ is None else environ,
    )
    app.include_router(router)
    docs, docs_csp = _docs_page()

    @app.get(DOCS_URL, include_in_schema=False)
    def swagger() -> HTMLResponse:
        return docs

    @app.exception_handler(ServiceError)
    async def service_error(request: Request, exc: ServiceError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=STATUS.get(type(exc), 400))

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": _detail(exc)}, status_code=422)

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception) -> JSONResponse:
        request_id = request.scope.get(REQUEST_ID_KEY) or uuid.uuid4().hex
        log.error("unexpected error (request %s)", request_id, exc_info=exc)
        return JSONResponse(
            {"detail": f"internal error (request {request_id})"},
            status_code=500,
            headers={"X-Request-ID": request_id, "X-Content-Type-Options": "nosniff"},
        )

    _install_openapi(app)
    multipart_limit = (settings.max_upload_mb + 1) * 1024 * 1024
    app.add_middleware(BodyLimit, json_limit=JSON_LIMIT, multipart_limit=multipart_limit)
    app.add_middleware(SecurityHeaders, docs_csp=docs_csp)
    return app
