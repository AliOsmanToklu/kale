# kale API service: jobs, queue and worker

Status: approved design, 2026-11-05. Phase 3, sub-project 1 of 4.

## 1. Context and goal

kale runs every module from the command line (`kale run`, `kale investigate`). Phase 3 puts
the same capabilities behind interfaces. It is split into four sub-projects, each with its
own spec, plan and pull request:

1. **API service, job queue and worker** (this document)
2. HTML and PDF reports, for the CLI and the API
3. Web UI on top of the API's service layer
4. Docker image, Compose file with PostgreSQL, PostgreSQL tests in CI

**Goal of this sub-project:** a script or CI job can submit a module run or an
investigation over HTTP, upload a file when the module needs one, and read the result in
the existing JSON formats (`schemas/result.v1.json`, `schemas/investigation.v1.json`). An
active module can never touch a target outside the scope the server operator authorized.

### Decisions

| Question | Decision |
|---|---|
| Who uses the service | One team on its own server. One operator configures it; there is no sign-up, no organizations, no plans. |
| Who authorizes active scans | The server's scope. A request may only narrow it, never widen it. |
| File uploads | Accepted, with limits: quarantined, never executed, never downloadable, deleted when the job ends. |
| Where jobs run | A database table is the queue; separate `kale worker` processes claim jobs from it (Kalkan's pattern). No Redis. |

### Out of scope (YAGNI)

Per-token rate limits, webhooks, cancelling a running job, cursor pagination, a token
management API, HTML reports (sub-project 2), the web UI (3), Docker and PostgreSQL CI (4),
a rate limiter shared across worker processes.

## 2. Architecture

A new package `kale.server`, installed with a new `server` extra: FastAPI, uvicorn,
SQLAlchemy 2.0, Alembic, python-multipart, pydantic-settings. The CLI keeps working without
these packages.

| Unit | Responsibility | Depends on |
|---|---|---|
| `config.py` | `Settings` read from environment variables (section 6.1) | pydantic-settings |
| `tables.py` | SQLAlchemy models `Job`, `Upload`, `Token` | SQLAlchemy |
| `db.py` | engine and session factory; schema version check | SQLAlchemy, Alembic |
| `migrations/` | Alembic environment and revisions | Alembic |
| `jobs.py` | service layer, no HTTP: submit, claim, heartbeat, complete, fail, recover stale, cancel, get, list | `tables`, `kale.core` |
| `tokens.py` | create, verify, revoke and list tokens | `tables` |
| `uploads.py` | stream a request body into the quarantine directory under a size limit; delete; clean orphans | `config` |
| `worker.py` | claim loop, run with `run_module` / `investigate`, heartbeat task, job deadline, graceful stop; `run_once()` for tests | `jobs`, `uploads`, `kale.core` |
| `auth.py` | FastAPI dependency: bearer token -> `Token`, role check | `tokens` |
| `api.py` | thin routers: parse, call the service layer, map errors to HTTP | `jobs`, `auth`, `uploads` |
| `app.py` | `create_app(settings)`: routers, error handlers, request ids, headers, startup checks | everything above |

The service layer (`jobs.py`, `tokens.py`, `uploads.py`) knows nothing about HTTP, as in
Kalkan's `services.py` / `routes.py` split, so it can be tested directly and reused by the
web UI.

### Data flow

1. The client sends `POST /api/v1/jobs` (JSON, or multipart with a file).
2. The API authenticates the token, checks the role and validates the request completely
   (section 4.2). If a file is attached, it streams the file into quarantine. It then
   stores the job as `queued` and answers `202 Accepted` with the job id and a
   `Location` header.
3. A worker claims the job, intersects its scope with the current server scope, runs it,
   stores the result and deletes the uploaded file.
4. The client polls `GET /api/v1/jobs/{id}` until the status is final and reads the result.

### Core change

`Scope.narrow(entries, *, allow_private=False) -> Scope` on `kale.core.Scope`. Each
requested entry must be covered by the scope it is called on:

- A domain is covered when it equals a scope domain or is a subdomain of one. With
  `shop.example.com` in the server scope, `example.com` is rejected because it would widen
  the scope.
- A network is covered when it is a subnet of a scope network of the same IP version.

Every uncovered entry is listed in one `InvalidInputError`; nothing is silently dropped.
`allow_private` may only be requested when the server scope allows private addresses.

New CLI commands: `kale serve`, `kale worker`, `kale token create|list|revoke`,
`kale db upgrade`.

## 3. Data model and job lifecycle

### Tables

**`jobs`**

| Column | Type | Notes |
|---|---|---|
| `id` | string (UUID4) | primary key |
| `kind` | enum `run` / `investigate` | |
| `module` | string, nullable | set for `run` |
| `target` | JSON | an `Observable`; for uploads, the quarantine path |
| `options` | JSON | `run`: option -> value. `investigate`: `depth`, `modules`, `max_runs` and module -> option -> value |
| `scope` | JSON | the effective scope entries after narrowing, plus `allow_private` |
| `lang` | string | `en` / `tr` |
| `status` | enum | `queued`, `running`, `succeeded`, `failed`, `cancelled` |
| `created_by` | FK `tokens.id` | |
| `created_at`, `started_at`, `finished_at`, `heartbeat_at` | timestamps (UTC) | |
| `worker_id` | string, nullable | host name and process id |
| `attempts` | integer | increased on every claim |
| `result` | JSON, nullable | `ModuleResult` or `Investigation` |
| `error` | text, nullable | infrastructure failures only |
| `upload_id` | FK `uploads.id`, nullable | |

Indexes: `(status, created_at)` for claiming and listing.

**`uploads`**: `id` (UUID4), `stored_path` (server-generated, never derived from the
client's file name), `original_name` (display only: base name, control characters
removed, at most 255 characters), `size`, `sha256`, `created_at`, `deleted_at`.

**`tokens`**: `id`, `name` (unique), `role` (`reader` / `runner`), `digest` (SHA-256 hex,
unique), `prefix` (first 8 characters after `kale_`, for identification), `created_at`,
`last_used_at`, `revoked_at`.

### Statuses

`queued` -> `running` -> `succeeded` | `failed`; `queued` -> `cancelled`.

- `succeeded`: the job produced a result. A module's own error (invalid input, target out
  of scope) is part of that result, exactly as in the CLI.
- `failed`: an infrastructure problem: the worker died repeatedly, the job deadline passed,
  the uploaded file disappeared, or the result could not be stored.

### Claiming

The worker picks the oldest `queued` job and runs
`UPDATE jobs SET status='running', worker_id=:me, started_at=now, heartbeat_at=now,
attempts=attempts+1 WHERE id=:id AND status='queued'`. Only one worker's update can match,
so any number of workers share the queue on SQLite and PostgreSQL. If the update matches no
row, the worker tries the next job.

### Heartbeat and recovery

While a job runs, the worker refreshes `heartbeat_at` every 15 seconds from a separate
task. Before each claim, any worker runs `recover_stale`: a `running` job whose heartbeat is
older than 2 minutes goes back to `queued`, or to `failed` when it has already used 3
attempts. The cap stops a sample that kills the worker process from looping forever.
`attempts`, the heartbeat interval and the stale threshold are settings.

### Deadline

Every job runs under a deadline (`KALE_JOB_TIMEOUT`, default 3600 s), on top of the
modules' own timeouts. When it passes, the job is `failed` with the error
`timed out after 3600 s`.

### Cancel

Only `queued` jobs can be cancelled; the call returns `409` for any other status. Running
modules cannot be interrupted safely.

### Uploaded files

The worker deletes the job's file when the job reaches a final status, whatever that
status is, and sets `deleted_at`. At start-up it also deletes files in the quarantine
directory that no queued or running job refers to. Only the hash and the findings remain.

### Known limit

Rate limiters live inside each process. Two worker processes can together exceed a
service's limit (NVD without a key). The documentation recommends a single worker without
keys. A limiter shared through the database can come later.

## 4. API

Base path `/api/v1`. Authentication: `Authorization: Bearer kale_<token>`.

| Endpoint | Role | Behavior |
|---|---|---|
| `GET /health` | none | `{"status": "ok"}`, nothing else |
| `GET /modules` | reader | name, version, summary, category, accepted kinds, active, options (type, default, help, choices, minimum, maximum); for each optional secret only whether it is configured; unavailable modules listed separately with the reason |
| `GET /scope` | reader | the server scope: domains, networks, `allow_private` |
| `POST /jobs` | runner | submit a job; `202`, `Location: /api/v1/jobs/{id}`, body `{"id": ..., "status": "queued"}` |
| `GET /jobs` | reader | newest first; `status` filter; `limit` (default 50, at most 200); `before` (an ISO timestamp) for the next page |
| `GET /jobs/{id}` | reader | the whole job, with the result once it is final |
| `GET /jobs/{id}/report?format=text` | reader | the CLI text report as `text/plain`; `409` until the job has a result |
| `POST /jobs/{id}/cancel` | runner | `queued` -> `cancelled`; `409` otherwise |

OpenAPI: `/api/docs` (Swagger UI) and `/api/openapi.json`.

### 4.1 Job submission

JSON body, a discriminated union on `kind`:

```json
{"kind": "run", "module": "web.scan",
 "target": {"kind": "domain", "value": "shop.example.com"},
 "options": {"checks": "tls,http"}, "scope": ["shop.example.com"], "lang": "tr"}
```

```json
{"kind": "investigate", "target": {"kind": "domain", "value": "example.com"},
 "depth": 2, "modules": ["surface.discover", "web.scan"],
 "options": {"vuln.intel": {"max_findings": "3"}}, "max_runs": 50}
```

`scope`, `allow_private`, `lang`, `options` and `modules` are optional. Without `scope`, the
job uses the whole server scope.

With a file, the same endpoint takes `multipart/form-data`: the JSON above in a `job` part,
with `"target": {"kind": "file"}`, and the file in a `file` part. The file and the job are
created together or not at all, so no upload is ever left without a job.

### 4.2 Validation before queuing

A request that fails any of these checks never reaches the queue:

- the module exists and is available (`run`), and every name in `modules` exists (`investigate`)
- the target kind is accepted by the module (`run`), and a file target comes with a file
- options are known and valid: `resolve_options` for `run`, `check_options` for `investigate`
- the requested scope is covered by the server scope (`Scope.narrow`)
- `depth` is between 0 and 5, and `max_runs` is between 1 and `KALE_MAX_RUNS`

### 4.3 Errors

The body is always `{"detail": "..."}`.

| Code | When |
|---|---|
| 400 | a rule is broken: unknown or unavailable module, kind not accepted, unknown option, scope wider than the server's |
| 401 | missing, malformed, unknown or revoked token (`WWW-Authenticate: Bearer`) |
| 403 | the token's role is not enough |
| 404 | no such job |
| 409 | the job cannot be cancelled, or has no report yet |
| 413 | the upload or the JSON body is too large |
| 422 | the body does not match the schema |
| 500 | an unexpected error; the response carries only the request id |

## 5. Security

1. **Scope.** The server scope comes from `KALE_SCOPE_FILE` (the CLI's scope file format),
   and `KALE_ALLOW_PRIVATE` allows private addresses. Without a scope file, no active module
   runs through the API. The effective scope is computed with `Scope.narrow` when a job is
   submitted and stored on the job. When the job runs, the worker keeps only the stored
   entries that the current server scope still covers, and clears `allow_private` if the
   server no longer allows private addresses. Entries dropped this way are not an error;
   the job log lists them. A target the operator removed in the meantime is therefore not
   touched. The engine's and the pipeline's own scope checks still apply.
2. **Tokens.** A token is `kale_` followed by 32 random bytes (`secrets.token_urlsafe`). It is
   shown once, at creation, and stored as its SHA-256 digest: the token's entropy makes a slow
   hash unnecessary. Tokens are created only with `kale token create --name NAME --role ROLE`,
   that is, by someone with access to the database. The API has no endpoint that creates
   tokens and no admin role. A `runner` can do everything a `reader` can. Revocation takes
   effect on the next request. `last_used_at` is
   written at most once a minute.
3. **Uploads.** Each file is streamed into `KALE_UPLOAD_DIR` under a UUID name, with
   permissions 0700 on the directory. The client's file name is never used in a path. The size
   limit (`KALE_MAX_UPLOAD_MB`, default 64) is enforced on the bytes actually read, not on
   `Content-Length`. When the limit is exceeded, the partial file is deleted and the request
   gets `413`. Uploads are accepted only for modules that take a `file`. No endpoint ever
   returns a file's contents, so the server cannot become a place to download malware from.
   Files are never executed: `malware.static` already analyzes in an isolated child process
   with a deadline.
4. **Service keys.** VirusTotal, NVD, CertSpotter and the other keys exist only in the
   server's environment. Requests cannot carry keys, and no response contains them.
5. **Responses and transport.** Responses are JSON or `text/plain`. Text reports go through the
   existing control-character cleaning. Every response carries
   `X-Content-Type-Options: nosniff`. The Swagger page gets its own Content-Security-Policy.
   CORS is off. Tokens travel in a header, not a cookie, so CSRF does not apply. `kale serve`
   binds to `127.0.0.1` by default; the documentation describes putting a TLS reverse proxy
   in front before exposing it.
6. **Limits.** JSON bodies are limited to 1 MB, `max_runs` to `KALE_MAX_RUNS` (default 100),
   `depth` to 5, and each job to `KALE_JOB_TIMEOUT`.
7. **Audit log.** Each submission is logged with the token name, kind, module and target, and
   each job's completion with its status and duration. Token values and service keys are
   never logged.

## 6. Configuration, errors and testing

### 6.1 Settings

| Variable | Default | Meaning |
|---|---|---|
| `KALE_DATABASE_URL` | `sqlite:///<data dir>/kale.db` | SQLAlchemy URL; PostgreSQL via `postgresql+psycopg://` |
| `KALE_SCOPE_FILE` | unset | the server scope; unset means no active modules |
| `KALE_ALLOW_PRIVATE` | `false` | allow private addresses inside the scope |
| `KALE_UPLOAD_DIR` | `<data dir>/uploads` | quarantine directory |
| `KALE_MAX_UPLOAD_MB` | `64` | upload size limit |
| `KALE_MAX_RUNS` | `100` | upper bound for an investigation's `max_runs` |
| `KALE_JOB_TIMEOUT` | `3600` | seconds per job |
| `KALE_JOB_ATTEMPTS` | `3` | claims before a job counts as poison |
| `KALE_HEARTBEAT_SECONDS` | `15` | heartbeat interval |
| `KALE_STALE_SECONDS` | `120` | heartbeat age after which a running job is recovered |
| `KALE_WORKER_POLL_SECONDS` | `1` | how often an idle worker checks the queue |

`<data dir>` is `%LOCALAPPDATA%\kale` on Windows and `$XDG_DATA_HOME/kale` (or
`~/.local/share/kale`) elsewhere.

### 6.2 Error handling

- **API.** Service-layer errors are one exception hierarchy, mapped to HTTP codes by a
  single handler. An unexpected exception is logged with the request id (`X-Request-ID`,
  generated when the client sends none), and the client gets a generic `500`.
- **Worker.** Module failures are already inside results, because the engine never raises.
  An infrastructure error fails the job, and the loop goes on to the next one. Database
  connection errors are retried with exponential backoff (1 s up to 30 s). `SIGTERM` and
  `SIGINT` stop the claiming of new jobs and let the current one finish. A killed worker's
  job is recovered through the heartbeat.
- **Start-up, fail closed.** `kale serve` and `kale worker` refuse to start when
  `KALE_SCOPE_FILE` is set but unreadable or invalid, or when the database schema is not the
  latest revision. In that case they say to run `kale db upgrade`. They do start without a
  scope file, logging a warning that active modules are disabled.

### 6.3 Testing

No test touches the network. Modules are the fakes from `tests/fakes.py` and
`tests/test_pipeline.py`, and the database is a SQLite file in `tmp_path`.

| Layer | What is tested |
|---|---|
| `Scope.narrow` | subdomains and subnets are accepted; wider entries, mixed IP versions and private addresses without permission are rejected, each listed |
| `jobs.py` | submission validation; two claims of one job, where only one wins; heartbeat recovery and the attempts cap under a fake clock; cancel rules; listing and `before` paging |
| `worker.py` | `run_once()`: success, a module error inside a succeeded result, the deadline with a slow fake, a scope intersected with a changed server scope, the upload deleted on success and on failure, orphan cleanup, graceful stop |
| `tokens.py` / `auth.py` | only the digest is stored; missing, malformed, unknown and revoked tokens give 401; a reader submitting a job gets 403; `last_used_at` throttling |
| `api.py` | every endpoint and status code through FastAPI's `TestClient`; the size limit enforced while streaming (`413`); a hostile file name kept only for display; no route serves upload contents; Swagger CSP; `nosniff` |
| End to end | submit through the API, process with `run_once()`, read the result back, and check that it equals what `run_module` or `investigate` returns directly |
| Migrations | the Alembic head matches the models (an autogenerate comparison that must find no difference) |

The quality gate does not change: `ruff format --check`, `ruff check`, strict `mypy` (with
SQLAlchemy 2.0 `Mapped` types), `pytest --cov --cov-fail-under=90`, and `ResourceWarning`
treated as an error, so engines and connections must be closed. Tests on PostgreSQL arrive
with sub-project 4.

## 7. Documentation

README.md and README.tr.md get a "Running the service" section covering:

- installation with the `server` extra, `kale db upgrade`, `kale token create`, `kale serve`
  and `kale worker`
- the settings table, the scope rule and the upload rules
- one `curl` example each for a domain job, a file job and reading a result
- the single-worker advice for keyless use
