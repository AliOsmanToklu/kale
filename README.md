# kale

**[English](README.md) · [Türkçe](README.tr.md)**

One command line and one result format for many security tools.

kale is a modular security toolkit. Each tool plugs in as a **module** that takes an
**observable** (a file, domain, URL, IP, hash, ...) and returns **findings** plus new
observables. Every module's output follows the same schema, so results can be compared,
stored, chained into other modules and served by an API or GUI later.

Existing tools join through thin adapters and stay independent projects:

| Module | Wraps | Accepts | Mode |
|---|---|---|---|
| `logs.auth` | [log-analyzer](https://github.com/AliOsmanToklu/log-analyzer): brute force, account compromise and username scanning in SSH / Windows logon logs | file | passive |
| `malware.static` | [malware-static-analyzer](https://github.com/AliOsmanToklu/malware-static-analyzer): PE imports and sections, suspicious strings, hashes and a heuristic risk score, analyzed in an isolated process | file | passive |
| `web.scan` | [Kalkan](https://github.com/AliOsmanToklu/KALKAN): TLS, headers, exposed files, ports, outdated software, SPF/DMARC/DKIM, DNS | domain, URL, IP | active |

Native modules are part of kale itself:

| Module | What it does | Accepts | Mode |
|---|---|---|---|
| `intel.enrich` | Reputation from GreyNoise, AbuseIPDB, URLhaus, MalwareBazaar and VirusTotal | IP, domain, URL, hash | passive |
| `vuln.intel` | Known vulnerabilities from NVD and OSV, ranked with CISA KEV and EPSS | software, CVE | passive |
| `surface.discover` | Subdomains from Certificate Transparency logs, dangling CNAMEs, subdomain takeovers | domain | passive |

## Installation

Requires Python 3.12+. The wrapped tools are installed from their own repositories,
next to this one:

```bash
git clone https://github.com/AliOsmanToklu/kale.git
git clone https://github.com/AliOsmanToklu/log-analyzer.git
git clone https://github.com/AliOsmanToklu/KALKAN.git kalkan
git clone https://github.com/AliOsmanToklu/malware-static-analyzer.git
cd kale
uv venv .venv
uv pip install -e ../log-analyzer -e ../kalkan -e ../malware-static-analyzer -e ".[dev]"
```

A module whose tool is not installed shows up as unavailable in `kale modules`; the rest
keep working. The tools are deliberately not declared as package dependencies: they are not
on PyPI, and an unpinned name there could resolve to someone else's package.

## Usage

```bash
kale modules                                  # list modules
kale modules logs.auth                        # accepted input, options, defaults
kale run logs.auth /var/log/auth.log          # text report
kale run logs.auth logons.csv -f json -o report.json
kale run logs.auth auth.log --set threshold=5 --set window=120
kale run web.scan example.com --scope example.com --lang tr
kale run logs.auth auth.log --fail-on high    # exit 1 if a high or critical finding (CI)
kale schema                                   # JSON schema of the result format
kale schema --investigation                   # ... and of investigations
```

The target's kind is guessed from its form (an existing path is a file, `https://...` a URL,
and so on); `--kind` overrides the guess.

Exit codes: `0` done, `1` a finding reached `--fail-on`, `2` usage error, `3` the module
could not run (the report says why).

### Investigations

`kale investigate` runs every module that accepts the target, then every module that
accepts what those found, and so on for `--depth` hops (default 2). Each value is analyzed
once, however many modules mention it:

```bash
kale investigate /var/log/auth.log --depth 1          # attacker IPs -> reputation
kale investigate sample.exe                           # hash, URLs, IPs -> reputation
kale investigate example.com --scope example.com      # subdomains -> web scan -> CVEs
kale investigate example.com --modules surface.discover,intel.enrich
kale investigate example.com --set vuln.intel.max_findings=3 -f json -o report.json
```

Active modules only ever see values inside the scope. A value another module discovered,
such as a command-and-control address in a malware sample or a subdomain in CT logs, is
never scanned just because it came up; the run is listed as skipped instead. `--max-runs`
(default 50) caps the number of module runs, and the report says when it stopped early.
The text report lists every finding, worst first, with the module and value it came from;
the JSON report follows `schemas/investigation.v1.json`.

### Authorization and scope

Active modules send traffic to their target. Scanning systems without the owner's
permission can be illegal, so active modules refuse to run unless the target is listed in
a scope:

```bash
kale run web.scan shop.example.com --scope example.com       # subdomains included
kale run web.scan 198.51.100.7 --scope 198.51.100.0/24
kale run web.scan intranet.local --scope-file scope.txt --allow-private
```

A scope file holds one domain or CIDR per line; `#` starts a comment. Private and reserved
addresses also need `--allow-private`.

### Threat intelligence

`intel.enrich` asks every configured source about an observable and reports what each one
says (malicious, suspicious, benign or no data):

```bash
kale run intel.enrich 185.10.20.30
kale run intel.enrich 468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e
kale run intel.enrich https://evil.example/payload.bin --set sources=urlhaus,virustotal
```

| Source | Looks up | Environment variable |
|---|---|---|
| GreyNoise Community | IPv4: internet-wide scanners, known services | `GREYNOISE_API_KEY` (optional) |
| AbuseIPDB | IP abuse reports | `ABUSEIPDB_API_KEY` |
| URLhaus (abuse.ch) | malware URLs and the hosts serving them | `ABUSECH_AUTH_KEY` |
| MalwareBazaar (abuse.ch) | known malware samples by hash | `ABUSECH_AUTH_KEY` |
| VirusTotal | stored reports for IPs, domains, URLs and hashes | `VIRUSTOTAL_API_KEY` |

Sources without a key are skipped and listed in the summary; GreyNoise works without one
at low volume. VirusTotal's free API is for non-commercial use and allows 4 requests a
minute, which kale respects.

Looking a value up discloses it to the source, so kale never sends private or reserved
addresses, internal host names (`.local`, `.corp`, single-label names, ...) or URLs that
contain credentials. Files are never uploaded: only hashes are looked up, and URLs are
never submitted for scanning. Answers are cached for 24 hours (`--set cache_hours=0` turns
the cache off; `KALE_CACHE_DIR` moves it) so investigations do not burn through free quotas.

### Vulnerabilities

`vuln.intel` lists the known vulnerabilities of a software version, or the details of one
CVE, in the order a defender should handle them:

```bash
kale run vuln.intel nginx@1.18.0                        # a product Kalkan fingerprints
kale run vuln.intel "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
kale run vuln.intel pkg:npm/lodash@4.17.20             # any package URL
kale run vuln.intel CVE-2021-44228
```

Server software goes to NVD by CPE name (some products are listed under two vendors, such
as `f5:nginx` and `nginx:nginx`, and both are asked). JavaScript libraries and package URLs
go to OSV, whose GitHub advisories cover them better. Each vulnerability then gets a
priority, which is the finding's severity:

| Priority | When |
|---|---|
| critical | in CISA's Known Exploited Vulnerabilities catalog: exploited in the wild |
| high | EPSS of 10% or more (likely to be exploited within 30 days), or CVSS 9 or more |
| medium | CVSS 7 or more |
| low | everything else |

CVSS says how bad an exploit would be, not how likely one is, so a CVSS 9.8 issue is not
critical on its own. NVD works without a key but allows only 5 requests per 30 seconds and
often resets connections; kale spaces requests out and retries them. `NVD_API_KEY` raises
the limit tenfold. Linux distributions often backport fixes without changing the version
number, so check the distribution's package before acting on a match.

### Attack surface

`surface.discover` maps a domain's hosts from Certificate Transparency logs (crt.sh and
CertSpotter) and checks each name in DNS. Nothing is sent to the hosts themselves, so it
runs without a scope:

```bash
kale run surface.discover example.com
kale run surface.discover example.com --set sources=certspotter --set max_names=100
```

| Finding | Severity |
|---|---|
| possible subdomain takeover: a CNAME to a name that does not exist on a service where anyone can claim it (Azure, AWS Elastic Beanstalk) | high |
| dangling CNAME: the same on any other service | medium |
| public names that point to private addresses | low |
| development and admin hosts listed in public certificates (`dev.`, `staging.`, `admin.`, `jenkins.`, ...) | low |

Takeovers are detected from DNS alone (the CNAME target answers NXDOMAIN). Services such as
S3 or GitHub Pages can only be confirmed with an HTTP request to the host, which would make
the module active, so they are reported as dangling CNAMEs at most. crt.sh is complete but
slow (a minute for a mid-sized domain); CertSpotter is fast but allows about ten requests an
hour without a key (`CERTSPOTTER_API_KEY`), so only its first pages are read. Resolving
hosts and their public addresses become observables for other modules.

## Running the service

kale can also run as a service for a team: an HTTP API queues module runs and
investigations, and separate workers process them. Results are the same JSON documents
the command line prints ([run](schemas/result.v1.json),
[investigation](schemas/investigation.v1.json)).

```bash
uv pip install -e ".[server]"                # FastAPI, uvicorn, SQLAlchemy, Alembic (part of .[dev])
kale db upgrade                              # create or migrate the database
kale token create --name ci --role runner    # printed once: store it
kale serve                                   # API on http://127.0.0.1:8000, docs at /api/docs
kale worker                                  # in another terminal; start as many as you need
```

A `reader` token can list modules, read the scope and read jobs; a `runner` token can also
submit and cancel jobs. Tokens are stored only as SHA-256 digests: `kale token list` shows
names and prefixes, and `kale token revoke NAME` takes effect on the next request. There is
no endpoint that creates tokens; that takes access to the database.

| Variable | Default | Meaning |
|---|---|---|
| `KALE_DATABASE_URL` | `sqlite:///<data dir>/kale.db` | SQLAlchemy URL; PostgreSQL through `postgresql+psycopg://` |
| `KALE_SCOPE_FILE` | unset | the server scope; unset means no active module runs |
| `KALE_ALLOW_PRIVATE` | `false` | allow private addresses inside the scope |
| `KALE_UPLOAD_DIR` | `<data dir>/uploads` | quarantine for uploaded files |
| `KALE_MAX_UPLOAD_MB` | `64` | upload size limit |
| `KALE_MAX_RUNS` | `100` | upper bound for an investigation's `max_runs` |
| `KALE_JOB_TIMEOUT` | `3600` | seconds a job may run |
| `KALE_JOB_ATTEMPTS` | `3` | claims before a job whose worker keeps dying fails |
| `KALE_HEARTBEAT_SECONDS` | `15` | how often a worker reports that its job is alive |
| `KALE_STALE_SECONDS` | `120` | heartbeat age after which another worker takes the job over |
| `KALE_WORKER_POLL_SECONDS` | `1` | how often an idle worker checks the queue |

The data directory is `%LOCALAPPDATA%\kale` on Windows and `$XDG_DATA_HOME/kale` (or
`~/.local/share/kale`) elsewhere.

**Scope.** Active modules only touch targets in the server scope, a file in the
`--scope-file` format named by `KALE_SCOPE_FILE`. A job may send `scope` to narrow it, never
to widen it: with `shop.example.com` in the server scope, a job asking for `example.com` is
refused. Each worker intersects a job's scope with the scope file again when the job
starts, so a target removed from the file is not touched even by jobs queued before the
change. `kale serve` reads the file when it starts: restart it after adding a target. A
scope file that is missing or invalid stops both commands from starting. Private addresses
need both `KALE_ALLOW_PRIVATE=true` on the server and `"allow_private": true` in the job.

**Uploads.** Modules that take a file (`logs.auth`, `malware.static`) receive it in a
multipart request. The file is stored under a random name in `KALE_UPLOAD_DIR` (a 0700
directory), limited to `KALE_MAX_UPLOAD_MB` counted on the bytes actually received. It is
never executed, no endpoint ever returns it, and it is deleted when the job ends, whatever
the outcome; only its name (for display), size and SHA-256 remain.

Submit a domain job, a file job, then read a result and its text report:

```bash
curl -s http://127.0.0.1:8000/api/v1/jobs \
  -H "Authorization: Bearer $KALE_TOKEN" -H "Content-Type: application/json" \
  -d '{"kind":"run","module":"surface.discover","target":{"kind":"domain","value":"example.com"}}'
# {"id":"0b6c3f4e-...","status":"queued"}

curl -s http://127.0.0.1:8000/api/v1/jobs \
  -H "Authorization: Bearer $KALE_TOKEN" \
  -F 'job={"kind":"run","module":"logs.auth","target":{"kind":"file"}};type=application/json' \
  -F file=@auth.log

curl -s http://127.0.0.1:8000/api/v1/jobs/0b6c3f4e-... -H "Authorization: Bearer $KALE_TOKEN"
curl -s http://127.0.0.1:8000/api/v1/jobs/0b6c3f4e-.../report -H "Authorization: Bearer $KALE_TOKEN"
```

A job is `queued`, then `running`, then `succeeded` or `failed`; a queued job can be
cancelled with `POST /api/v1/jobs/{id}/cancel`. `succeeded` means the job produced a
result: a module's own error (an invalid file, a target out of scope) is inside it, exactly
as on the command line. `failed` means the infrastructure gave up: the job deadline passed,
the worker died three times, or the scope file broke. `GET /api/v1/jobs` lists jobs newest
first; pass the oldest `created_at` you have as `before` to get the next page.

Things to know before running it for real:

- `kale serve` binds to `127.0.0.1`. Put a TLS reverse proxy (Caddy, nginx) in front before
  exposing it: tokens travel in a header and must not cross a network in clear text.
- Rate limits for services used without a key (NVD, CertSpotter) are kept inside each worker
  process. Without keys, run a single worker, or two workers together can exceed a limit.
- Service keys (`VIRUSTOTAL_API_KEY`, `NVD_API_KEY`, ...) live only in the workers'
  environment. Requests cannot carry keys, and `GET /api/v1/modules` only says whether each
  one is set.

## Result format

Every run produces a `ModuleResult` ([schema](schemas/result.v1.json)):

```json
{
  "schema_version": "1",
  "module": "logs.auth",
  "module_version": "0.1.0",
  "target": {"kind": "file", "value": "auth.log", "source": ""},
  "findings": [
    {
      "rule_id": "logs.auth.brute_force",
      "severity": "high",
      "title": "Brute force from 203.0.113.45",
      "recommendation": "Block the address at the firewall, ...",
      "evidence": {"ip": "203.0.113.45", "total_failed": 40, "max_in_window": 21},
      "observables": [{"kind": "ip", "value": "203.0.113.45", "source": "logs.auth"}],
      "references": ["https://attack.mitre.org/techniques/T1110/"]
    }
  ],
  "observables": [{"kind": "ip", "value": "203.0.113.45", "source": "logs.auth"}],
  "summary": {"total_events": 66},
  "error": null
}
```

- `rule_id` is stable across versions, so findings can be tracked, suppressed or compared.
- `severity` is one of `critical`, `high`, `medium`, `low`, `info`. Findings come worst
  first; within one severity they keep the order the module ranked them in.
- `observables` are facts other modules can take as input (an attacker IP for a reputation
  lookup, a software version for a CVE lookup).
- Failures never crash a run: they appear in `error` with a code (`invalid_input`,
  `out_of_scope`, `missing_secret`, `timeout`, `failed`).

## Writing a module

A module is a class with a `spec` and an async `run`:

```python
from typing import ClassVar

from kale.core import (
    Category, Finding, Kind, ModuleOutput, ModuleSpec, Observable, Option, RunContext, Severity,
)


class HashLookup:
    spec: ClassVar[ModuleSpec] = ModuleSpec(
        name="intel.hash",
        version="0.1.0",
        summary="Look up a file hash in a threat intelligence feed",
        category=Category.THREAT_INTEL,
        accepts=frozenset({Kind.HASH}),
        secrets=frozenset({"FEED_API_KEY"}),
        options={"timeout": Option("float", 10.0, "request timeout, seconds", minimum=1)},
    )

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        ...  # raise InvalidInputError for bad input; anything else is reported as a failure
        return ModuleOutput(findings=(Finding(rule_id="intel.hash.known_bad", ...),))
```

Register it in the plugin's `pyproject.toml`:

```toml
[project.entry-points."kale.modules"]
"intel.hash" = "my_plugin:HashLookup"
```

Loading a plugin runs its code, so third-party plugins load only when allow-listed:
`KALE_PLUGINS=intel.hash`. The engine handles the rest: input kind, scope, secrets, option
parsing, timeouts and error reporting. Keys a module can work without go in
`optional_secrets` instead of `secrets`: they reach the module only when they are set. `tests/test_contract.py` checks every registered
module against the rules automatically.

## Architecture

```
src/kale/
├── core/            # the contract; knows nothing about the CLI or HTTP
│   ├── models.py    # Severity, Kind, Observable, Finding, ModuleResult (pydantic)
│   ├── module.py    # ModuleSpec, Option, RunContext, Module protocol
│   ├── registry.py  # entry-point discovery with an allowlist
│   ├── engine.py    # guards, timeout, error isolation
│   ├── pipeline.py  # kale investigate: breadth-first walk, scope rule, run budget
│   └── scope.py     # authorization scope for active modules
├── modules/         # built-in modules and adapters
│   ├── intel/       # intel.enrich: sources and verdict aggregation
│   ├── surface/     # surface.discover: CT sources, DNS checks, takeover rules
│   └── vuln/        # vuln.intel: CPE/purl mapping, NVD, OSV, KEV, EPSS, priority
├── net/             # shared by modules that call services: HTTP errors and retries,
│                    # DNS lookups, privacy guard, rate limiter, TTL cache
├── server/          # the service (server extra): HTTP API, job queue, worker
│   ├── jobs.py      # service layer without HTTP: validate, queue, claim, recover, cancel
│   ├── worker.py    # claim loop, job deadline, heartbeat, run-time scope, upload cleanup
│   ├── api.py       # thin FastAPI routes; app.py adds errors, request ids, headers
│   └── migrations/  # Alembic revisions
├── report.py        # text (terminal-safe) and JSON renderers
└── cli.py           # thin command line layer
```

## Development

```bash
ruff format --check . && ruff check . && mypy && pytest --cov --cov-fail-under=90
```

Tests never touch the network: the Kalkan adapter is tested against a fake scanner and
`intel.enrich`, `vuln.intel` and `surface.discover` against a fake HTTP layer shaped like
the real services (and a fake resolver). The service is tested through FastAPI's test
client on a SQLite file per test, with the worker driven one job at a time.

## Roadmap

1. **Core** (done): contract, registry, engine, scope, CLI, adapters for all three tools
   (`logs.auth`, `malware.static`, `web.scan`) and CI that tests them together.
2. **New modules and pipeline** (done): `intel.enrich`, `vuln.intel`,
   `surface.discover`, and `kale investigate`, which feeds each module's observables to
   the next.
3. **Interfaces**: the API service with a database job queue and workers (done),
   HTML/PDF reports, a web UI, a Docker image with PostgreSQL.
4. **Depth**: YARA, Sigma rules, EVTX, SARIF and STIX export, MITRE ATT&CK mapping.

## License

[MIT](LICENSE)
