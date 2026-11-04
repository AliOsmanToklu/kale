"""The result contract every module speaks: observables in, findings and observables out.

These models are the stable surface of the toolkit. The CLI, JSON reports and any
future API or GUI depend on them, so breaking changes bump ``SCHEMA_VERSION``.
"""

from __future__ import annotations

import enum
import ipaddress
import re
from datetime import datetime
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationInfo, field_validator

SCHEMA_VERSION = "1"


class Severity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """0 for the most severe; sorts findings worst first."""
        return _SEVERITY_ORDER.index(self)

    def at_least(self, other: Severity) -> bool:
        return self.rank <= other.rank


_SEVERITY_ORDER = list(Severity)


class Kind(enum.StrEnum):
    """What an observable is. Modules declare which kinds they accept."""

    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    FILE = "file"
    SOFTWARE = "software"  # "product@version", e.g. "php@8.1.2"
    CVE = "cve"


class ErrorCode(enum.StrEnum):
    INVALID_INPUT = "invalid_input"
    OUT_OF_SCOPE = "out_of_scope"
    MISSING_SECRET = "missing_secret"  # noqa: S105 - an error code, not a secret
    TIMEOUT = "timeout"
    FAILED = "failed"


_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTHS = frozenset({32, 40, 64, 128})  # MD5, SHA-1, SHA-256, SHA-512
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_RULE_ID = r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9_-]+)+$"


def normalize_hostname(value: str) -> str:
    """Lower-case ASCII (punycode) form without a trailing dot. Raises ``ValueError``."""
    host = value.strip().rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"not a valid hostname: {value!r}") from exc
    labels = host.split(".")
    if not host or len(host) > 253 or not all(_LABEL.match(label) for label in labels):
        raise ValueError(f"not a valid hostname: {value!r}")
    if labels[-1].isdigit():  # no top-level domain is numeric: "8.1.2" is not a host
        raise ValueError(f"not a valid hostname: {value!r}")
    return host


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize(kind: Kind, value: str) -> str:
    """Validate ``value`` as ``kind`` and return its canonical form (``ValueError`` if bad).

    Canonical values make deduplication and caching reliable: ``Example.COM.`` and
    ``example.com`` are the same domain, ``2001:DB8::0:1`` and ``2001:db8::1`` the same IP.
    """
    value = value.strip()
    if not value:
        raise ValueError("value must not be empty")
    if kind is Kind.DOMAIN:
        if _is_ip(value):
            raise ValueError(f"{value!r} is an IP address; use kind 'ip'")
        return normalize_hostname(value)
    if kind is Kind.IP:
        return str(ipaddress.ip_address(value))
    if kind is Kind.URL:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            raise ValueError(f"not an http(s) URL with a host: {value!r}")
        return value
    if kind is Kind.EMAIL:
        local, at, domain = value.rpartition("@")
        if not at or not local:
            raise ValueError(f"not an e-mail address: {value!r}")
        return f"{local}@{normalize_hostname(domain)}"
    if kind is Kind.HASH:
        digest = value.lower()
        if len(digest) not in _HASH_LENGTHS or not _HEX.match(digest):
            raise ValueError(f"not an MD5/SHA-1/SHA-256/SHA-512 hex digest: {value!r}")
        return digest
    if kind is Kind.CVE:
        cve = value.upper()
        if not _CVE.match(cve):
            raise ValueError(f"not a CVE identifier: {value!r}")
        return cve
    return value  # FILE and SOFTWARE are free-form


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Observable(_Model):
    """Something a module can look at: a target given by the user or a fact a module found."""

    kind: Kind
    value: str
    source: str = ""  # the module that produced it; empty for user input

    @field_validator("value")
    @classmethod
    def _canonical(cls, value: str, info: ValidationInfo) -> str:
        kind = info.data.get("kind")
        return value if kind is None else normalize(kind, value)

    @property
    def key(self) -> tuple[Kind, str]:
        """Identity for deduplication (the source does not matter)."""
        return (self.kind, self.value)

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"


class Finding(_Model):
    """One result, written so that the reader knows what is wrong and what to do."""

    rule_id: str = Field(pattern=_RULE_ID)  # stable across versions: "logs.auth.brute_force"
    severity: Severity
    title: str = Field(min_length=1)
    description: str = ""
    recommendation: str = ""
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    observables: tuple[Observable, ...] = ()  # facts other modules can take as input
    references: tuple[str, ...] = ()  # URLs: CVE entries, MITRE ATT&CK techniques, docs


class ModuleError(_Model):
    code: ErrorCode
    message: str


class ModuleOutput(_Model):
    """What a module returns. The engine adds identity, timing and error handling."""

    findings: tuple[Finding, ...] = ()
    observables: tuple[Observable, ...] = ()
    summary: dict[str, JsonValue] = Field(default_factory=dict)


class ModuleResult(_Model):
    """One module run against one target; the unit every report format renders."""

    schema_version: str = SCHEMA_VERSION
    module: str
    module_version: str
    target: Observable
    started_at: datetime
    finished_at: datetime
    findings: tuple[Finding, ...] = ()
    observables: tuple[Observable, ...] = ()
    summary: dict[str, JsonValue] = Field(default_factory=dict)
    error: ModuleError | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def duration(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity is severity)

    def worst_severity(self) -> Severity | None:
        return min((f.severity for f in self.findings), key=lambda s: s.rank, default=None)


INVESTIGATION_SCHEMA_VERSION = "1"


class Skipped(_Model):
    """A module that could have run on an observable but was not allowed to."""

    module: str
    target: Observable
    reason: str


class Investigation(_Model):
    """``kale investigate``: every module run, starting from one target."""

    schema_version: str = INVESTIGATION_SCHEMA_VERSION
    target: Observable
    depth: int
    started_at: datetime
    finished_at: datetime
    runs: tuple[ModuleResult, ...] = ()
    skipped: tuple[Skipped, ...] = ()
    truncated: bool = False  # the run budget ran out before every observable was followed

    @property
    def duration(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def findings(self) -> list[tuple[ModuleResult, Finding]]:
        """All findings, worst first; runs keep their order within a severity."""
        pairs = [(run, finding) for run in self.runs for finding in run.findings]
        return sorted(pairs, key=lambda pair: pair[1].severity.rank)

    def count(self, severity: Severity) -> int:
        return sum(run.count(severity) for run in self.runs)

    def worst_severity(self) -> Severity | None:
        return min(
            (f.severity for run in self.runs for f in run.findings),
            key=lambda s: s.rank,
            default=None,
        )
