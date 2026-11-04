from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from kale.core import (
    ErrorCode,
    Finding,
    Kind,
    ModuleError,
    ModuleResult,
    Observable,
    Severity,
)
from kale.core.models import normalize_hostname

SCHEMA_FILE = Path(__file__).parents[1] / "schemas" / "result.v1.json"


@pytest.mark.parametrize(
    ("kind", "raw", "canonical"),
    [
        (Kind.DOMAIN, " Example.COM. ", "example.com"),
        (Kind.DOMAIN, "müşteri.com.tr", "xn--mteri-kva70e.com.tr"),
        (Kind.DOMAIN, "_dmarc.example.com", "_dmarc.example.com"),
        (Kind.IP, "2001:DB8::0:1", "2001:db8::1"),
        (Kind.IP, "203.0.113.5", "203.0.113.5"),
        (Kind.URL, "https://example.com/a?b=1", "https://example.com/a?b=1"),
        (Kind.EMAIL, "Ali@Example.COM", "Ali@example.com"),
        (Kind.HASH, "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
        (Kind.CVE, "cve-2024-3094", "CVE-2024-3094"),
        (Kind.FILE, "logs/auth.log", "logs/auth.log"),
        (Kind.SOFTWARE, "php@8.1.2", "php@8.1.2"),
    ],
)
def test_observables_are_canonical(kind: Kind, raw: str, canonical: str) -> None:
    assert Observable(kind=kind, value=raw).value == canonical


@pytest.mark.parametrize(
    ("kind", "raw"),
    [
        (Kind.DOMAIN, ""),
        (Kind.DOMAIN, "203.0.113.5"),
        (Kind.DOMAIN, "bad..example.com"),
        (Kind.DOMAIN, "-bad.example.com"),
        (Kind.DOMAIN, "a" * 64 + ".com"),
        (Kind.DOMAIN, "spaces in.example.com"),
        (Kind.IP, "999.1.1.1"),
        (Kind.URL, "ftp://example.com"),
        (Kind.URL, "https://"),
        (Kind.EMAIL, "no-at-sign"),
        (Kind.EMAIL, "@example.com"),
        (Kind.EMAIL, "php@8.1.2"),
        (Kind.DOMAIN, "10.0.0"),
        (Kind.HASH, "abc"),
        (Kind.HASH, "z" * 32),
        (Kind.CVE, "CVE-24-1"),
    ],
)
def test_invalid_observables_are_rejected(kind: Kind, raw: str) -> None:
    with pytest.raises(ValidationError):
        Observable(kind=kind, value=raw)


def test_observable_identity_ignores_source() -> None:
    a = Observable(kind=Kind.IP, value="203.0.113.5", source="one")
    b = Observable(kind=Kind.IP, value="203.0.113.5")
    assert a.key == b.key
    assert str(a) == "ip:203.0.113.5"


def test_observable_with_invalid_kind_reports_the_kind() -> None:
    with pytest.raises(ValidationError, match="kind"):
        Observable(kind="planet", value="mars")


def test_normalize_hostname_rejects_overlong_names() -> None:
    with pytest.raises(ValueError, match="hostname"):
        normalize_hostname(".".join(["a" * 60] * 5))


@pytest.mark.parametrize("rule_id", ["nodot", "Upper.case", ".leading", "a..b", "a.b c"])
def test_finding_rule_ids_are_stable_identifiers(rule_id: str) -> None:
    with pytest.raises(ValidationError):
        Finding(rule_id=rule_id, severity=Severity.LOW, title="t")


def test_models_are_frozen_and_strict() -> None:
    finding = Finding(rule_id="a.b", severity=Severity.LOW, title="t")
    with pytest.raises(ValidationError):
        finding.title = "changed"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Finding(rule_id="a.b", severity=Severity.LOW, title="t", unexpected=1)  # type: ignore[call-arg]


def test_severity_order() -> None:
    assert [s.rank for s in Severity] == [0, 1, 2, 3, 4]
    assert Severity.CRITICAL.at_least(Severity.HIGH)
    assert Severity.HIGH.at_least(Severity.HIGH)
    assert not Severity.LOW.at_least(Severity.MEDIUM)


def _result(**kwargs: object) -> ModuleResult:
    now = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
    fields: dict[str, object] = {
        "module": "fake.echo",
        "module_version": "1.0",
        "target": Observable(kind=Kind.DOMAIN, value="example.com"),
        "started_at": now,
        "finished_at": now + timedelta(seconds=2.5),
    }
    fields.update(kwargs)
    return ModuleResult.model_validate(fields)


def test_result_helpers() -> None:
    findings = (
        Finding(rule_id="a.low", severity=Severity.LOW, title="l"),
        Finding(rule_id="a.high", severity=Severity.HIGH, title="h"),
        Finding(rule_id="a.high2", severity=Severity.HIGH, title="h2"),
    )
    result = _result(findings=findings)
    assert result.ok
    assert result.duration == 2.5
    assert result.count(Severity.HIGH) == 2
    assert result.worst_severity() is Severity.HIGH
    assert _result().worst_severity() is None
    failed = _result(error=ModuleError(code=ErrorCode.FAILED, message="x"))
    assert not failed.ok


def test_result_round_trips_through_json() -> None:
    result = _result(
        findings=(
            Finding(
                rule_id="a.b",
                severity=Severity.MEDIUM,
                title="t",
                evidence={"n": 1, "items": ["x", {"y": None}]},
                observables=(Observable(kind=Kind.IP, value="203.0.113.5"),),
                references=("https://attack.mitre.org/techniques/T1110/",),
            ),
        ),
        summary={"score": 40},
    )
    assert ModuleResult.model_validate_json(result.model_dump_json()) == result
    assert json.loads(result.model_dump_json())["schema_version"] == "1"


def test_published_schema_matches_the_models() -> None:
    """schemas/result.v1.json is the public contract; regenerate it with `kale schema`."""
    published = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    assert published == ModuleResult.model_json_schema()
