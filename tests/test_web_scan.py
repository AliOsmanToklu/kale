from __future__ import annotations

from datetime import UTC, datetime

import pytest
from kalkan.i18n import Text
from kalkan.scanner import Category as KalkanCategory
from kalkan.scanner import DetectedSoftware, ScanOptions, ScanReport, TargetError
from kalkan.scanner import Finding as KalkanFinding
from kalkan.scanner import Severity as KalkanSeverity
from kalkan.scanner.models import CheckError

from kale.core import ErrorCode, Kind, ModuleResult, Observable, Scope, Severity, run_module
from kale.modules import web_scan
from kale.modules.web_scan import WebScanModule

DOMAIN = Observable(kind=Kind.DOMAIN, value="example.com")
SCOPE = Scope.parse(["example.com"])
EXPIRED = Text({"tr": "Sertifikanın süresi dolmuş", "en": "The certificate has expired"})


def report() -> ScanReport:
    now = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)
    return ScanReport(
        target="example.com",
        display_name="example.com",
        addresses=["203.0.113.10", "2001:db8::10", "not-an-ip"],
        started_at=now,
        finished_at=now,
        findings=[
            KalkanFinding(
                id="tls.expired",
                category=KalkanCategory.TLS,
                severity=KalkanSeverity.CRITICAL,
                title=EXPIRED,
                recommendation=Text({"tr": "Yenileyin.", "en": "Renew it."}),
                details={"Bitiş": "2026-01-01"},
            ),
            KalkanFinding(
                id="wordpress.closed.Contact Form 7",
                category=KalkanCategory.SOFTWARE,
                severity=KalkanSeverity.HIGH,
                title="Eklenti kapatılmış",
            ),
            KalkanFinding(
                id="http.hsts_ok",
                category=KalkanCategory.HTTP,
                severity=KalkanSeverity.PASS,
                title="HSTS açık",
            ),
        ],
        software=[
            DetectedSoftware(product="php", name="PHP", version="8.1.2", source="X-Powered-By"),
            DetectedSoftware(product="nginx", name="nginx", version=None, source="Server"),
        ],
        open_ports=[80, 443],
        errors=[CheckError("ports", Text({"tr": "zaman aşımı", "en": "timed out"}))],
        score=40,
        grade="F",
        tool_version="0.3.0",
        notes=["Not"],
    )


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ScanOptions]]:
    """Replace the real scanner: tests never touch the network."""
    seen: list[tuple[str, ScanOptions]] = []

    async def fake_scan(target: str, options: ScanOptions | None = None) -> ScanReport:
        assert options is not None
        seen.append((target, options))
        return report()

    monkeypatch.setattr(web_scan, "scan", fake_scan)
    return seen


async def scan_with(
    target: Observable = DOMAIN, scope: Scope | None = SCOPE, lang: str = "en", **options: str
) -> ModuleResult:
    return await run_module(WebScanModule(), target, scope=scope, lang=lang, options=options)


async def test_never_scans_without_a_scope(calls: list[tuple[str, ScanOptions]]) -> None:
    result = await scan_with(scope=None)
    assert result.error is not None
    assert result.error.code is ErrorCode.OUT_OF_SCOPE
    assert calls == []


async def test_findings_are_translated_and_passes_counted(
    calls: list[tuple[str, ScanOptions]],
) -> None:
    result = await scan_with()
    assert result.ok
    assert [(f.rule_id, f.severity) for f in result.findings] == [
        ("web.scan.tls.expired", Severity.CRITICAL),
        ("web.scan.wordpress.closed.contact_form_7", Severity.HIGH),
    ]
    expired = result.findings[0]
    assert expired.title == "The certificate has expired"
    assert expired.recommendation == "Renew it."
    assert expired.evidence == {"category": "tls", "details": {"Bitiş": "2026-01-01"}}
    assert result.summary["passed"] == ["http.hsts_ok"]
    assert result.summary["check_errors"] == [{"check": "ports", "message": "timed out"}]
    assert result.summary["score"] == 40
    assert result.summary["open_ports"] == [80, 443]
    assert [str(o) for o in result.observables] == [
        "ip:203.0.113.10",
        "ip:2001:db8::10",
        "software:php@8.1.2",
    ]


async def test_turkish_report(calls: list[tuple[str, ScanOptions]]) -> None:
    result = await scan_with(lang="tr")
    assert result.findings[0].title == "Sertifikanın süresi dolmuş"
    assert result.summary["check_errors"] == [{"check": "ports", "message": "zaman aşımı"}]


async def test_options_reach_kalkan(calls: list[tuple[str, ScanOptions]]) -> None:
    scope = Scope.parse(["203.0.113.0/24", "10.0.0.0/8"], allow_private=True)
    target = Observable(kind=Kind.URL, value="https://10.0.0.5/")
    await scan_with(target, scope, checks="tls, http", timeout="5")
    ((scanned, options),) = calls
    assert scanned == "https://10.0.0.5/"
    assert options.checks == frozenset({"tls", "http"})
    assert options.timeout == 5.0
    assert options.allow_private is True


async def test_default_runs_every_check(calls: list[tuple[str, ScanOptions]]) -> None:
    await scan_with()
    assert calls[0][1].checks is None
    assert calls[0][1].allow_private is False


async def test_unknown_check_is_rejected(calls: list[tuple[str, ScanOptions]]) -> None:
    result = await scan_with(checks="tls,teleport")
    assert result.error is not None
    assert result.error.code is ErrorCode.INVALID_INPUT
    assert "teleport" in result.error.message
    assert calls == []


async def test_target_errors_are_invalid_input(monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse(target: str, options: ScanOptions | None = None) -> ScanReport:
        raise TargetError(
            Text({"tr": "Geçerli bir alan adı girin.", "en": "Enter a valid domain."})
        )

    monkeypatch.setattr(web_scan, "scan", refuse)
    result = await scan_with()
    assert result.error is not None
    assert result.error.code is ErrorCode.INVALID_INPUT
    assert result.error.message == "Enter a valid domain."


def test_rule_suffix_never_breaks_the_rule_id_alphabet() -> None:
    assert web_scan._rule_suffix("ports.open_3306") == "ports.open_3306"
    assert web_scan._rule_suffix("..Weird..ID!") == "weird.id_"
    assert web_scan._rule_suffix("...") == "unknown"
