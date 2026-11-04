"""``web.scan``: the Kalkan website scanner as a kale module.

Kalkan stores its texts in every language it supports; the adapter renders them in the
language of the run. Passed checks are not findings in kale: they are counted in the
summary so reports stay focused on what needs attention.
"""

from __future__ import annotations

import ipaddress
import re
from typing import ClassVar

from kalkan import __version__ as KALKAN_VERSION
from kalkan.i18n import localize
from kalkan.scanner import Finding as KalkanFinding
from kalkan.scanner import ScanOptions, ScanReport, TargetError, scan
from kalkan.scanner import Severity as KalkanSeverity
from kalkan.scanner.checks import CHECK_NAMES

from kale.core import (
    Category,
    Finding,
    InvalidInputError,
    Kind,
    ModuleOutput,
    ModuleSpec,
    Observable,
    Option,
    RunContext,
    Severity,
)

_SEVERITY = {
    KalkanSeverity.CRITICAL: Severity.CRITICAL,
    KalkanSeverity.HIGH: Severity.HIGH,
    KalkanSeverity.MEDIUM: Severity.MEDIUM,
    KalkanSeverity.LOW: Severity.LOW,
    KalkanSeverity.INFO: Severity.INFO,
}
_UNSAFE_RULE_CHARS = re.compile(r"[^a-z0-9_.-]")


class WebScanModule:
    spec: ClassVar[ModuleSpec] = ModuleSpec(
        name="web.scan",
        version=KALKAN_VERSION,
        summary="Website scan by Kalkan: TLS, headers, exposed files, ports, software, e-mail, DNS",
        category=Category.VULNERABILITY,
        accepts=frozenset({Kind.DOMAIN, Kind.URL, Kind.IP}),
        active=True,
        options={
            "checks": Option("str", "", f"comma-separated subset of: {', '.join(CHECK_NAMES)}"),
            "timeout": Option("float", 10.0, "network timeout per request, seconds", minimum=1),
        },
        timeout=600.0,  # Kalkan runs three stages with a 90 s limit per check
    )

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        options = ScanOptions(
            checks=_checks(ctx.get_str("checks")),
            allow_private=ctx.allow_private,
            timeout=ctx.get_float("timeout"),
        )
        try:
            report = await scan(target.value, options)
        except TargetError as exc:
            raise InvalidInputError(localize(exc.text, ctx.lang)) from None
        return _output(report, ctx.lang)


def _checks(value: str) -> frozenset[str] | None:
    names = frozenset(name.strip() for name in value.split(",") if name.strip())
    unknown = sorted(names - set(CHECK_NAMES))
    if unknown:
        raise InvalidInputError(
            f"unknown check(s): {', '.join(unknown)} (available: {', '.join(CHECK_NAMES)})"
        )
    return names or None


def _output(report: ScanReport, lang: str) -> ModuleOutput:
    observables: list[Observable] = []
    for address in report.addresses:
        try:
            observables.append(Observable(kind=Kind.IP, value=str(ipaddress.ip_address(address))))
        except ValueError:
            continue
    for item in report.software:
        if item.version:
            observables.append(
                Observable(kind=Kind.SOFTWARE, value=f"{item.product}@{item.version}")
            )

    return ModuleOutput(
        findings=tuple(_finding(f, lang) for f in report.findings if f.severity in _SEVERITY),
        observables=tuple(observables),
        summary={
            "hostname": report.target,
            "score": report.score,
            "grade": report.grade,
            "addresses": list(report.addresses),
            "open_ports": list(report.open_ports),
            "passed": [f.id for f in report.findings if f.severity is KalkanSeverity.PASS],
            "check_errors": [
                {"check": e.check, "message": localize(e.message, lang)} for e in report.errors
            ],
            "notes": [localize(note, lang) for note in report.notes],
        },
    )


def _finding(finding: KalkanFinding, lang: str) -> Finding:
    return Finding(
        rule_id=f"web.scan.{_rule_suffix(finding.id)}",
        severity=_SEVERITY[finding.severity],
        title=localize(finding.title, lang),
        description=localize(finding.description, lang),
        recommendation=localize(finding.recommendation, lang),
        evidence={
            "category": finding.category.value,
            "details": {
                localize(key, lang): localize(value, lang) for key, value in finding.details.items()
            },
        },
    )


def _rule_suffix(finding_id: str) -> str:
    """Kalkan ids embed product and plugin names; keep them inside the rule id alphabet."""
    cleaned = _UNSAFE_RULE_CHARS.sub("_", finding_id.lower())
    return ".".join(part for part in cleaned.split(".") if part) or "unknown"
