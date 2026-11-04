"""``logs.auth``: log-analyzer (SSH auth.log, Windows logon CSV) as a kale module."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from log_analyzer import __version__ as LOG_ANALYZER_VERSION
from log_analyzer.analysis import AnalysisResult, analyze
from log_analyzer.models import Event
from log_analyzer.parsers import parse_file, parse_windows_csv

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

ATTACK_BRUTE_FORCE = "https://attack.mitre.org/techniques/T1110/"
ATTACK_VALID_ACCOUNTS = "https://attack.mitre.org/techniques/T1078/"
_MB = 1024 * 1024
_USERS_SHOWN = 5


class AuthLogModule:
    spec: ClassVar[ModuleSpec] = ModuleSpec(
        name="logs.auth",
        version=LOG_ANALYZER_VERSION,
        summary="Brute force, account compromise and username scanning in authentication logs",
        category=Category.DETECTION,
        accepts=frozenset({Kind.FILE}),
        options={
            "format": Option(
                "str",
                "auto",
                "ssh, windows or auto (.csv means windows)",
                ("auto", "ssh", "windows"),
            ),
            "year": Option("int", 0, "year of classic syslog timestamps; 0 infers it", minimum=0),
            "threshold": Option(
                "int", 10, "failed logins in one window that count as brute force", minimum=1
            ),
            "window": Option("int", 60, "brute force window in seconds", minimum=1),
            "scan_threshold": Option(
                "int", 3, "unknown-user logins that count as a scan", minimum=1
            ),
            "max_size_mb": Option("int", 512, "refuse larger files", minimum=1),
        },
    )

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        fmt = _resolve_format(target.value, ctx.get_str("format"))
        events = await asyncio.to_thread(
            _load, Path(target.value), fmt, ctx.get_int("year") or None, ctx.get_int("max_size_mb")
        )
        result = analyze(
            events,
            threshold=ctx.get_int("threshold"),
            window_seconds=ctx.get_int("window"),
            scan_threshold=ctx.get_int("scan_threshold"),
        )
        return ModuleOutput(
            findings=tuple(_findings(result)),
            summary={
                "format": fmt,
                "total_events": result.total_events,
                "threshold": result.threshold,
                "window_seconds": result.window_seconds,
                "scan_threshold": result.scan_threshold,
            },
        )


def _resolve_format(path: str, fmt: str) -> str:
    if fmt != "auto":
        return fmt
    return "windows" if path.lower().endswith(".csv") else "ssh"


def _load(path: Path, fmt: str, year: int | None, max_size_mb: int) -> list[Event]:
    """Runs in a worker thread: every blocking call stays off the event loop."""
    try:
        if not path.is_file():
            raise InvalidInputError(f"not a file: {path}")
        size = path.stat().st_size
        if size > max_size_mb * _MB:
            raise InvalidInputError(
                f"{path} is {size / _MB:.0f} MB, over the {max_size_mb} MB limit "
                "(raise it with max_size_mb)"
            )
        if fmt == "windows":
            return parse_windows_csv(path)
        return parse_file(path, year)
    except ValueError as exc:  # missing CSV columns, undecodable text
        raise InvalidInputError(str(exc)) from None
    except OSError as exc:
        raise InvalidInputError(f"cannot read {path}: {exc.strerror or exc}") from None


def _findings(result: AnalysisResult) -> list[Finding]:
    findings: list[Finding] = []
    for suspect in result.bruteforce:
        findings.append(
            Finding(
                rule_id="logs.auth.brute_force",
                severity=Severity.HIGH,
                title=f"Brute force from {suspect.ip}",
                description=(
                    f"{suspect.total_failed} failed logins between {suspect.first_seen} and "
                    f"{suspect.last_seen}, up to {suspect.max_in_window} within "
                    f"{result.window_seconds} s. Accounts tried: {_names(suspect.users_tried)}."
                ),
                recommendation=(
                    "Block the address at the firewall, lock out or rate-limit repeated "
                    "failures, and require keys or MFA for remote logins."
                ),
                evidence={
                    "ip": suspect.ip,
                    "total_failed": suspect.total_failed,
                    "max_in_window": suspect.max_in_window,
                    "window_seconds": result.window_seconds,
                    "first_seen": suspect.first_seen.isoformat(),
                    "last_seen": suspect.last_seen.isoformat(),
                    "users_tried": list(suspect.users_tried),
                },
                observables=_ip(suspect.ip),
                references=(ATTACK_BRUTE_FORCE,),
            )
        )

    logins: dict[tuple[str, str], list[Event]] = {}
    for event in result.compromises:
        logins.setdefault((event.ip, event.user), []).append(event)
    for (ip, user), events in logins.items():
        first = min(e.time for e in events)
        findings.append(
            Finding(
                rule_id="logs.auth.possible_compromise",
                severity=Severity.CRITICAL,
                title=f"Successful login as {user} from brute force source {ip}",
                description=(
                    f"{ip} logged in as {user} at {first}, after its failed attempts began. "
                    "The password may have been guessed."
                ),
                recommendation=(
                    f"Treat the {user} account as compromised: reset its credentials, end its "
                    f"sessions and review its activity since {first}."
                ),
                evidence={
                    "ip": ip,
                    "user": user,
                    "first_login": first.isoformat(),
                    "logins": len(events),
                },
                observables=_ip(ip),
                references=(ATTACK_VALID_ACCOUNTS, ATTACK_BRUTE_FORCE),
            )
        )

    for scanner in result.scanners:
        findings.append(
            Finding(
                rule_id="logs.auth.username_scan",
                severity=Severity.MEDIUM,
                title=f"Username scanning from {scanner.ip}",
                description=(
                    f"{scanner.count} logins with usernames that do not exist: "
                    f"{_names(scanner.users_tried)}."
                ),
                recommendation=(
                    "Block the address, and make sure default account names (admin, oracle, "
                    "test) do not exist or cannot log in remotely."
                ),
                evidence={
                    "ip": scanner.ip,
                    "count": scanner.count,
                    "users_tried": list(scanner.users_tried),
                },
                observables=_ip(scanner.ip),
                references=(ATTACK_BRUTE_FORCE,),
            )
        )

    if result.total_events == 0:
        findings.append(
            Finding(
                rule_id="logs.auth.no_events",
                severity=Severity.INFO,
                title="No authentication events found",
                description=(
                    "The file contains no lines this module recognizes. If it is a log, "
                    "check the format option (ssh or windows)."
                ),
            )
        )
    return findings


def _ip(value: str) -> tuple[Observable, ...]:
    """Log fields are attacker-influenced: sshd logs a hostname when UseDNS is on, so only
    real addresses become observables (the raw value stays in the evidence)."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return ()
    return (Observable(kind=Kind.IP, value=value),)


def _names(users: Sequence[str]) -> str:
    shown = ", ".join(u or "(empty)" for u in users[:_USERS_SHOWN])
    hidden = len(users) - _USERS_SHOWN
    return f"{shown} and {hidden} more" if hidden > 0 else shown
