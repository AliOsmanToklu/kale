from __future__ import annotations

from pathlib import Path

from kale.core import ErrorCode, Kind, ModuleResult, Observable, Severity, run_module
from kale.modules.auth_logs import AuthLogModule
from tests.conftest import sshd


async def analyze(path: Path, **options: str) -> ModuleResult:
    return await run_module(
        AuthLogModule(), Observable(kind=Kind.FILE, value=str(path)), options=options
    )


def by_rule(result: ModuleResult) -> dict[str, list[str]]:
    rules: dict[str, list[str]] = {}
    for finding in result.findings:
        rules.setdefault(finding.rule_id, []).append(finding.title)
    return rules


async def test_ssh_log(ssh_log: Path) -> None:
    result = await analyze(ssh_log)
    assert result.ok
    assert [(f.rule_id, f.severity) for f in result.findings] == [
        ("logs.auth.possible_compromise", Severity.CRITICAL),
        ("logs.auth.brute_force", Severity.HIGH),
        ("logs.auth.username_scan", Severity.MEDIUM),
    ]
    compromise, brute, scan = result.findings
    assert compromise.title == "Successful login as root from brute force source 203.0.113.45"
    assert compromise.evidence == {
        "ip": "203.0.113.45",
        "user": "root",
        "first_login": "2026-10-25T11:00:30",
        "logins": 1,
    }
    assert brute.evidence["total_failed"] == 12
    assert brute.evidence["users_tried"] == ["root"]
    assert scan.evidence == {"ip": "198.51.100.7", "count": 3, "users_tried": ["oracle"]}
    assert all(f.references for f in result.findings)
    assert [str(o) for o in result.observables] == ["ip:203.0.113.45", "ip:198.51.100.7"]
    assert result.summary == {
        "format": "ssh",
        "total_events": 16,
        "threshold": 10,
        "window_seconds": 60,
        "scan_threshold": 3,
    }


async def test_options_change_thresholds(ssh_log: Path) -> None:
    result = await analyze(ssh_log, threshold="20", scan_threshold="5")
    assert result.findings == ()
    assert result.summary["threshold"] == 20


async def test_windows_csv_is_chosen_by_extension(windows_csv: Path) -> None:
    result = await analyze(windows_csv)
    assert result.summary["format"] == "windows"
    assert by_rule(result) == {
        "logs.auth.possible_compromise": [
            "Successful login as administrator from brute force source 203.0.113.99"
        ],
        "logs.auth.brute_force": ["Brute force from 203.0.113.99"],
    }


async def test_explicit_format_overrides_the_extension(windows_csv: Path) -> None:
    result = await analyze(windows_csv, format="ssh")
    assert result.summary["format"] == "ssh"
    assert [f.rule_id for f in result.findings] == ["logs.auth.no_events"]


async def test_csv_without_the_expected_columns(tmp_path: Path) -> None:
    path = tmp_path / "other.csv"
    path.write_text("a,b\n1,2\n", encoding="utf-8")
    result = await analyze(path)
    assert result.error is not None
    assert result.error.code is ErrorCode.INVALID_INPUT
    assert "missing column" in result.error.message


async def test_undecodable_csv(tmp_path: Path) -> None:
    path = tmp_path / "binary.csv"
    path.write_bytes(b"Time,Id,User,IP\n\xff\xfe\x00bad\n")
    result = await analyze(path)
    assert result.error is not None
    assert result.error.code is ErrorCode.INVALID_INPUT


async def test_missing_file_and_directory(tmp_path: Path) -> None:
    for path in (tmp_path / "nope.log", tmp_path):
        result = await analyze(path)
        assert result.error is not None
        assert result.error.code is ErrorCode.INVALID_INPUT
        assert "not a file" in result.error.message


async def test_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "big.log"
    path.write_bytes(b"x" * (1024 * 1024 + 1))
    result = await analyze(path, max_size_mb="1")
    assert result.error is not None
    assert "over the 1 MB limit" in result.error.message


async def test_empty_log_explains_itself(tmp_path: Path) -> None:
    path = tmp_path / "empty.log"
    path.write_text("nothing to see\n", encoding="utf-8")
    result = await analyze(path)
    assert [(f.rule_id, f.severity) for f in result.findings] == [
        ("logs.auth.no_events", Severity.INFO)
    ]


async def test_hostnames_stay_in_evidence_but_are_not_observables(tmp_path: Path) -> None:
    path = tmp_path / "dns.log"
    lines = [
        sshd(i, "Failed password for root from scanner.example.net port 1 ssh2") for i in range(10)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = await analyze(path)
    assert result.findings[0].evidence["ip"] == "scanner.example.net"
    assert result.observables == ()


async def test_many_users_are_summarized_and_logins_grouped(tmp_path: Path) -> None:
    lines = [
        sshd(i, f"Failed password for invalid user u{i} from 203.0.113.8 port 1 ssh2")
        for i in range(12)
    ]
    lines += [
        sshd(30 + i, "Accepted password for u3 from 203.0.113.8 port 2 ssh2") for i in range(2)
    ]
    path = tmp_path / "spray.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = await analyze(path)
    compromise, brute = result.findings
    assert compromise.evidence["logins"] == 2
    assert "u0, u1, u10, u11, u2 and 7 more" in brute.description
