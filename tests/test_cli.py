from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from kalkan.scanner import ScanOptions, ScanReport

from kale import cli
from kale.cli import EXIT_FINDINGS, EXIT_MODULE_ERROR, EXIT_OK, EXIT_USAGE, UsageError, main
from kale.core import Kind, ModuleResult, Registry, Unavailable
from kale.modules import web_scan

NETWORK = frozenset({Kind.DOMAIN, Kind.URL, Kind.IP})


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_modules_list(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "modules")
    assert code == EXIT_OK
    rows = {line.split()[0]: line.split()[1] for line in out.splitlines() if line.strip()}
    assert rows == {"logs.auth": "passive", "malware.static": "passive", "web.scan": "active"}


def test_modules_describe(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "modules", "logs.auth")
    assert code == EXIT_OK
    assert "accepts: file" in out
    assert "threshold" in out and "--set KEY=VALUE" in out


def test_modules_lists_unavailable_ones(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = Registry([], [Unavailable("intel.enrich", "missing dependency: httpx")])
    monkeypatch.setattr(Registry, "discover", classmethod(lambda cls: registry))
    code, out, _ = run(capsys, "modules")
    assert "No modules available." in out
    assert "intel.enrich: missing dependency: httpx" in out

    code, _, err = run(capsys, "run", "intel.enrich", "203.0.113.5")
    assert code == EXIT_USAGE
    assert "intel.enrich is unavailable: missing dependency: httpx" in err


def test_unknown_module(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "modules", "nope.nope")
    assert code == EXIT_USAGE
    assert "unknown module 'nope.nope'" in err


def test_run_text(capsys: pytest.CaptureFixture[str], ssh_log: Path) -> None:
    code, out, _ = run(capsys, "run", "logs.auth", str(ssh_log))
    assert code == EXIT_OK
    assert "[CRITICAL] Successful login as root" in out


def test_run_json_with_options(capsys: pytest.CaptureFixture[str], ssh_log: Path) -> None:
    code, out, _ = run(
        capsys, "run", "logs.auth", str(ssh_log), "-f", "json", "--set", "threshold=50"
    )
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["module"] == "logs.auth"
    assert data["summary"]["threshold"] == 50


@pytest.mark.parametrize(
    ("fail_on", "expected"), [("high", EXIT_FINDINGS), ("critical", EXIT_FINDINGS)]
)
def test_fail_on(
    capsys: pytest.CaptureFixture[str], ssh_log: Path, fail_on: str, expected: int
) -> None:
    code, _, _ = run(capsys, "run", "logs.auth", str(ssh_log), "--fail-on", fail_on)
    assert code == expected


def test_fail_on_below_threshold(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = tmp_path / "quiet.log"
    path.write_text("nothing\n", encoding="utf-8")
    code, _, _ = run(capsys, "run", "logs.auth", str(path), "--fail-on", "low")
    assert code == EXIT_OK  # an INFO finding never fails a build


def test_output_file(capsys: pytest.CaptureFixture[str], ssh_log: Path, tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    code, out, _ = run(capsys, "run", "logs.auth", str(ssh_log), "-f", "json", "-o", str(report))
    assert code == EXIT_OK
    assert out == ""
    assert ModuleResult.model_validate_json(report.read_text(encoding="utf-8")).ok


def test_unwritable_output(
    capsys: pytest.CaptureFixture[str], ssh_log: Path, tmp_path: Path
) -> None:
    code, _, err = run(capsys, "run", "logs.auth", str(ssh_log), "-o", str(tmp_path))
    assert code == EXIT_USAGE
    assert "cannot write" in err


def test_module_error(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    missing = str(tmp_path / "missing.log")
    code, out, err = run(capsys, "run", "logs.auth", missing)
    assert code == EXIT_MODULE_ERROR
    assert "ERROR (invalid_input): not a file" in out
    assert err == ""

    code, out, err = run(capsys, "run", "logs.auth", missing, "-f", "json")
    assert json.loads(out)["error"]["code"] == "invalid_input"
    assert "kale: logs.auth: not a file" in err


def test_bad_set_syntax(capsys: pytest.CaptureFixture[str], ssh_log: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["run", "logs.auth", str(ssh_log), "--set", "novalue"])
    assert exc.value.code == EXIT_USAGE
    assert "expected KEY=VALUE" in capsys.readouterr().err


def test_active_module_out_of_scope_gives_a_hint(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "run", "web.scan", "https://www.example.com/shop")
    assert code == EXIT_MODULE_ERROR
    assert "add --scope www.example.com" in err

    code, _, err = run(capsys, "run", "web.scan", "example.com", "--scope", "other.org")
    assert "hint" not in err


@pytest.fixture
def fake_kalkan(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    scanned: list[str] = []

    async def fake_scan(target: str, options: ScanOptions | None = None) -> ScanReport:
        scanned.append(target)
        now = datetime.now(UTC)
        return ScanReport(
            target=target,
            display_name=target,
            addresses=[],
            started_at=now,
            finished_at=now,
            findings=[],
            software=[],
            open_ports=[],
            errors=[],
            score=100,
            grade="A",
            tool_version="0.3.0",
        )

    monkeypatch.setattr(web_scan, "scan", fake_scan)
    return scanned


def test_scope_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, fake_kalkan: list[str]
) -> None:
    scope = tmp_path / "scope.txt"
    scope.write_text("# client\nexample.com\n", encoding="utf-8")
    code, out, _ = run(capsys, "run", "web.scan", "shop.example.com", "--scope-file", str(scope))
    assert code == EXIT_OK
    assert fake_kalkan == ["shop.example.com"]
    assert "grade=A" in out


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--scope-file", "does-not-exist.txt"], "cannot read scope file"),
        (["--scope", "not a domain!"], "invalid scope entry"),
    ],
)
def test_bad_scope(capsys: pytest.CaptureFixture[str], args: list[str], message: str) -> None:
    code, _, err = run(capsys, "run", "web.scan", "example.com", *args)
    assert code == EXIT_USAGE
    assert message in err


def test_schema(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "schema")
    assert code == EXIT_OK
    assert json.loads(out) == ModuleResult.model_json_schema()


def test_debug_flag_enables_logging(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "--debug", "modules")[0] == EXIT_OK


@pytest.mark.parametrize(
    ("value", "accepts", "kind"),
    [
        ("https://example.com/a", NETWORK, Kind.URL),
        ("203.0.113.5", NETWORK, Kind.IP),
        ("Example.com", NETWORK, Kind.DOMAIN),
        ("auth.log", frozenset({Kind.FILE}), Kind.FILE),  # missing file: the module reports it
        ("d41d8cd98f00b204e9800998ecf8427e", frozenset({Kind.HASH, Kind.IP}), Kind.HASH),
        ("example.com", frozenset({Kind.HASH, Kind.IP}), Kind.DOMAIN),  # engine rejects later
    ],
)
def test_guess_target(value: str, accepts: frozenset[Kind], kind: Kind) -> None:
    assert cli.guess_target(value, accepts).kind is kind


def test_guess_target_prefers_existing_files(ssh_log: Path) -> None:
    target = cli.guess_target(str(ssh_log), frozenset({Kind.FILE, Kind.DOMAIN}))
    assert target.kind is Kind.FILE


def test_guess_target_with_explicit_kind() -> None:
    assert cli.guess_target("x", NETWORK, Kind.SOFTWARE).kind is Kind.SOFTWARE
    with pytest.raises(UsageError, match="invalid ip target"):
        cli.guess_target("example.com", NETWORK, Kind.IP)


def test_guess_target_gives_up_on_nonsense() -> None:
    with pytest.raises(UsageError, match="pass --kind"):
        cli.guess_target("not a thing", frozenset({Kind.IP, Kind.HASH}))
