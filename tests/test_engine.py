from __future__ import annotations

import pytest

from kale.core import ErrorCode, Kind, Observable, Scope, Severity, run_module
from kale.core.module import Module
from tests import fakes

TARGET = Observable(kind=Kind.DOMAIN, value="example.com")
SCOPE = Scope.parse(["example.com"])


async def test_successful_run_carries_identity_and_output() -> None:
    result = await run_module(fakes.EchoModule(), TARGET, options={"count": "2"}, lang="tr")
    assert result.ok
    assert (result.module, result.module_version, result.target) == ("fake.echo", "1.0", TARGET)
    assert result.started_at <= result.finished_at
    assert [f.rule_id for f in result.findings] == ["fake.echo.f0", "fake.echo.f1"]
    assert result.summary == {"lang": "tr", "allow_private": False, "loud": False, "ratio": 0.5}


async def test_observables_are_deduplicated_stamped_and_exclude_the_target() -> None:
    result = await run_module(fakes.EchoModule(), TARGET, options={"count": "2"})
    assert [str(o) for o in result.observables] == [
        "ip:203.0.113.1",
        "ip:203.0.113.2",
        "domain:f0.example.org",
        "domain:f1.example.org",
    ]
    sources = {str(o): o.source for o in result.observables}
    assert sources["ip:203.0.113.1"] == "fake.echo"
    assert sources["ip:203.0.113.2"] == "x"  # a source the module set is kept
    assert all(o.source == "fake.echo" for f in result.findings for o in f.observables)


async def test_findings_are_sorted_worst_first_then_by_rule() -> None:
    result = await run_module(fakes.MixedModule(), TARGET)
    assert [f.rule_id for f in result.findings] == ["fake.mixed.c", "fake.mixed.a", "fake.mixed.b"]
    assert result.worst_severity() is Severity.CRITICAL


async def test_wrong_kind_is_invalid_input() -> None:
    result = await run_module(fakes.EchoModule(), Observable(kind=Kind.FILE, value="x.log"))
    assert result.error is not None
    assert result.error.code is ErrorCode.INVALID_INPUT
    assert "accepts domain, ip, url, not file" in result.error.message


@pytest.mark.parametrize(
    ("options", "message"),
    [({"count": "many"}, "expects int"), ({"colour": "red"}, "unknown option")],
)
async def test_bad_options_are_invalid_input(options: dict[str, str], message: str) -> None:
    result = await run_module(fakes.EchoModule(), TARGET, options=options)
    assert result.error is not None
    assert result.error.code is ErrorCode.INVALID_INPUT
    assert message in result.error.message


@pytest.mark.parametrize("scope", [None, Scope()])
async def test_active_module_needs_a_scope(scope: Scope | None) -> None:
    result = await run_module(fakes.ActiveModule(), TARGET, scope=scope)
    assert result.error is not None
    assert result.error.code is ErrorCode.OUT_OF_SCOPE
    assert "authorized" in result.error.message


async def test_active_module_runs_inside_its_scope() -> None:
    result = await run_module(fakes.ActiveModule(), TARGET, scope=SCOPE)
    assert result.ok
    assert result.summary == {"allow_private": False}

    outside = await run_module(
        fakes.ActiveModule(), Observable(kind=Kind.DOMAIN, value="other.org"), scope=SCOPE
    )
    assert outside.error is not None
    assert outside.error.code is ErrorCode.OUT_OF_SCOPE


async def test_allow_private_reaches_the_module() -> None:
    scope = Scope.parse(["10.0.0.0/8"], allow_private=True)
    target = Observable(kind=Kind.IP, value="10.1.2.3")
    result = await run_module(fakes.ActiveModule(), target, scope=scope)
    assert result.summary == {"allow_private": True}


async def test_passive_module_ignores_scope() -> None:
    result = await run_module(fakes.EchoModule(), TARGET, scope=Scope.parse(["other.org"]))
    assert result.ok


async def test_missing_secret_is_reported_and_present_secret_is_passed() -> None:
    missing = await run_module(fakes.SecretModule(), TARGET, environ={})
    assert missing.error is not None
    assert missing.error.code is ErrorCode.MISSING_SECRET
    assert "FAKE_API_KEY" in missing.error.message

    present = await run_module(fakes.SecretModule(), TARGET, environ={"FAKE_API_KEY": "abcd"})
    assert present.summary == {"key_length": 4}


async def test_timeout_cancels_the_module() -> None:
    result = await run_module(fakes.SlowModule(), TARGET)
    assert result.error is not None
    assert result.error.code is ErrorCode.TIMEOUT
    assert "0.05s" in result.error.message


async def test_timeout_raised_inside_a_module_is_an_ordinary_failure() -> None:
    result = await run_module(fakes.InnerTimeoutModule(), TARGET)
    assert result.error is not None
    assert result.error.code is ErrorCode.FAILED
    assert "socket timed out" in result.error.message


@pytest.mark.parametrize(
    ("module", "code", "message"),
    [
        (fakes.CrashModule(), ErrorCode.FAILED, "RuntimeError: boom"),
        (fakes.RejectModule(), ErrorCode.INVALID_INPUT, "cannot use this target"),
        (fakes.WrongReturnModule(), ErrorCode.FAILED, "expected ModuleOutput"),
    ],
)
async def test_module_failures_become_errors(module: Module, code: ErrorCode, message: str) -> None:
    result = await run_module(module, TARGET)
    assert result.error is not None
    assert result.error.code is code
    assert message in result.error.message
    assert result.findings == ()
