"""kale investigate with small fake modules: the walk, the scope rule and the budget."""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest

from kale.core import (
    Category,
    Finding,
    InvalidInputError,
    Investigation,
    Kind,
    ModuleOutput,
    ModuleSpec,
    Observable,
    Option,
    Registry,
    RunContext,
    Scope,
    Severity,
    UnknownModuleError,
    investigate,
)
from kale.report import render_investigation_json, render_investigation_text

SCHEMA_FILE = Path(__file__).parents[1] / "schemas" / "investigation.v1.json"
DOMAIN = Observable(kind=Kind.DOMAIN, value="example.com")


def spec(name: str, accepts: set[Kind], **kwargs: object) -> ModuleSpec:
    return ModuleSpec(
        name=name,
        version="1",
        summary=name,
        category=Category.RECON,
        accepts=frozenset(accepts),
        **kwargs,  # type: ignore[arg-type]
    )


class Discover:
    """example.com -> two subdomains and a C2-looking address (and itself again)."""

    spec: ClassVar[ModuleSpec] = spec(
        "fake.discover", {Kind.DOMAIN}, options={"extra": Option("str", "", "one more name")}
    )
    calls: ClassVar[list[str]] = []

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        self.calls.append(target.value)
        found = [
            Observable(kind=Kind.DOMAIN, value="www.example.com"),
            Observable(kind=Kind.DOMAIN, value="shop.example.com"),
            Observable(kind=Kind.IP, value="8.8.4.4"),
            target,
        ]
        if extra := ctx.get_str("extra"):
            found.append(Observable(kind=Kind.DOMAIN, value=extra))
        return ModuleOutput(
            findings=(
                Finding(rule_id="fake.discover.hosts", severity=Severity.INFO, title="hosts"),
            ),
            observables=tuple(found) if target.value == "example.com" else (),
        )


class Reputation:
    """Passive: any IP -> another IP (to test depth and dedup)."""

    spec: ClassVar[ModuleSpec] = spec("fake.reputation", {Kind.IP})

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        return ModuleOutput(
            findings=(Finding(rule_id="fake.reputation.bad", severity=Severity.HIGH, title="bad"),),
            observables=(Observable(kind=Kind.IP, value="8.8.8.8"),),
        )


class Scanner:
    """Active: may only see in-scope domains and addresses."""

    spec: ClassVar[ModuleSpec] = spec("fake.scanner", {Kind.DOMAIN, Kind.IP}, active=True)
    seen: ClassVar[list[str]] = []

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        self.seen.append(target.value)
        return ModuleOutput(
            findings=(Finding(rule_id="fake.scanner.low", severity=Severity.LOW, title="low"),)
        )


class Broken:
    spec: ClassVar[ModuleSpec] = spec("fake.broken", {Kind.DOMAIN})

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        raise RuntimeError("boom")


@pytest.fixture(autouse=True)
def reset() -> None:
    Discover.calls.clear()
    Scanner.seen.clear()


def registry(*extra: object) -> Registry:
    return Registry([Discover(), Reputation(), Scanner(), *extra])  # type: ignore[list-item]


def runs(result: Investigation) -> list[tuple[str, str]]:
    return [(run.module, run.target.value) for run in result.runs]


async def test_depth_zero_runs_only_the_target() -> None:
    result = await investigate(registry(), DOMAIN, depth=0)
    assert runs(result) == [("fake.discover", "example.com")]
    assert [(s.module, s.target.value) for s in result.skipped] == [("fake.scanner", "example.com")]


async def test_walk_follows_observables_once() -> None:
    result = await investigate(registry(), DOMAIN, depth=2)
    assert runs(result) == [
        ("fake.discover", "example.com"),
        ("fake.discover", "www.example.com"),
        ("fake.discover", "shop.example.com"),
        ("fake.reputation", "8.8.4.4"),
        ("fake.reputation", "8.8.8.8"),
    ]
    assert Discover.calls.count("example.com") == 1  # re-emitted target is not run again
    assert not result.truncated


async def test_active_modules_only_touch_the_scope() -> None:
    scope = Scope.parse(["shop.example.com", "8.8.8.0/24"])
    result = await investigate(registry(), DOMAIN, depth=2, scope=scope)
    assert sorted(Scanner.seen) == ["8.8.8.8", "shop.example.com"]
    skipped = {(s.module, s.target.value) for s in result.skipped}
    assert skipped == {
        ("fake.scanner", "example.com"),
        ("fake.scanner", "www.example.com"),
        ("fake.scanner", "8.8.4.4"),
    }
    assert all(s.reason == "outside the authorized scope" for s in result.skipped)


async def test_without_a_scope_nothing_active_runs() -> None:
    result = await investigate(registry(), DOMAIN, depth=2)
    assert Scanner.seen == []
    assert len(result.skipped) == 5


async def test_module_allowlist() -> None:
    result = await investigate(registry(), DOMAIN, depth=2, modules={"fake.discover"})
    assert {run.module for run in result.runs} == {"fake.discover"}
    with pytest.raises(UnknownModuleError):
        await investigate(registry(), DOMAIN, modules={"fake.typo"})


async def test_options_reach_their_module() -> None:
    result = await investigate(
        registry(), DOMAIN, depth=1, options={"fake.discover": {"extra": "api.example.com"}}
    )
    assert ("fake.discover", "api.example.com") in runs(result)


@pytest.mark.parametrize(
    ("options", "error", "message"),
    [
        ({"fake.discover": {"colour": "red"}}, InvalidInputError, "unknown option"),
        ({"fake.nothing": {"x": "1"}}, UnknownModuleError, "fake.nothing"),
    ],
)
async def test_bad_options_fail_before_anything_runs(
    options: dict[str, dict[str, str]], error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        await investigate(registry(), DOMAIN, options=options)
    assert Discover.calls == []


async def test_run_budget() -> None:
    result = await investigate(registry(), DOMAIN, depth=3, max_runs=2)
    assert len(result.runs) == 2
    assert result.truncated


@pytest.mark.parametrize(("depth", "max_runs"), [(-1, 10), (6, 10), (1, 0)])
async def test_limits_are_validated(depth: int, max_runs: int) -> None:
    with pytest.raises(InvalidInputError):
        await investigate(registry(), DOMAIN, depth=depth, max_runs=max_runs)


async def test_a_failing_module_does_not_stop_the_walk() -> None:
    result = await investigate(registry(Broken()), DOMAIN, depth=1)
    broken = [run for run in result.runs if run.module == "fake.broken"]
    assert broken and all(run.error is not None for run in broken)
    assert ("fake.reputation", "8.8.4.4") in runs(result)


async def test_aggregates_and_json() -> None:
    result = await investigate(registry(), DOMAIN, depth=2)
    assert result.worst_severity() is Severity.HIGH
    assert result.count(Severity.HIGH) == 2
    assert [f.severity for _, f in result.findings()][:2] == [Severity.HIGH, Severity.HIGH]
    assert Investigation.model_validate_json(render_investigation_json(result)) == result


async def test_text_report() -> None:
    scope = Scope.parse(["shop.example.com"])
    result = await investigate(registry(Broken()), DOMAIN, depth=1, scope=scope, max_runs=8)
    text = render_investigation_text(result)
    assert text.startswith("kale investigate | domain:example.com | depth 1 | ")
    assert "[HIGH] bad\n    fake.reputation on ip:8.8.4.4 | rule: fake.reputation.bad" in text
    assert "Informational (" in text and "fake.discover on domain:example.com: hosts" in text
    assert "failed (failed): RuntimeError: boom" in text
    assert (
        "Skipped (" in text
        and "fake.scanner  domain:example.com  outside the authorized scope" in text
    )
    assert "Stopped early" not in text


async def test_text_report_mentions_the_budget() -> None:
    result = await investigate(registry(), DOMAIN, depth=3, max_runs=1)
    assert "Stopped early: the run budget (--max-runs) was used up." in render_investigation_text(
        result
    )


def test_published_schema_matches_the_model() -> None:
    """schemas/investigation.v1.json; regenerate with `kale schema --investigation`."""
    assert json.loads(SCHEMA_FILE.read_text(encoding="utf-8")) == Investigation.model_json_schema()
