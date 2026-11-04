"""Small modules for exercising the engine, registry and CLI without real tools."""

from __future__ import annotations

import asyncio
from typing import ClassVar

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

NETWORK = frozenset({Kind.DOMAIN, Kind.IP, Kind.URL})


def make_spec(name: str, **kwargs: object) -> ModuleSpec:
    defaults: dict[str, object] = {
        "version": "1.0",
        "summary": f"{name} for tests",
        "category": Category.RECON,
        "accepts": NETWORK,
    }
    defaults.update(kwargs)
    return ModuleSpec(name=name, **defaults)  # type: ignore[arg-type]


class EchoModule:
    """One finding per ``count`` at ``severity``; reports what it was given."""

    spec: ClassVar[ModuleSpec] = make_spec(
        "fake.echo",
        options={
            "severity": Option("str", "low", "finding severity", tuple(s.value for s in Severity)),
            "count": Option("int", 1, "number of findings", minimum=0),
            "loud": Option("bool", False, "unused flag"),
            "ratio": Option("float", 0.5, "unused number", minimum=0),
        },
    )

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        severity = Severity(ctx.get_str("severity"))
        shared = Observable(kind=Kind.IP, value="203.0.113.1")
        findings = tuple(
            Finding(
                rule_id=f"fake.echo.f{i}",
                severity=severity,
                title=f"finding {i}",
                observables=(shared, Observable(kind=Kind.DOMAIN, value=f"f{i}.example.org")),
            )
            for i in range(ctx.get_int("count"))
        )
        return ModuleOutput(
            findings=findings,
            observables=(shared, target, Observable(kind=Kind.IP, value="203.0.113.2", source="x")),
            summary={
                "lang": ctx.lang,
                "allow_private": ctx.allow_private,
                "loud": ctx.get_bool("loud"),
                "ratio": ctx.get_float("ratio"),
            },
        )


class MixedModule:
    """Findings in an order the engine has to sort."""

    spec: ClassVar[ModuleSpec] = make_spec("fake.mixed")

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        return ModuleOutput(
            findings=(
                Finding(rule_id="fake.mixed.b", severity=Severity.LOW, title="low"),
                Finding(rule_id="fake.mixed.c", severity=Severity.CRITICAL, title="critical"),
                Finding(rule_id="fake.mixed.a", severity=Severity.LOW, title="low too"),
            )
        )


class ActiveModule:
    spec: ClassVar[ModuleSpec] = make_spec("fake.active", active=True)

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        return ModuleOutput(summary={"allow_private": ctx.allow_private})


class SlowModule:
    spec: ClassVar[ModuleSpec] = make_spec("fake.slow", timeout=0.05)

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        await asyncio.sleep(10)
        return ModuleOutput()


class InnerTimeoutModule:
    spec: ClassVar[ModuleSpec] = make_spec("fake.inner_timeout")

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        raise TimeoutError("socket timed out")


class CrashModule:
    spec: ClassVar[ModuleSpec] = make_spec("fake.crash")

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        raise RuntimeError("boom")


class RejectModule:
    spec: ClassVar[ModuleSpec] = make_spec("fake.reject")

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        raise InvalidInputError("cannot use this target")


class SecretModule:
    spec: ClassVar[ModuleSpec] = make_spec("fake.secret", secrets=frozenset({"FAKE_API_KEY"}))

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        return ModuleOutput(summary={"key_length": len(ctx.secrets["FAKE_API_KEY"])})


class WrongReturnModule:
    spec: ClassVar[ModuleSpec] = make_spec("fake.wrong_return")

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        return {"findings": []}  # type: ignore[return-value]


# Broken plugins, for the registry.


class NoSpec:
    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        return ModuleOutput()


class SyncRun:
    spec: ClassVar[ModuleSpec] = make_spec("fake.sync")

    def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        return ModuleOutput()


class Exploding:
    spec: ClassVar[ModuleSpec] = make_spec("fake.exploding")

    def __init__(self) -> None:
        raise RuntimeError("constructor failed")


echo_instance = EchoModule()
