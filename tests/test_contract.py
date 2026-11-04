"""Rules every registered module must follow. A new module is covered automatically."""

from __future__ import annotations

import inspect

import pytest

from kale.core import ErrorCode, Kind, ModuleResult, Observable, Registry, Scope, run_module
from kale.core.module import Module

MODULES = Registry.discover().modules
# A valid observable of every kind, to feed modules what they do not accept.
SAMPLES = {
    Kind.DOMAIN: "example.com",
    Kind.IP: "203.0.113.5",
    Kind.URL: "https://example.com/",
    Kind.EMAIL: "a@example.com",
    Kind.HASH: "d41d8cd98f00b204e9800998ecf8427e",
    Kind.FILE: "missing.log",
    Kind.SOFTWARE: "php@8.1.2",
    Kind.CVE: "CVE-2024-3094",
}


def ids(module: Module) -> str:
    return module.spec.name


@pytest.mark.parametrize("module", MODULES, ids=ids)
def test_spec_is_complete(module: Module) -> None:
    spec = module.spec
    assert spec.version
    assert spec.summary and len(spec.summary) <= 100
    assert spec.accepts
    assert all(option.help for option in spec.options.values())
    assert inspect.iscoroutinefunction(module.run)


@pytest.mark.parametrize("module", MODULES, ids=ids)
async def test_unaccepted_kinds_are_rejected_cleanly(module: Module) -> None:
    scope = Scope.parse(["example.com", "203.0.113.0/24"])
    for kind in set(Kind) - module.spec.accepts:
        target = Observable(kind=kind, value=SAMPLES[kind])
        result = await run_module(module, target, scope=scope)
        assert result.error is not None
        assert result.error.code is ErrorCode.INVALID_INPUT
        assert ModuleResult.model_validate_json(result.model_dump_json()) == result


def test_every_kind_has_a_sample() -> None:
    assert set(SAMPLES) == set(Kind)
