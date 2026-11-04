from __future__ import annotations

from importlib.metadata import EntryPoint

import pytest

from kale.core import Kind, Registry, UnknownModuleError
from kale.core.registry import ENTRY_POINT_GROUP, PLUGINS_ENV
from tests import fakes


def ep(name: str, value: str) -> EntryPoint:
    return EntryPoint(name=name, value=value, group=ENTRY_POINT_GROUP)


def test_builtin_modules_are_discovered() -> None:
    registry = Registry.discover()
    names = [m.spec.name for m in registry]
    assert names == sorted(names)
    assert {"logs.auth", "malware.static", "web.scan"} <= set(names)
    assert registry.unavailable == []
    assert len(registry) == len(names)


def test_third_party_plugins_need_an_allowlist() -> None:
    eps = [ep("fake.echo", "tests.fakes:EchoModule")]
    blocked = Registry.discover(allow=[], eps=eps)
    assert len(blocked) == 0
    reason = blocked.reason_unavailable("fake.echo")
    assert reason is not None
    assert PLUGINS_ENV in reason

    allowed = Registry.discover(allow=["fake.echo"], eps=eps)
    assert isinstance(allowed.get("fake.echo"), fakes.EchoModule)
    assert allowed.reason_unavailable("fake.echo") is None


def test_allowlist_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PLUGINS_ENV, " fake.echo , other ")
    registry = Registry.discover(eps=[ep("fake.echo", "tests.fakes:EchoModule")])
    assert [m.spec.name for m in registry] == ["fake.echo"]


def test_module_instances_are_accepted_too() -> None:
    registry = Registry.discover(
        allow=["fake.echo"], eps=[ep("fake.echo", "tests.fakes:echo_instance")]
    )
    assert registry.get("fake.echo") is fakes.echo_instance


@pytest.mark.parametrize(
    ("name", "value", "reason"),
    [
        (
            "fake.missing",
            "kale_no_such_package.mod:Thing",
            "missing dependency: kale_no_such_package",
        ),
        ("fake.nospec", "tests.fakes:NoSpec", "has no ModuleSpec"),
        ("fake.renamed", "tests.fakes:EchoModule", "declares name 'fake.echo'"),
        ("fake.sync", "tests.fakes:SyncRun", "must be an async function"),
        ("fake.exploding", "tests.fakes:Exploding", "constructor failed"),
    ],
)
def test_broken_plugins_are_unavailable_not_fatal(name: str, value: str, reason: str) -> None:
    registry = Registry.discover(allow=[name], eps=[ep(name, value)])
    assert len(registry) == 0
    found = registry.reason_unavailable(name)
    assert found is not None
    assert reason in found


def test_duplicate_entry_points_keep_the_first() -> None:
    eps = [ep("fake.echo", "tests.fakes:EchoModule"), ep("fake.echo", "tests.fakes:echo_instance")]
    registry = Registry.discover(allow=["fake.echo"], eps=eps)
    assert len(registry) == 1
    assert registry.unavailable[0].reason.startswith("duplicate name")


def test_lookup_helpers() -> None:
    registry = Registry([fakes.EchoModule(), fakes.SecretModule()])
    assert [m.spec.name for m in registry.accepting(Kind.IP)] == ["fake.echo", "fake.secret"]
    assert registry.accepting(Kind.FILE) == []
    with pytest.raises(UnknownModuleError, match=r"nope.nope"):
        registry.get("nope.nope")
    with pytest.raises(ValueError, match="duplicate"):
        Registry([fakes.EchoModule(), fakes.EchoModule()])
