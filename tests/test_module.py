from __future__ import annotations

import pytest

from kale.core import Category, InvalidInputError, Kind, ModuleSpec, Option, RunContext
from kale.core.module import resolve_options
from tests.fakes import EchoModule


@pytest.mark.parametrize(
    ("option", "raw", "value"),
    [
        (Option("int", 1, "h"), " 42 ", 42),
        (Option("float", 1.0, "h"), "2.5", 2.5),
        (Option("bool", False, "h"), "Yes", True),
        (Option("bool", True, "h"), "off", False),
        (Option("str", "", "h"), "text", "text"),
        (Option("str", "a", "h", choices=("a", "b")), "b", "b"),
        (Option("int", 5, "h", minimum=1), "1", 1),
        (Option("float", 5.0, "h", minimum=1, maximum=10), "10", 10.0),
    ],
)
def test_option_parse(option: Option, raw: str, value: object) -> None:
    assert option.parse("name", raw) == value


@pytest.mark.parametrize(
    ("option", "raw", "message"),
    [
        (Option("int", 1, "h"), "1.5", "expects int"),
        (Option("float", 1.0, "h"), "nan", "expects float"),
        (Option("float", 1.0, "h"), "inf", "expects float"),
        (Option("bool", False, "h"), "maybe", "expects bool"),
        (Option("str", "a", "h", choices=("a", "b")), "c", "must be one of a, b"),
        (Option("int", 5, "h", minimum=1), "0", "at least 1"),
        (Option("float", 5.0, "h", maximum=10), "10.5", "at most 10"),
    ],
)
def test_option_parse_rejects(option: Option, raw: str, message: str) -> None:
    with pytest.raises(InvalidInputError, match=message):
        option.parse("name", raw)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"name": "nodot"}, "group.name"),
        ({"name": "Bad.Name"}, "group.name"),
        ({"accepts": frozenset()}, "at least one kind"),
        ({"timeout": 0}, "timeout"),
        ({"options": {"n": Option("int", "ten", "h")}}, "expects int"),
        ({"options": {"flag": Option("int", True, "h")}}, "expects int"),
    ],
)
def test_spec_validation(kwargs: dict[str, object], message: str) -> None:
    fields: dict[str, object] = {
        "name": "fake.ok",
        "version": "1",
        "summary": "s",
        "category": Category.RECON,
        "accepts": frozenset({Kind.IP}),
    }
    fields.update(kwargs)
    with pytest.raises((ValueError, InvalidInputError), match=message):
        ModuleSpec(**fields)  # type: ignore[arg-type]


def test_resolve_options_fills_defaults_and_parses() -> None:
    values = resolve_options(EchoModule.spec, {"count": "3"})
    assert values == {"severity": "low", "count": 3, "loud": False, "ratio": 0.5}


def test_resolve_options_rejects_unknown_names() -> None:
    with pytest.raises(InvalidInputError, match=r"unknown option.*colour.*available: severity"):
        resolve_options(EchoModule.spec, {"colour": "red"})


def test_run_context_getters_check_types() -> None:
    ctx = RunContext(options={"s": "x", "i": 1, "f": 2, "b": True})
    assert ctx.get_str("s") == "x"
    assert ctx.get_int("i") == 1
    assert ctx.get_float("f") == 2.0
    assert ctx.get_bool("b") is True
    for getter, name in [
        (ctx.get_str, "i"),
        (ctx.get_int, "b"),
        (ctx.get_float, "s"),
        (ctx.get_bool, "i"),
    ]:
        with pytest.raises(TypeError):
            getter(name)
