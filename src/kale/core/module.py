"""What a module is: a ``ModuleSpec`` the toolkit can inspect, plus an async ``run``.

The spec is plain data so that every front end (CLI, API, GUI) can describe a module,
build an options form and enforce its rules without running it.
"""

from __future__ import annotations

import enum
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import ClassVar, Literal, Protocol

from kale.core.errors import InvalidInputError
from kale.core.models import Kind, ModuleOutput, Observable

OptionValue = str | int | float | bool
OptionType = Literal["str", "int", "float", "bool"]

_NAME = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


class Category(enum.StrEnum):
    RECON = "recon"
    VULNERABILITY = "vulnerability"
    THREAT_INTEL = "threat_intel"
    DETECTION = "detection"
    MALWARE = "malware"


def _matches(kind: OptionType, value: OptionValue) -> bool:
    if kind == "bool":
        return isinstance(value, bool)
    if isinstance(value, bool):
        return False
    if kind == "int":
        return isinstance(value, int)
    if kind == "float":
        return isinstance(value, int | float)
    return isinstance(value, str)


@dataclass(frozen=True, slots=True)
class Option:
    """A setting a module accepts, given on the command line as ``--set name=value``."""

    type: OptionType
    default: OptionValue
    help: str
    choices: tuple[str, ...] = ()
    minimum: float | None = None
    maximum: float | None = None

    def parse(self, name: str, raw: str) -> OptionValue:
        text = raw.strip()
        value: OptionValue
        try:
            if self.type == "int":
                value = int(text)
            elif self.type == "float":
                value = float(text)
                if not math.isfinite(value):
                    raise ValueError(text)
            elif self.type == "bool":
                if text.lower() not in _TRUE | _FALSE:
                    raise ValueError(text)
                value = text.lower() in _TRUE
            else:
                value = text
        except ValueError:
            raise InvalidInputError(f"option {name!r} expects {self.type}, got {raw!r}") from None
        self.validate(name, value)
        return value

    def validate(self, name: str, value: OptionValue) -> None:
        if not _matches(self.type, value):
            raise InvalidInputError(f"option {name!r} expects {self.type}, got {value!r}")
        if self.choices and value not in self.choices:
            raise InvalidInputError(
                f"option {name!r} must be one of {', '.join(self.choices)}, got {value!r}"
            )
        if isinstance(value, str | bool):
            return
        if self.minimum is not None and value < self.minimum:
            raise InvalidInputError(f"option {name!r} must be at least {self.minimum:g}")
        if self.maximum is not None and value > self.maximum:
            raise InvalidInputError(f"option {name!r} must be at most {self.maximum:g}")


@dataclass(frozen=True, slots=True)
class ModuleSpec:
    name: str  # "group.name", e.g. "logs.auth"; also the entry-point name
    version: str
    summary: str  # one line for listings
    category: Category
    accepts: frozenset[Kind]
    active: bool = False  # sends traffic to the target: only runs inside a scope
    secrets: frozenset[str] = frozenset()  # environment variables the module needs
    options: Mapping[str, Option] = field(default_factory=dict)
    timeout: float = 120.0

    def __post_init__(self) -> None:
        if not _NAME.match(self.name):
            raise ValueError(f"module name must look like 'group.name': {self.name!r}")
        if not self.accepts:
            raise ValueError(f"{self.name}: a module must accept at least one kind")
        if not self.timeout > 0:
            raise ValueError(f"{self.name}: timeout must be positive")
        for option_name, option in self.options.items():
            option.validate(option_name, option.default)


@dataclass(frozen=True, slots=True)
class RunContext:
    """Everything a module may use besides its target. Options are already validated."""

    options: Mapping[str, OptionValue] = field(default_factory=dict)
    secrets: Mapping[str, str] = field(default_factory=dict)
    lang: str = "en"
    allow_private: bool = False  # the user explicitly allowed internal addresses

    def get_str(self, name: str) -> str:
        value = self.options[name]
        if not isinstance(value, str):
            raise TypeError(f"option {name!r} is not a str")
        return value

    def get_int(self, name: str) -> int:
        value = self.options[name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"option {name!r} is not an int")
        return value

    def get_float(self, name: str) -> float:
        value = self.options[name]
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise TypeError(f"option {name!r} is not a number")
        return float(value)

    def get_bool(self, name: str) -> bool:
        value = self.options[name]
        if not isinstance(value, bool):
            raise TypeError(f"option {name!r} is not a bool")
        return value


def resolve_options(spec: ModuleSpec, raw: Mapping[str, str]) -> dict[str, OptionValue]:
    """Defaults overlaid with ``raw`` (strings from the CLI or API), parsed and checked."""
    unknown = sorted(set(raw) - set(spec.options))
    if unknown:
        available = ", ".join(spec.options) or "none"
        raise InvalidInputError(
            f"unknown option(s) for {spec.name}: {', '.join(unknown)} (available: {available})"
        )
    values = {name: option.default for name, option in spec.options.items()}
    for name, text in raw.items():
        values[name] = spec.options[name].parse(name, text)
    return values


class Module(Protocol):
    spec: ClassVar[ModuleSpec]

    async def run(self, target: Observable, ctx: RunContext) -> ModuleOutput:
        """Analyze ``target``. Raise a ``KaleError`` subclass for expected failures."""
        ...
