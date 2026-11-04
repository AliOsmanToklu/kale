"""Find modules through the ``kale.modules`` entry-point group.

Loading an entry point imports and runs its code, so only modules that ship with kale
itself, plus third-party plugins the user allow-lists by name in ``KALE_PLUGINS``
(comma separated), are loaded. A module whose dependencies are missing is reported as
unavailable instead of breaking the whole toolkit.
"""

from __future__ import annotations

import inspect
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from typing import cast

from kale.core.errors import UnknownModuleError
from kale.core.models import Kind
from kale.core.module import Module, ModuleSpec

ENTRY_POINT_GROUP = "kale.modules"
BUILTIN_DISTRIBUTION = "kale"
PLUGINS_ENV = "KALE_PLUGINS"


@dataclass(frozen=True, slots=True)
class Unavailable:
    name: str
    reason: str


class Registry:
    def __init__(self, modules: Iterable[Module] = (), unavailable: Iterable[Unavailable] = ()):
        self._modules: dict[str, Module] = {}
        for module in modules:
            name = module.spec.name
            if name in self._modules:
                raise ValueError(f"duplicate module name: {name}")
            self._modules[name] = module
        self.unavailable: list[Unavailable] = sorted(unavailable, key=lambda u: u.name)

    @classmethod
    def discover(
        cls,
        *,
        allow: Iterable[str] | None = None,
        eps: Iterable[EntryPoint] | None = None,
    ) -> Registry:
        allowed = set(_allow_from_env() if allow is None else allow)
        found = entry_points(group=ENTRY_POINT_GROUP) if eps is None else eps
        modules: list[Module] = []
        unavailable: list[Unavailable] = []
        names: set[str] = set()
        for ep in sorted(found, key=lambda e: e.name):
            if ep.name in names:
                unavailable.append(Unavailable(ep.name, f"duplicate name (from {ep.value})"))
                continue
            if not _is_builtin(ep) and ep.name not in allowed:
                unavailable.append(
                    Unavailable(ep.name, f"third-party plugin; add it to {PLUGINS_ENV} to load it")
                )
                continue
            try:
                module = _load(ep)
            except ImportError as exc:
                missing = exc.name or str(exc)
                unavailable.append(Unavailable(ep.name, f"missing dependency: {missing}"))
                continue
            except Exception as exc:
                unavailable.append(Unavailable(ep.name, f"failed to load: {exc}"))
                continue
            names.add(ep.name)
            modules.append(module)
        return cls(modules, unavailable)

    def get(self, name: str) -> Module:
        try:
            return self._modules[name]
        except KeyError:
            raise UnknownModuleError(f"unknown module: {name}") from None

    def reason_unavailable(self, name: str) -> str | None:
        return next((u.reason for u in self.unavailable if u.name == name), None)

    @property
    def modules(self) -> list[Module]:
        return [self._modules[name] for name in sorted(self._modules)]

    def accepting(self, kind: Kind) -> list[Module]:
        return [m for m in self.modules if kind in m.spec.accepts]

    def __iter__(self) -> Iterator[Module]:
        return iter(self.modules)

    def __len__(self) -> int:
        return len(self._modules)


def _allow_from_env() -> list[str]:
    return [name.strip() for name in os.environ.get(PLUGINS_ENV, "").split(",") if name.strip()]


def _is_builtin(ep: EntryPoint) -> bool:
    return ep.dist is not None and ep.dist.name == BUILTIN_DISTRIBUTION


def _load(ep: EntryPoint) -> Module:
    obj = ep.load()
    instance = obj() if isinstance(obj, type) else obj
    spec = getattr(type(instance), "spec", None)
    if not isinstance(spec, ModuleSpec):
        raise TypeError(f"{ep.value} has no ModuleSpec 'spec' class attribute")
    if spec.name != ep.name:
        raise TypeError(f"{ep.value} declares name {spec.name!r}, registered as {ep.name!r}")
    if not inspect.iscoroutinefunction(getattr(instance, "run", None)):
        raise TypeError(f"{ep.value}.run must be an async function")
    return cast(Module, instance)
