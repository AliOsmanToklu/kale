"""``kale investigate``: run every module that accepts an observable, then follow what
the modules find.

The walk is breadth-first from the target, ``depth`` hops deep. Every value is analyzed
once, however many modules mention it. Active modules only ever see observables inside
the scope: a value another module discovered (a C2 address in a malware sample, a
subdomain in CT logs) is never scanned just because it came up, and the run is recorded
as skipped instead.
"""

from __future__ import annotations

import asyncio
from collections.abc import Collection, Mapping
from datetime import UTC, datetime

from kale.core.engine import run_module
from kale.core.errors import InvalidInputError, OutOfScopeError
from kale.core.models import Investigation, ModuleResult, Observable, Skipped
from kale.core.module import Module
from kale.core.registry import Registry
from kale.core.scope import Scope

MAX_DEPTH = 5
OUT_OF_SCOPE = "outside the authorized scope"


def in_scope(scope: Scope | None, observable: Observable) -> bool:
    if scope is None or scope.empty:
        return False
    try:
        scope.check(observable)
    except (OutOfScopeError, InvalidInputError):
        return False
    return True


def check_options(registry: Registry, options: Mapping[str, Mapping[str, str]]) -> None:
    """Fail before anything runs when an option names an unknown module or setting."""
    for name, values in options.items():
        spec = registry.get(name).spec
        unknown = sorted(set(values) - set(spec.options))
        if unknown:
            raise InvalidInputError(
                f"unknown option(s) for {name}: {', '.join(unknown)} "
                f"(available: {', '.join(spec.options) or 'none'})"
            )


async def investigate(
    registry: Registry,
    target: Observable,
    *,
    depth: int = 2,
    scope: Scope | None = None,
    modules: Collection[str] | None = None,
    options: Mapping[str, Mapping[str, str]] | None = None,
    max_runs: int = 50,
    concurrency: int = 4,
    lang: str = "en",
    environ: Mapping[str, str] | None = None,
) -> Investigation:
    if not 0 <= depth <= MAX_DEPTH:
        raise InvalidInputError(f"depth must be between 0 and {MAX_DEPTH}")
    if max_runs < 1:
        raise InvalidInputError("max_runs must be at least 1")
    options = options or {}
    for name in modules or ():
        registry.get(name)  # UnknownModuleError for a typo, before anything runs
    check_options(registry, options)

    started = datetime.now(UTC)
    gate = asyncio.Semaphore(concurrency)
    seen = {target.key}
    frontier = [target]
    runs: list[ModuleResult] = []
    skipped: list[Skipped] = []
    truncated = False

    async def run(module: Module, observable: Observable) -> ModuleResult:
        async with gate:
            return await run_module(
                module,
                observable,
                options=options.get(module.spec.name),
                scope=scope,
                lang=lang,
                environ=environ,
            )

    for level in range(depth + 1):
        planned: list[tuple[Module, Observable]] = []
        for observable in frontier:
            for module in registry.accepting(observable.kind):
                if modules is not None and module.spec.name not in modules:
                    continue
                if module.spec.active and not in_scope(scope, observable):
                    skipped.append(
                        Skipped(module=module.spec.name, target=observable, reason=OUT_OF_SCOPE)
                    )
                    continue
                if len(runs) + len(planned) >= max_runs:
                    truncated = True
                    break
                planned.append((module, observable))
        results = await asyncio.gather(*(run(m, o) for m, o in planned))
        runs.extend(results)
        if level == depth or truncated:
            break
        frontier = []
        for result in results:
            for observable in result.observables:
                if observable.key not in seen:
                    seen.add(observable.key)
                    frontier.append(observable)
        if not frontier:
            break

    return Investigation(
        target=target,
        depth=depth,
        started_at=started,
        finished_at=datetime.now(UTC),
        runs=tuple(runs),
        skipped=tuple(skipped),
        truncated=truncated,
    )
