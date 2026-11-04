"""Run one module against one target. Every failure becomes part of the result.

The order of the guards matters: nothing reaches a module unless its kind is accepted,
an active module's target is inside the scope, its secrets are present and its options
are valid. A module that hangs is cancelled at its timeout; a module that crashes is
reported, never propagated, so one bad module cannot take down a larger run.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime

from kale.core.errors import (
    InvalidInputError,
    KaleError,
    MissingSecretError,
    ModuleTimeoutError,
    OutOfScopeError,
)
from kale.core.models import (
    ErrorCode,
    Finding,
    ModuleError,
    ModuleOutput,
    ModuleResult,
    Observable,
)
from kale.core.module import Module, ModuleSpec, RunContext, resolve_options
from kale.core.scope import Scope

log = logging.getLogger(__name__)


async def run_module(
    module: Module,
    target: Observable,
    *,
    options: Mapping[str, str] | None = None,
    scope: Scope | None = None,
    lang: str = "en",
    environ: Mapping[str, str] | None = None,
) -> ModuleResult:
    spec = module.spec
    started = datetime.now(UTC)
    output = ModuleOutput()
    error: ModuleError | None = None
    try:
        env = os.environ if environ is None else environ
        ctx = _prepare(spec, target, options or {}, scope, lang, env)
        output = await _execute(module, target, ctx)
    except KaleError as exc:
        error = ModuleError(code=exc.code, message=str(exc))
    except Exception as exc:
        log.exception("module %s failed on %s", spec.name, target)
        error = ModuleError(code=ErrorCode.FAILED, message=f"{type(exc).__name__}: {exc}")

    findings = tuple(
        sorted(
            (_stamp_finding(f, spec.name) for f in output.findings),
            key=lambda f: (f.severity.rank, f.rule_id),
        )
    )
    discovered = [*output.observables, *(o for f in findings for o in f.observables)]
    return ModuleResult(
        module=spec.name,
        module_version=spec.version,
        target=target,
        started_at=started,
        finished_at=datetime.now(UTC),
        findings=findings,
        observables=_unique(_stamp(discovered, spec.name), exclude=target),
        summary=output.summary,
        error=error,
    )


def _prepare(
    spec: ModuleSpec,
    target: Observable,
    raw_options: Mapping[str, str],
    scope: Scope | None,
    lang: str,
    environ: Mapping[str, str],
) -> RunContext:
    if target.kind not in spec.accepts:
        accepted = ", ".join(sorted(spec.accepts))
        raise InvalidInputError(f"{spec.name} accepts {accepted}, not {target.kind}")
    if spec.active:
        if scope is None or scope.empty:
            raise OutOfScopeError(
                f"{spec.name} sends traffic to the target; list the targets you are "
                "authorized to test in a scope"
            )
        scope.check(target)
    missing = sorted(name for name in spec.secrets if not environ.get(name))
    if missing:
        raise MissingSecretError(f"{spec.name} needs environment variable(s): {', '.join(missing)}")
    return RunContext(
        options=resolve_options(spec, raw_options),
        secrets={name: environ[name] for name in spec.secrets},
        lang=lang,
        allow_private=scope.allow_private if scope else False,
    )


async def _execute(module: Module, target: Observable, ctx: RunContext) -> ModuleOutput:
    deadline = asyncio.timeout(module.spec.timeout)
    try:
        async with deadline:
            output = await module.run(target, ctx)
    except TimeoutError:
        if deadline.expired():
            raise ModuleTimeoutError(f"timed out after {module.spec.timeout:g}s") from None
        raise  # a timeout inside the module (e.g. a socket) is an ordinary failure
    if not isinstance(output, ModuleOutput):
        raise TypeError(f"run() returned {type(output).__name__}, expected ModuleOutput")
    return output


def _stamp(observables: Iterable[Observable], source: str) -> list[Observable]:
    return [o if o.source else o.model_copy(update={"source": source}) for o in observables]


def _stamp_finding(finding: Finding, source: str) -> Finding:
    if all(o.source for o in finding.observables):
        return finding
    return finding.model_copy(update={"observables": tuple(_stamp(finding.observables, source))})


def _unique(observables: Iterable[Observable], *, exclude: Observable) -> tuple[Observable, ...]:
    seen = {exclude.key}
    unique: list[Observable] = []
    for observable in observables:
        if observable.key not in seen:
            seen.add(observable.key)
            unique.append(observable)
    return tuple(unique)
