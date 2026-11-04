"""``kale`` command line: ``modules``, ``run``, ``investigate`` and ``schema``.

Exit codes: 0 done, 1 a finding reached ``--fail-on``, 2 usage error, 3 the module (or, for
``investigate``, every module) failed.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError

from kale import __version__
from kale.core import (
    ErrorCode,
    Investigation,
    KaleError,
    Kind,
    Module,
    ModuleResult,
    Observable,
    Registry,
    Scope,
    Severity,
    UnknownModuleError,
    investigate,
    run_module,
)
from kale.core.pipeline import MAX_DEPTH
from kale.report import (
    render_investigation_json,
    render_investigation_text,
    render_json,
    render_text,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_MODULE_ERROR = 3

LANGUAGES = ("en", "tr")
# When a module accepts several kinds, a raw target is tried in this order. SOFTWARE is
# free-form, so it is never guessed: it needs --kind or a module that accepts only it.
_GUESS_ORDER = (Kind.URL, Kind.IP, Kind.HASH, Kind.CVE, Kind.EMAIL, Kind.DOMAIN)


class UsageError(Exception):
    pass


def _key_value(text: str) -> tuple[str, str]:
    key, sep, value = text.partition("=")
    if not sep or not key.strip():
        raise argparse.ArgumentTypeError(f"expected KEY=VALUE, got {text!r}")
    return key.strip(), value


def _add_shared(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="ENTRY",
        help="domain or CIDR you are authorized to test (repeatable)",
    )
    parser.add_argument("--scope-file", type=Path, help="file with one scope entry per line")
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="let active modules reach private/internal addresses in scope",
    )
    parser.add_argument("-f", "--format", choices=("text", "json"), default="text")
    parser.add_argument("-o", "--output", type=Path, help="write the report to this file")
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity if s is not Severity.INFO],
        help="exit with 1 if a finding is at least this severe (for CI)",
    )
    env_lang = os.environ.get("KALE_LANG", "")
    parser.add_argument(
        "--lang",
        choices=LANGUAGES,
        default=env_lang if env_lang in LANGUAGES else "en",
        help="language of module texts, where the module supports it (default: KALE_LANG or en)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kale", description="Modular security toolkit: many tools, one result format."
    )
    parser.add_argument("--version", action="version", version=f"kale {__version__}")
    parser.add_argument("--debug", action="store_true", help="log tracebacks to stderr")
    sub = parser.add_subparsers(dest="command", required=True)

    p_modules = sub.add_parser("modules", help="list modules, or describe one")
    p_modules.add_argument("name", nargs="?", help="module to describe")

    p_run = sub.add_parser(
        "run",
        help="run one module against one target",
        description=(
            "Run a module. Active modules only touch targets listed with --scope or "
            "--scope-file: test only systems you own or have written permission to test."
        ),
    )
    p_run.add_argument("module", help="module name, e.g. logs.auth")
    p_run.add_argument("target", help="file, domain, URL, IP, hash, ...")
    p_run.add_argument("--kind", choices=[k.value for k in Kind], help="type of the target")
    p_run.add_argument(
        "--set",
        dest="options",
        action="append",
        type=_key_value,
        default=[],
        metavar="KEY=VALUE",
        help="module option (repeatable; see 'kale modules NAME')",
    )
    _add_shared(p_run)

    p_inv = sub.add_parser(
        "investigate",
        help="run every applicable module, then follow what they find",
        description=(
            "Run every module that accepts the target, then every module that accepts what "
            "those found, up to --depth hops. Active modules only run on values inside "
            "--scope; everything else they could have touched is listed as skipped."
        ),
    )
    p_inv.add_argument("target", help="file, domain, URL, IP, hash, software, CVE, ...")
    p_inv.add_argument("--kind", choices=[k.value for k in Kind], help="type of the target")
    p_inv.add_argument(
        "--depth",
        type=int,
        choices=range(MAX_DEPTH + 1),
        default=2,
        metavar=f"0-{MAX_DEPTH}",
        help="hops to follow from the target (default: 2)",
    )
    p_inv.add_argument("--modules", help="comma-separated modules to use (default: all)")
    p_inv.add_argument(
        "--max-runs", type=int, default=50, help="stop after this many module runs (default: 50)"
    )
    p_inv.add_argument(
        "--set",
        dest="options",
        action="append",
        type=_key_value,
        default=[],
        metavar="MODULE.OPTION=VALUE",
        help="module option, e.g. vuln.intel.max_findings=3 (repeatable)",
    )
    _add_shared(p_inv)

    p_schema = sub.add_parser("schema", help="print the JSON schema of results")
    p_schema.add_argument(
        "--investigation", action="store_true", help="the schema of investigations instead"
    )
    return parser


def guess_target(value: str, accepts: frozenset[Kind], kind: Kind | None = None) -> Observable:
    """Turn a command-line target into an observable of a kind the module accepts."""
    if kind is not None:
        return _observable(kind, value)
    if Kind.FILE in accepts and Path(value).exists():
        return _observable(Kind.FILE, value)
    candidates: list[Observable] = []
    for candidate in _GUESS_ORDER:
        try:
            candidates.append(Observable(kind=candidate, value=value))
        except ValidationError:
            continue
    for observable in candidates:
        if observable.kind in accepts:
            return observable
    if Kind.SOFTWARE in accepts and not candidates:  # "nginx@1.18.0", "pkg:npm/x@1"
        return _observable(Kind.SOFTWARE, value)
    if len(accepts) == 1:  # e.g. a file that does not exist: let the module say so
        return _observable(next(iter(accepts)), value)
    if candidates:
        return candidates[0]
    raise UsageError(f"cannot tell what kind of target {value!r} is; pass --kind")


def _observable(kind: Kind, value: str) -> Observable:
    try:
        return Observable(kind=kind, value=value)
    except ValidationError as exc:
        reason = exc.errors()[0]["msg"].removeprefix("Value error, ")
        raise UsageError(f"invalid {kind} target: {reason}") from None


def _scope(args: argparse.Namespace) -> Scope | None:
    entries = list(args.scope)
    if args.scope_file:
        try:
            entries += args.scope_file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise UsageError(f"cannot read scope file: {exc.strerror or exc}") from None
    if not entries:
        return None
    try:
        return Scope.parse(entries, allow_private=args.allow_private)
    except KaleError as exc:
        raise UsageError(str(exc)) from None


def _module(registry: Registry, name: str) -> Module:
    try:
        return registry.get(name)
    except UnknownModuleError:
        reason = registry.reason_unavailable(name)
        if reason:
            raise UsageError(f"module {name} is unavailable: {reason}") from None
        raise UsageError(f"unknown module {name!r}; 'kale modules' lists them") from None


def cmd_modules(registry: Registry, name: str | None) -> int:
    if name:
        spec = _module(registry, name).spec
        mode = "active" if spec.active else "passive"
        print(f"{spec.name} {spec.version} ({spec.category}, {mode})")
        print(f"  {spec.summary}")
        print(f"  accepts: {', '.join(sorted(spec.accepts))}")
        print(f"  timeout: {spec.timeout:g} s")
        if spec.secrets:
            print(f"  secrets: {', '.join(sorted(spec.secrets))}")
        if spec.optional_secrets:
            print(f"  optional secrets: {', '.join(sorted(spec.optional_secrets))}")
        if spec.options:
            print("  options (--set KEY=VALUE):")
            width = max(len(n) for n in spec.options)
            for option_name, option in spec.options.items():
                default = json.dumps(option.default)
                print(f"    {option_name:<{width}}  {option.type:<5}  {default:<8}  {option.help}")
        return EXIT_OK

    if registry.modules:
        width = max(len(m.spec.name) for m in registry.modules)
        for module in registry.modules:
            spec = module.spec
            mode = "active" if spec.active else "passive"
            print(f"{spec.name:<{width}}  {mode:<7}  {spec.summary}")
    else:
        print("No modules available.")
    if registry.unavailable:
        print("\nUnavailable:")
        for item in registry.unavailable:
            print(f"  {item.name}: {item.reason}")
    return EXIT_OK


def cmd_run(registry: Registry, args: argparse.Namespace) -> int:
    module = _module(registry, args.module)
    kind = Kind(args.kind) if args.kind else None
    target = guess_target(args.target, module.spec.accepts, kind)
    result = asyncio.run(
        run_module(module, target, options=dict(args.options), scope=_scope(args), lang=args.lang)
    )
    report = render_json(result) if args.format == "json" else render_text(result)
    _write(report, args.output)
    if result.error and (args.output or args.format == "json"):
        print(f"kale: {result.module}: {result.error.message}", file=sys.stderr)
    if result.error and result.error.code is ErrorCode.OUT_OF_SCOPE and not args.scope:
        print(
            f"kale: hint: if you are authorized to test it, add --scope {_host_hint(target)}",
            file=sys.stderr,
        )
    return _exit_code(result, args.fail_on)


def _module_options(pairs: Sequence[tuple[str, str]]) -> dict[str, dict[str, str]]:
    options: dict[str, dict[str, str]] = {}
    for key, value in pairs:
        module, _, option = key.rpartition(".")
        if "." not in module or not option:
            raise UsageError(
                f"expected MODULE.OPTION=VALUE (e.g. vuln.intel.max_findings=3), got {key!r}"
            )
        options.setdefault(module, {})[option] = value
    return options


def cmd_investigate(registry: Registry, args: argparse.Namespace) -> int:
    accepts = frozenset(kind for module in registry.modules for kind in module.spec.accepts)
    kind = Kind(args.kind) if args.kind else None
    target = guess_target(args.target, accepts, kind)
    modules = {n.strip() for n in args.modules.split(",") if n.strip()} if args.modules else None
    scope = _scope(args)
    try:
        result = asyncio.run(
            investigate(
                registry,
                target,
                depth=args.depth,
                scope=scope,
                modules=modules,
                options=_module_options(args.options),
                max_runs=args.max_runs,
                lang=args.lang,
            )
        )
    except KaleError as exc:
        raise UsageError(str(exc)) from None
    if args.format == "json":
        report = render_investigation_json(result)
    else:
        report = render_investigation_text(result)
    _write(report, args.output)
    if result.skipped and scope is None:
        print(
            f"kale: {len(result.skipped)} active run(s) skipped: add --scope with the targets "
            "you are authorized to test to allow them",
            file=sys.stderr,
        )
    return _investigation_exit_code(result, args.fail_on)


def _write(report: str, output: Path | None) -> None:
    if output:
        try:
            output.write_text(report, encoding="utf-8")
        except OSError as exc:
            raise UsageError(f"cannot write {output}: {exc.strerror or exc}") from None
    else:
        sys.stdout.write(report)


def _investigation_exit_code(result: Investigation, fail_on: str | None) -> int:
    if result.runs and not any(run.ok for run in result.runs):
        return EXIT_MODULE_ERROR
    worst = result.worst_severity()
    if fail_on and worst is not None and worst.at_least(Severity(fail_on)):
        return EXIT_FINDINGS
    return EXIT_OK


def _host_hint(target: Observable) -> str:
    if target.kind is Kind.URL:
        return urlsplit(target.value).hostname or target.value
    return target.value


def _exit_code(result: ModuleResult, fail_on: str | None) -> int:
    if result.error:
        return EXIT_MODULE_ERROR
    worst = result.worst_severity()
    if fail_on and worst is not None and worst.at_least(Severity(fail_on)):
        return EXIT_FINDINGS
    return EXIT_OK


def _safe_streams() -> None:
    # On Windows, redirected output defaults to the ANSI code page (cp1254 for Turkish),
    # which mangles reports read as UTF-8 and cannot encode every character. Files and
    # pipes get UTF-8; a console keeps its encoding but never crashes on a character.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            if stream.isatty():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: Sequence[str] | None = None) -> int:
    _safe_streams()
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.CRITICAL,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        if args.command == "schema":
            model = Investigation if args.investigation else ModuleResult
            print(json.dumps(model.model_json_schema(), indent=2))
            return EXIT_OK
        registry = Registry.discover()
        if args.command == "modules":
            return cmd_modules(registry, args.name)
        if args.command == "investigate":
            return cmd_investigate(registry, args)
        return cmd_run(registry, args)
    except UsageError as exc:
        print(f"kale: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
