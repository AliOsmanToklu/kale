"""Render a ``ModuleResult`` as text for people or JSON for programs."""

from __future__ import annotations

import json

from pydantic import JsonValue

from kale.core import ModuleResult, Severity

# Findings quote attacker-controlled data (log usernames, strings from malware samples).
# Control characters could rewrite the terminal (ANSI escape sequences, carriage returns
# that hide a line), so everything but tab and newline is replaced before printing.
_CONTROL = {i: "?" for i in (*range(0x20), *range(0x7F, 0xA0)) if i not in (0x09, 0x0A)}
_INDENT = "    "


def clean(text: str) -> str:
    return text.translate(_CONTROL)


def render_json(result: ModuleResult) -> str:
    return result.model_dump_json(indent=2) + "\n"


def render_text(result: ModuleResult) -> str:
    lines = [
        f"{result.module} {result.module_version} | {result.target} | {result.duration:.1f} s",
    ]
    if result.error:
        lines.append(f"ERROR ({result.error.code}): {result.error.message}")
    if result.summary:
        lines.append("Summary: " + "; ".join(f"{k}={_value(v)}" for k, v in result.summary.items()))

    counts = [f"{result.count(s)} {s}" for s in Severity if result.count(s)]
    lines.append("")
    lines.append(f"Findings: {', '.join(counts) if counts else 'none'}")
    for finding in result.findings:
        lines.append("")
        lines.append(f"[{finding.severity.upper()}] {finding.title}")
        lines.append(f"{_INDENT}rule: {finding.rule_id}")
        if finding.description:
            lines.append(f"{_INDENT}{finding.description}")
        if finding.recommendation:
            lines.append(f"{_INDENT}Fix: {finding.recommendation}")
        lines.extend(f"{_INDENT}See: {ref}" for ref in finding.references)

    if result.observables:
        lines.append("")
        lines.append(f"Observables ({len(result.observables)}):")
        lines.extend(f"{_INDENT}{o}" for o in result.observables)
    return clean("\n".join(lines)) + "\n"


def _value(value: JsonValue) -> str:
    if isinstance(value, list) and all(not isinstance(v, list | dict) for v in value):
        return ", ".join(str(v) for v in value) or "-"
    if isinstance(value, list | dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)
