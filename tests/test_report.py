from __future__ import annotations

import json
from datetime import UTC, datetime

from kale.core import ErrorCode, Finding, Kind, ModuleError, ModuleResult, Observable, Severity
from kale.report import clean, render_json, render_text

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)


def result(**kwargs: object) -> ModuleResult:
    fields: dict[str, object] = {
        "module": "logs.auth",
        "module_version": "0.1.0",
        "target": Observable(kind=Kind.FILE, value="auth.log"),
        "started_at": NOW,
        "finished_at": NOW,
    }
    fields.update(kwargs)
    return ModuleResult.model_validate(fields)


def test_text_report() -> None:
    text = render_text(
        result(
            findings=(
                Finding(
                    rule_id="logs.auth.brute_force",
                    severity=Severity.HIGH,
                    title="Brute force from 203.0.113.45",
                    description="40 failed logins.",
                    recommendation="Block it.",
                    references=("https://attack.mitre.org/techniques/T1110/",),
                ),
                Finding(rule_id="logs.auth.no_events", severity=Severity.INFO, title="Quiet"),
            ),
            observables=(Observable(kind=Kind.IP, value="203.0.113.45"),),
            summary={"total": 66, "users": ["a", "b"], "empty": [], "nested": [{"k": "ü"}]},
        )
    )
    assert text.splitlines()[0] == "logs.auth 0.1.0 | file:auth.log | 0.0 s"
    assert 'Summary: total=66; users=a, b; empty=-; nested=[{"k": "ü"}]' in text
    assert "Findings: 1 high, 1 info" in text
    assert "[HIGH] Brute force from 203.0.113.45" in text
    assert "    Fix: Block it." in text
    assert "    See: https://attack.mitre.org/techniques/T1110/" in text
    assert "Observables (1):\n    ip:203.0.113.45" in text


def test_text_report_with_error_and_no_findings() -> None:
    text = render_text(
        result(error=ModuleError(code=ErrorCode.INVALID_INPUT, message="not a file"))
    )
    assert "ERROR (invalid_input): not a file" in text
    assert "Findings: none" in text
    assert "Summary" not in text


def test_terminal_control_characters_are_neutralized() -> None:
    hostile = "root\x1b[2J\x1b]0;pwned\x07\rfake\x9b"
    finding = Finding(rule_id="logs.auth.x", severity=Severity.LOW, title=hostile)
    text = render_text(result(findings=(finding,)))
    assert "\x1b" not in text and "\r" not in text and "\x9b" not in text
    assert clean("a\tb\nc\x00") == "a\tb\nc?"


def test_json_report_round_trips() -> None:
    original = result(summary={"n": 1})
    text = render_json(original)
    assert json.loads(text)["module"] == "logs.auth"
    assert ModuleResult.model_validate_json(text) == original
