from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

BASE = datetime(2026, 10, 25, 11, 0, 0)


def sshd(offset: int, message: str) -> str:
    """An auth.log line with an RFC 3339 timestamp, so no year has to be guessed."""
    return f"{(BASE + timedelta(seconds=offset)).isoformat()} srv sshd[1]: {message}"


@pytest.fixture
def ssh_log(tmp_path: Path) -> Path:
    """12 failures and a login from one address, 3 unknown users from another."""
    lines = [
        sshd(i, f"Failed password for root from 203.0.113.45 port {40000 + i} ssh2")
        for i in range(12)
    ]
    lines.append(sshd(30, "Accepted password for root from 203.0.113.45 port 40100 ssh2"))
    lines += [
        sshd(40 + i, f"Invalid user oracle from 198.51.100.7 port {5000 + i}") for i in range(3)
    ]
    lines.append(sshd(50, "pam_unix(sshd:session): session opened for user root"))
    path = tmp_path / "auth.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def windows_csv(tmp_path: Path) -> Path:
    rows = ["Time,Id,User,IP"]
    rows += [f"2026-10-25 13:00:{i:02d},4625,administrator,203.0.113.99" for i in range(15)]
    rows.append("2026-10-25 13:01:00,4624,administrator,203.0.113.99")
    rows.append("2026-10-25 13:02:00,4624,alice,127.0.0.1")
    path = tmp_path / "logons.csv"
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path
