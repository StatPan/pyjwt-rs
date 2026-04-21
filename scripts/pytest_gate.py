#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / ".quality" / "pytest-allowlist.json"


def load_allowlist() -> list[dict[str, str]]:
    if not ALLOWLIST.exists():
        return []
    data = json.loads(ALLOWLIST.read_text())
    skips = data.get("skips", [])
    if not isinstance(skips, list):
        raise RuntimeError("allowlist 'skips' must be a list")
    normalized: list[dict[str, str]] = []
    for item in skips:
        if not isinstance(item, dict):
            raise RuntimeError("allowlist skip entries must be objects")
        normalized.append(
            {
                "nodeid": str(item.get("nodeid", "")),
                "reason_contains": str(item.get("reason_contains", "")),
            }
        )
    return normalized


def skip_reason(longrepr: Any) -> str:
    if hasattr(longrepr, "reprcrash") and getattr(longrepr.reprcrash, "message", None):
        return str(longrepr.reprcrash.message)
    if isinstance(longrepr, tuple) and len(longrepr) >= 3:
        return str(longrepr[2])
    return str(longrepr)


class SkipTracker:
    def __init__(self) -> None:
        self.skips: list[dict[str, str]] = []

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        if report.outcome != "skipped" or report.when not in {"setup", "call"}:
            return
        self.skips.append(
            {
                "nodeid": report.nodeid,
                "reason": skip_reason(report.longrepr),
            }
        )


def is_allowed_skip(skip: dict[str, str], allowlist: list[dict[str, str]]) -> bool:
    for allowed in allowlist:
        nodeid = allowed["nodeid"]
        reason = allowed["reason_contains"]
        if nodeid and nodeid != skip["nodeid"]:
            continue
        if reason and reason not in skip["reason"]:
            continue
        return True
    return False


def main(argv: list[str]) -> int:
    tracker = SkipTracker()
    allowlist = load_allowlist()
    pytest_args = ["-q", "-W", "error", *argv]
    exit_code = pytest.main(pytest_args, plugins=[tracker])
    if exit_code != 0:
        return int(exit_code)

    unexpected_skips = [skip for skip in tracker.skips if not is_allowed_skip(skip, allowlist)]
    if not unexpected_skips:
        return 0

    print("\nunexpected skips detected:", file=sys.stderr)
    for skip in unexpected_skips:
        print(f"- {skip['nodeid']}: {skip['reason']}", file=sys.stderr)
    print(
        "\nAdd an explicit entry to .quality/pytest-allowlist.json or remove the skip.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
