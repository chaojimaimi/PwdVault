#!/usr/bin/env python3
"""Validate Chrome/Firefox E2E evidence before release-gate aggregation."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.phase5.common import write_json  # type: ignore
else:
    from .common import write_json

REQUIRED_CASES = {f"E2E-{index:02d}" for index in range(1, 17)} | {
    f"SEC-{index:02d}" for index in range(1, 6)
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def validate(payload: dict[str, Any]) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    if payload.get("platform") != "macos":
        checks.append({"status": "FAIL", "message": "platform must be macos"})
    if payload.get("windows") != "DEFERRED":
        checks.append({"status": "FAIL", "message": "windows must be explicitly DEFERRED"})

    browsers = payload.get("browsers")
    if not isinstance(browsers, dict):
        browsers = {}
    for browser in ("chrome", "firefox"):
        evidence = browsers.get(browser)
        if not isinstance(evidence, dict):
            checks.append({"status": "BLOCKED", "message": f"{browser} evidence missing"})
            continue
        if not isinstance(evidence.get("version"), str) or not evidence["version"].strip():
            checks.append({"status": "FAIL", "message": f"{browser} version missing"})
        digest = str(evidence.get("artifact_sha256", ""))
        if not SHA256.fullmatch(digest):
            checks.append({"status": "FAIL", "message": f"{browser} artifact SHA-256 invalid"})
        cases = evidence.get("cases")
        if not isinstance(cases, dict):
            checks.append({"status": "BLOCKED", "message": f"{browser} case map missing"})
            continue
        missing = sorted(REQUIRED_CASES - set(cases))
        if missing:
            checks.append({"status": "BLOCKED", "message": f"{browser} missing cases: {', '.join(missing)}"})
        failures = sorted(case for case in REQUIRED_CASES if cases.get(case) == "FAIL")
        blocked = sorted(case for case in REQUIRED_CASES if cases.get(case) not in {"PASS", "FAIL"})
        if failures:
            checks.append({"status": "FAIL", "message": f"{browser} failed cases: {', '.join(failures)}"})
        if blocked:
            checks.append({"status": "BLOCKED", "message": f"{browser} incomplete cases: {', '.join(blocked)}"})
        if not missing and not failures and not blocked:
            checks.append({"status": "PASS", "message": f"{browser} all required cases passed"})

    statuses = {check["status"] for check in checks}
    status = "FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses else "PASS"
    return {"suite": "browser-e2e", "status": status, "checks": checks}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 2
    result = validate(payload)
    write_json(args.output, result)
    print(f"browser evidence: {result['status']}")
    if result["status"] == "PASS":
        return 0
    return 2 if result["status"] == "BLOCKED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
