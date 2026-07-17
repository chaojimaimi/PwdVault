#!/usr/bin/env python3
"""Evaluate attack-window process metrics against an idle baseline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.phase5.common import write_json  # type: ignore
else:
    from .common import write_json

RSS_PEAK_DELTA_KIB = 128 * 1024
RSS_RECOVERY_DELTA_KIB = 32 * 1024
THREAD_PEAK_DELTA = 16
FD_RECOVERY_DELTA = 10


def metric(payload: dict[str, Any], name: str, point: str) -> float | None:
    value = payload.get("summary", {}).get(name, {}).get(point)
    return float(value) if isinstance(value, (int, float)) else None


def check_delta(
    checks: list[dict[str, object]],
    name: str,
    baseline: float | None,
    observed: float | None,
    maximum_delta: float,
) -> None:
    if baseline is None or observed is None:
        checks.append({"name": name, "status": "BLOCKED", "reason": "metric unavailable"})
        return
    delta = observed - baseline
    checks.append(
        {
            "name": name,
            "status": "PASS" if delta <= maximum_delta else "FAIL",
            "baseline": baseline,
            "observed": observed,
            "delta": delta,
            "maximum_delta": maximum_delta,
        }
    )


def evaluate(baseline: dict[str, Any], attack: dict[str, Any]) -> dict[str, object]:
    checks: list[dict[str, object]] = []
    check_delta(
        checks,
        "thread_peak_delta",
        metric(baseline, "threads", "last"),
        metric(attack, "threads", "max"),
        THREAD_PEAK_DELTA,
    )
    check_delta(
        checks,
        "rss_peak_delta_kib",
        metric(baseline, "rss_kib", "last"),
        metric(attack, "rss_kib", "max"),
        RSS_PEAK_DELTA_KIB,
    )
    check_delta(
        checks,
        "rss_recovery_delta_kib",
        metric(baseline, "rss_kib", "last"),
        metric(attack, "rss_kib", "last"),
        RSS_RECOVERY_DELTA_KIB,
    )
    check_delta(
        checks,
        "fd_recovery_delta",
        metric(baseline, "open_files", "last"),
        metric(attack, "open_files", "last"),
        FD_RECOVERY_DELTA,
    )
    alive = bool(attack.get("samples")) and all(sample.get("alive") for sample in attack["samples"])
    checks.append({"name": "process_alive", "status": "PASS" if alive else "FAIL"})

    statuses = {str(check["status"]) for check in checks}
    status = "FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses else "PASS"
    return {"suite": "resource-thresholds", "status": status, "checks": checks}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--attack", required=True, type=Path)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        attack = json.loads(args.attack.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 2
    result = evaluate(baseline, attack)
    write_json(args.output, result)
    print(f"resource thresholds: {result['status']}")
    if result["status"] == "PASS":
        return 0
    return 2 if result["status"] == "BLOCKED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
