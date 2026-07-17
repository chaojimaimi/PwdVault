#!/usr/bin/env python3
"""Aggregate Phase 5 JSON outputs into a sanitized Markdown release report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.phase5.common import redact, utc_now, write_json  # type: ignore
else:
    from .common import redact, utc_now, write_json


def discover_results(root: Path) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for path in sorted(root.rglob("*.json")):
        if path.name in {"summary.json"}:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and isinstance(payload.get("status"), str):
            payload["source"] = str(path.relative_to(root))
            results.append(payload)
    return results


def aggregate(results: list[dict[str, object]], mode: str) -> dict[str, object]:
    statuses = [str(result.get("status", "BLOCKED")) for result in results]
    if "FAIL" in statuses:
        status = "FAIL"
    elif "BLOCKED" in statuses:
        status = "BLOCKED"
    elif statuses and all(value in {"PASS", "SKIP"} for value in statuses):
        status = "PASS"
    else:
        status = "BLOCKED"
    return {
        "suite": "phase5-gate",
        "mode": mode,
        "status": status,
        "generated_at": utc_now(),
        "results": results,
    }


def markdown(summary: dict[str, object]) -> str:
    lines = [
        "# Phase 5 Gate Report",
        "",
        f"- Mode: `{summary['mode']}`",
        f"- Status: **{summary['status']}**",
        f"- Generated: `{summary['generated_at']}`",
        "- Windows: **DEFERRED**",
        "",
        "| Suite | Status | Source |",
        "|---|---|---|",
    ]
    for result in summary["results"]:  # type: ignore[index]
        suite = redact(str(result.get("suite", "unknown")))
        status = str(result.get("status", "BLOCKED"))
        source = str(result.get("source", ""))
        lines.append(f"| {suite} | {status} | `{source}` |")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `PASS` means every included automated suite passed.",
            "- `BLOCKED` means required runtime/browser evidence was unavailable; it is not a pass.",
            "- A macOS pass must still be reported as **Windows deferred**, not cross-platform complete.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--mode", choices=("fast", "release-macos"), required=True)
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--markdown-output", required=True)
    args = parser.parse_args()
    summary = aggregate(discover_results(args.input), args.mode)
    write_json(args.json_output, summary)
    Path(args.markdown_output).write_text(markdown(summary), encoding="utf-8")
    print(f"phase5 report: {summary['status']} ({len(summary['results'])} suites)")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
