#!/usr/bin/env python3
"""Sample PwdVault process RSS, CPU, threads, FDs and loopback sockets."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.phase5.common import utc_now, write_json  # type: ignore
else:
    from .common import utc_now, write_json


def command_output(command: list[str]) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=3, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def sample(pid: int) -> dict[str, object]:
    ps_fields = command_output(["ps", "-o", "rss=,pcpu=", "-p", str(pid)]).strip().split()
    rss_kib = int(ps_fields[0]) if ps_fields else None
    cpu_percent = float(ps_fields[1]) if len(ps_fields) > 1 else None
    if sys.platform == "darwin":
        thread_lines = command_output(["ps", "-M", str(pid)]).splitlines()
        threads = max(0, len(thread_lines) - 1) if thread_lines else None
    else:
        task_dir = Path(f"/proc/{pid}/task")
        threads = len(list(task_dir.iterdir())) if task_dir.is_dir() else None
    lsof = command_output(["lsof", "-nP", "-p", str(pid)])
    lsof_lines = lsof.splitlines()
    fds = max(0, len(lsof_lines) - 1) if lsof_lines else None
    port_sockets = sum("TCP" in line and ":17429" in line for line in lsof_lines)
    return {
        "timestamp": utc_now(),
        "rss_kib": rss_kib,
        "cpu_percent": cpu_percent,
        "threads": threads,
        "open_files": fds,
        "port_17429_sockets": port_sockets,
        "alive": process_exists(pid),
    }


def summarize(samples: list[dict[str, object]], pid: int) -> dict[str, object]:
    def numeric(field: str) -> list[float]:
        return [float(item[field]) for item in samples if isinstance(item.get(field), (int, float))]

    return {
        "suite": "process-monitor",
        "status": "PASS" if samples and all(item["alive"] for item in samples) else "FAIL",
        "pid": pid,
        "samples": samples,
        "summary": {
            field: {
                "first": values[0] if values else None,
                "max": max(values) if values else None,
                "last": values[-1] if values else None,
            }
            for field in ("rss_kib", "cpu_percent", "threads", "open_files", "port_17429_sockets")
            if (values := numeric(field)) is not None
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.pid <= 1 or args.duration <= 0 or args.interval <= 0:
        parser.error("invalid PID/duration/interval")
    samples: list[dict[str, object]] = []
    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        samples.append(sample(args.pid))
        if not samples[-1]["alive"]:
            break
        time.sleep(min(args.interval, max(0, deadline - time.monotonic())))
    result = summarize(samples, args.pid)
    write_json(args.output, result)
    print(f"process monitor: {result['status']} ({len(samples)} samples)")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
