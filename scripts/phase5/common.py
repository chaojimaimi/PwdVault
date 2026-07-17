#!/usr/bin/env python3
"""Shared, dependency-free helpers for Phase 5 release validation."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import statistics
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 17429
PROTOCOL_VERSION = 1
CHROME_TEST_CALLER = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
TOKEN_PATTERN = re.compile(r"(?i)(bearer\s+)[0-9a-f]{32,}|\b[0-9a-f]{64}\b")


def require_loopback(host: str) -> str:
    """Return a numeric loopback address or reject the target."""
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror as error:
        raise ValueError(f"cannot resolve target host: {host}") from error
    if not addresses:
        raise ValueError(f"target host has no addresses: {host}")
    for address in addresses:
        normalized = address.split("%", 1)[0]
        if not ipaddress.ip_address(normalized).is_loopback:
            raise ValueError(f"refusing non-loopback target: {host} -> {address}")
    return sorted(addresses)[0]


def redact(value: str) -> str:
    return TOKEN_PATTERN.sub(lambda match: f"{match.group(1) if match.lastindex else ''}<redacted>", value)


def percentile(values: Iterable[float], percentile_value: float) -> float | None:
    samples = sorted(values)
    if not samples:
        return None
    if len(samples) == 1:
        return samples[0]
    index = (len(samples) - 1) * percentile_value
    lower = int(index)
    upper = min(lower + 1, len(samples) - 1)
    fraction = index - lower
    return samples[lower] + (samples[upper] - samples[lower]) * fraction


@dataclass
class CaseResult:
    case_id: str
    status: str
    expected: str
    actual: str
    elapsed_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)

    def sanitized(self) -> dict[str, Any]:
        data = asdict(self)
        data["actual"] = redact(data["actual"])
        data["details"] = json.loads(redact(json.dumps(data["details"], default=str)))
        return data


@dataclass
class SuiteResult:
    suite: str
    started_at: str
    duration_ms: float
    status: str
    cases: list[CaseResult]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "started_at": self.started_at,
            "duration_ms": round(self.duration_ms, 3),
            "status": self.status,
            "metadata": self.metadata,
            "cases": [case.sanitized() for case in self.cases],
        }


def suite_status(cases: Iterable[CaseResult]) -> str:
    statuses = {case.status for case in cases}
    if "FAIL" in statuses:
        return "FAIL"
    if "BLOCKED" in statuses:
        return "BLOCKED"
    if statuses and statuses <= {"PASS", "SKIP"}:
        return "PASS"
    return "BLOCKED"


def write_json(path: str | Path, payload: Any) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(destination)


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def latency_summary(values_ms: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values_ms),
        "min_ms": round(min(values_ms), 3) if values_ms else None,
        "mean_ms": round(statistics.fmean(values_ms), 3) if values_ms else None,
        "p50_ms": round(percentile(values_ms, 0.50), 3) if values_ms else None,
        "p95_ms": round(percentile(values_ms, 0.95), 3) if values_ms else None,
        "max_ms": round(max(values_ms), 3) if values_ms else None,
    }
