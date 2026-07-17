#!/usr/bin/env python3
"""Raw HTTP rejection probe for the PwdVault loopback bridge."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.phase5.common import (  # type: ignore
        CHROME_TEST_CALLER,
        DEFAULT_HOST,
        DEFAULT_PORT,
        CaseResult,
        SuiteResult,
        require_loopback,
        suite_status,
        utc_now,
        write_json,
    )
else:
    from .common import (
        CHROME_TEST_CALLER,
        DEFAULT_HOST,
        DEFAULT_PORT,
        CaseResult,
        SuiteResult,
        require_loopback,
        suite_status,
        utc_now,
        write_json,
    )

MAX_RESPONSE_BYTES = 1024 * 1024 + 64 * 1024


@dataclass(frozen=True)
class ProbeCase:
    case_id: str
    request: bytes
    expected_status: int | None = None
    expected_text: bytes | None = None


def json_body(command: str = "handshake", protocol_version: int | None = 1) -> bytes:
    payload: dict[str, object] = {"id": 1, "command": command}
    if protocol_version is not None:
        payload["protocol_version"] = protocol_version
    return json.dumps(payload, separators=(",", ":")).encode()


def http_request(
    *,
    method: str = "POST",
    path: str = "/api/handshake",
    body: bytes | None = None,
    content_type: str | None = "application/json",
    content_length: int | None = None,
    origin: str | None = CHROME_TEST_CALLER,
    caller: str | None = CHROME_TEST_CALLER,
) -> bytes:
    body = json_body() if body is None else body
    headers = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1:17429", "Connection: close"]
    if content_type is not None:
        headers.append(f"Content-Type: {content_type}")
    if content_length is not None:
        headers.append(f"Content-Length: {content_length}")
    elif body:
        headers.append(f"Content-Length: {len(body)}")
    if origin is not None:
        headers.append(f"Origin: {origin}")
    if caller is not None:
        headers.append(f"X-PwdVault-Caller: {caller}")
    return ("\r\n".join(headers) + "\r\n\r\n").encode() + body


def default_cases() -> list[ProbeCase]:
    valid = json_body()
    missing_version = json_body(protocol_version=None)
    wrong_version = json_body(protocol_version=2)
    unknown = json_body(command="unknown_phase5_command")
    return [
        ProbeCase("HTTP-00", http_request(), 200, b'"success":true'),
        ProbeCase("HTTP-01", http_request(method="GET"), 405),
        ProbeCase("HTTP-02", http_request(content_type=None), 415),
        ProbeCase("HTTP-03", http_request(content_type="text/plain"), 415),
        ProbeCase("HTTP-04", http_request(body=b"", content_length=None), 411),
        ProbeCase("HTTP-05", http_request(body=b"", content_length=0), 411),
        ProbeCase("HTTP-06", http_request(body=valid, content_length=len(valid) - 1), None, b"Invalid request"),
        ProbeCase("HTTP-07", http_request(body=b"", content_length=10 * 1024 * 1024 + 1), None, b"Request too large"),
        ProbeCase("HTTP-08", http_request(body=b"{"), None, b"Invalid request"),
        ProbeCase("HTTP-09", http_request(body=missing_version), None, b"Unsupported protocol version"),
        ProbeCase("HTTP-10", http_request(body=wrong_version), None, b"Unsupported protocol version"),
        ProbeCase("HTTP-11", http_request(path="/api/not-handshake"), 404),
        ProbeCase("HTTP-12", http_request(origin=None), None, b"Forbidden"),
        ProbeCase(
            "HTTP-13",
            http_request(path="/api/pair", body=json_body(command="pair"), caller=None),
            None,
            b"Browser caller required",
        ),
        ProbeCase(
            "HTTP-14",
            http_request(path="/api/is_vault_initialized", body=json_body(command="is_vault_initialized")),
            None,
            b"Unauthorized",
        ),
        # Protected commands are authenticated before dispatch. Without a test
        # token, an unknown command must not reveal whether that command exists.
        ProbeCase("HTTP-15", http_request(path="/api/unknown_phase5_command", body=unknown), None, b"Unauthorized"),
    ]


def parse_status(response: bytes) -> int | None:
    try:
        first_line = response.split(b"\r\n", 1)[0]
        return int(first_line.split()[1])
    except (IndexError, ValueError):
        return None


def stale_phase5_runtime(response: bytes, status_ok: bool, text_ok: bool) -> bool:
    if status_ok and text_ok:
        return False
    preview = response[-1024:]
    return b"Unauthorized" in preview or b'"protocol_version":1' not in preview


def send_raw(host: str, port: int, request: bytes, timeout: float) -> tuple[bytes, float]:
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(request)
        response = bytearray()
        while len(response) <= MAX_RESPONSE_BYTES:
            try:
                chunk = connection.recv(min(65536, MAX_RESPONSE_BYTES + 1 - len(response)))
            except socket.timeout:
                break
            if not chunk:
                break
            response.extend(chunk)
        if len(response) > MAX_RESPONSE_BYTES:
            raise RuntimeError("response exceeded probe safety limit")
    return bytes(response), (time.perf_counter() - started) * 1000


def run(host: str, port: int, timeout: float) -> SuiteResult:
    address = require_loopback(host)
    started_at = utc_now()
    suite_started = time.perf_counter()
    cases: list[CaseResult] = []
    matrix = default_cases()
    for index, case in enumerate(matrix):
        try:
            response, elapsed = send_raw(address, port, case.request, timeout)
            status = parse_status(response)
            status_ok = case.expected_status is None or status == case.expected_status
            text_ok = case.expected_text is None or case.expected_text in response
            cases.append(
                CaseResult(
                    case.case_id,
                    "PASS" if status_ok and text_ok else "FAIL",
                    f"status={case.expected_status or 'any'} text={case.expected_text!r}",
                    f"status={status} bytes={len(response)}",
                    elapsed,
                    {"response_preview": response[-512:].decode("utf-8", errors="replace")},
                )
            )
            if index == 0 and not (status_ok and text_ok):
                if stale_phase5_runtime(response, status_ok, text_ok):
                    cases[-1].status = "BLOCKED"
                    cases[-1].actual = (
                        "running desktop does not expose the Phase 5 handshake; "
                        "rebuild/restart PwdVault before probing"
                    )
                    break
        except (ConnectionError, OSError) as error:
            cases.append(CaseResult(case.case_id, "BLOCKED", "running loopback bridge", str(error)))
            break
        except Exception as error:  # probe must record failures, not hide them
            cases.append(CaseResult(case.case_id, "FAIL", "bounded response", str(error)))
    return SuiteResult(
        "native-bridge-probe",
        started_at,
        (time.perf_counter() - suite_started) * 1000,
        suite_status(cases),
        cases,
        {"host": address, "port": port, "timeout_seconds": timeout},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = run(args.host, args.port, args.timeout)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    write_json(args.output, result.to_dict())
    print(f"native bridge probe: {result.status} ({len(result.cases)} cases)")
    if result.status == "PASS":
        return 0
    return 2 if result.status == "BLOCKED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
