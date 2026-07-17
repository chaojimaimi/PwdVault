#!/usr/bin/env python3
"""Process-level Native Messaging frame and caller probe."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.phase5.common import (  # type: ignore
        CHROME_TEST_CALLER,
        DEFAULT_PORT,
        CaseResult,
        SuiteResult,
        suite_status,
        utc_now,
        write_json,
    )
else:
    from .common import (
        CHROME_TEST_CALLER,
        DEFAULT_PORT,
        CaseResult,
        SuiteResult,
        suite_status,
        utc_now,
        write_json,
    )

MAX_FRAME = 10 * 1024 * 1024


def encode_frame(payload: bytes) -> bytes:
    return struct.pack("=I", len(payload)) + payload


def decode_first_frame(stream: bytes) -> bytes:
    if len(stream) < 4:
        raise ValueError("native host produced no complete frame header")
    length = struct.unpack("=I", stream[:4])[0]
    if length > 2 * 1024 * 1024:
        raise ValueError(f"native host output frame unexpectedly large: {length}")
    if len(stream) < 4 + length:
        raise ValueError("native host output frame was truncated")
    return stream[4 : 4 + length]


class FakeBridgeServer:
    def __init__(self, response_body: bytes, inspect_request: Callable[[bytes], None] | None = None):
        self.response_body = response_body
        self.inspect_request = inspect_request
        self.error: Exception | None = None
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, name="phase5-fake-bridge", daemon=True)

    def __enter__(self) -> "FakeBridgeServer":
        self.thread.start()
        if not self.ready.wait(2):
            raise RuntimeError("fake bridge did not start")
        if self.error:
            raise self.error
        return self

    def __exit__(self, *_args: object) -> None:
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("fake bridge did not stop")
        if self.error:
            raise self.error

    def _run(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", DEFAULT_PORT))
                server.listen(1)
                server.settimeout(5)
                self.ready.set()
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(5)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        request.extend(chunk)
                    headers, _, remainder = bytes(request).partition(b"\r\n\r\n")
                    content_length = 0
                    for line in headers.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            content_length = int(line.split(b":", 1)[1].strip())
                    body = bytearray(remainder)
                    while len(body) < content_length:
                        chunk = connection.recv(min(65536, content_length - len(body)))
                        if not chunk:
                            break
                        body.extend(chunk)
                    full_request = headers + b"\r\n\r\n" + bytes(body)
                    if self.inspect_request:
                        self.inspect_request(full_request)
                    response = (
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                        + str(len(self.response_body)).encode()
                        + b"\r\nConnection: close\r\n\r\n"
                        + self.response_body
                    )
                    connection.sendall(response)
        except Exception as error:
            self.error = error
            self.ready.set()


def run_host(binary: Path, args: list[str], stdin: bytes, timeout: float = 8) -> tuple[bytes, str, int, float]:
    started = time.perf_counter()
    process = subprocess.run(
        [str(binary), *args],
        input=stdin,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    elapsed = (time.perf_counter() - started) * 1000
    return process.stdout, process.stderr.decode(errors="replace"), process.returncode, elapsed


def json_payload(version: int | None = 1, **extra: object) -> bytes:
    payload: dict[str, object] = {"id": 7, "command": "handshake", **extra}
    if version is not None:
        payload["protocol_version"] = version
    return json.dumps(payload, separators=(",", ":")).encode()


def response_contains(frame_stream: bytes, expected: bytes) -> tuple[bool, str]:
    payload = decode_first_frame(frame_stream)
    return expected in payload, payload.decode(errors="replace")


def run(binary: Path) -> SuiteResult:
    started_at = utc_now()
    started = time.perf_counter()
    cases: list[CaseResult] = []
    if not binary.is_file():
        cases.append(CaseResult("HOST-00", "BLOCKED", "native host binary exists", str(binary)))
        return SuiteResult("native-host-probe", started_at, 0, "BLOCKED", cases)

    try:
        output, stderr, code, elapsed = run_host(binary, [], b"")
        ok, actual = response_contains(output, b"Missing browser caller identity")
        cases.append(CaseResult("HOST-01", "PASS" if ok else "FAIL", "missing caller rejected", actual, elapsed, {"exit": code, "stderr": stderr}))

        for case_id, version, expected in (
            ("HOST-02", None, b"Missing protocol version"),
            ("HOST-03", 2, b"Unsupported protocol version"),
        ):
            output, stderr, code, elapsed = run_host(
                binary, [CHROME_TEST_CALLER], encode_frame(json_payload(version))
            )
            ok, actual = response_contains(output, expected)
            cases.append(CaseResult(case_id, "PASS" if ok else "FAIL", expected.decode(), actual, elapsed, {"exit": code, "stderr": stderr}))

        observed_request: list[bytes] = []
        normal_response = b'{"id":7,"success":true,"data":{"protocol_version":1}}'
        with FakeBridgeServer(normal_response, observed_request.append):
            spoofed = json_payload(1, origin="moz-extension://attacker")
            output, stderr, code, elapsed = run_host(
                binary, [CHROME_TEST_CALLER], encode_frame(spoofed)
            )
        ok, actual = response_contains(output, b'"success":true')
        caller_ok = bool(observed_request) and (
            f"X-PwdVault-Caller: {CHROME_TEST_CALLER}".encode() in observed_request[0]
            and b"X-PwdVault-Caller: moz-extension://attacker" not in observed_request[0]
        )
        cases.append(CaseResult("HOST-04", "PASS" if ok and caller_ok else "FAIL", "valid frame forwarded with argv caller", actual, elapsed, {"exit": code, "stderr": stderr, "caller_header_ok": caller_ok}))

        oversized_body = b"x" * (1024 * 1024 + 1)
        with FakeBridgeServer(oversized_body):
            output, stderr, code, elapsed = run_host(
                binary, [CHROME_TEST_CALLER], encode_frame(json_payload())
            )
        ok, actual = response_contains(output, b"Desktop response exceeds native messaging limit")
        cases.append(CaseResult("HOST-05", "PASS" if ok else "FAIL", "response above 1 MiB rejected", actual, elapsed, {"exit": code, "stderr": stderr}))

        declared_oversize = struct.pack("=I", MAX_FRAME + 1)
        output, stderr, code, elapsed = run_host(binary, [CHROME_TEST_CALLER], declared_oversize)
        ok, actual = response_contains(output, b"Message too large")
        cases.append(CaseResult("HOST-06", "PASS" if ok else "FAIL", "frame above 10 MiB rejected", actual, elapsed, {"exit": code, "stderr": stderr}))
    except OSError as error:
        cases.append(CaseResult("HOST-SETUP", "BLOCKED", "port 17429 available and binary runnable", str(error)))
    except Exception as error:
        cases.append(CaseResult("HOST-PROBE", "FAIL", "bounded native host behavior", str(error)))

    return SuiteResult(
        "native-host-probe",
        started_at,
        (time.perf_counter() - started) * 1000,
        suite_status(cases),
        cases,
        {"binary": str(binary)},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run(args.binary.resolve())
    write_json(args.output, result.to_dict())
    print(f"native host probe: {result.status} ({len(result.cases)} cases)")
    if result.status == "PASS":
        return 0
    return 2 if result.status == "BLOCKED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
