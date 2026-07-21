#!/usr/bin/env python3
"""Execute the packaged Windows Native Messaging host end to end.

This is intentionally a process-level test, not another Rust unit test. It
starts a mock PwdVault loopback server, launches the actual Windows EXE with
Chrome's arguments, sends a length-prefixed handshake on stdin, and validates
the framed stdout response. It catches loader, argv, O_TEXT/O_BINARY, framing,
HTTP bridge, and clean-exit regressions in one release gate.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import subprocess
import threading
from pathlib import Path


HOST = "127.0.0.1"
PORT = 17429
CHROME_ORIGIN = "chrome-extension://kekeibdcccjakipnmdpbafhaeknioaem/"


def mock_server(ready: threading.Event, errors: list[str]) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, PORT))
            server.listen(1)
            ready.set()
            server.settimeout(10)
            connection, _ = server.accept()
            with connection:
                connection.settimeout(10)
                data = bytearray()
                while b"\r\n\r\n" not in data:
                    chunk = connection.recv(4096)
                    if not chunk:
                        raise RuntimeError("host closed before HTTP headers")
                    data.extend(chunk)

                headers, body = bytes(data).split(b"\r\n\r\n", 1)
                header_lines = headers.decode("ascii").split("\r\n")
                if header_lines[0] != "POST /api/handshake HTTP/1.1":
                    raise RuntimeError(f"unexpected request line: {header_lines[0]}")
                lengths = [
                    int(line.split(":", 1)[1].strip())
                    for line in header_lines[1:]
                    if line.lower().startswith("content-length:")
                ]
                if len(lengths) != 1:
                    raise RuntimeError("missing or duplicate Content-Length")
                while len(body) < lengths[0]:
                    chunk = connection.recv(lengths[0] - len(body))
                    if not chunk:
                        raise RuntimeError("host closed before HTTP body")
                    body += chunk

                request = json.loads(body[: lengths[0]])
                if request.get("command") != "handshake":
                    raise RuntimeError("host forwarded the wrong command")

                response_body = json.dumps(
                    {
                        "id": request["id"],
                        "success": True,
                        "data": {
                            "protocol_version": 1,
                            "probe": "binary\nstdio",
                        },
                        "error": None,
                        "error_code": None,
                        "error_message": None,
                        "retry_after": None,
                    },
                    separators=(",", ":"),
                ).encode("utf-8") + b"\n"
                # The trailing JSON whitespace is a real LF byte. A Windows
                # O_TEXT stdout would translate it and make the Native
                # Messaging frame length inconsistent.
                http = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: "
                    + str(len(response_body)).encode("ascii")
                    + b"\r\nConnection: close\r\n\r\n"
                    + response_body
                )
                connection.sendall(http)
    except Exception as error:  # noqa: BLE001 - report thread failures to main
        errors.append(str(error))
        ready.set()


def run_probe(executable: Path) -> None:
    ready = threading.Event()
    server_errors: list[str] = []
    thread = threading.Thread(target=mock_server, args=(ready, server_errors), daemon=True)
    thread.start()
    if not ready.wait(timeout=10):
        raise RuntimeError("mock server did not start")
    if server_errors:
        raise RuntimeError(server_errors[0])

    request = json.dumps(
        {"id": 73, "protocol_version": 1, "command": "handshake"},
        separators=(",", ":"),
    ).encode("utf-8")
    # Append an insignificant JSON LF so the input exercises O_BINARY too.
    request += b"\n"
    frame = struct.pack("<I", len(request)) + request

    process = subprocess.run(
        [str(executable.resolve()), CHROME_ORIGIN, "--parent-window=0"],
        input=frame,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    thread.join(timeout=10)
    if thread.is_alive():
        raise RuntimeError("mock server did not finish")
    if server_errors:
        raise RuntimeError(server_errors[0])
    if process.returncode != 0:
        raise RuntimeError(
            f"host exited {process.returncode}: {process.stderr.decode(errors='replace')}"
        )
    if len(process.stdout) < 4:
        raise RuntimeError(
            "host returned no Native Messaging frame: "
            + process.stderr.decode(errors="replace")
        )

    response_length = struct.unpack("<I", process.stdout[:4])[0]
    response = process.stdout[4:]
    if response_length != len(response):
        raise RuntimeError(
            f"frame length mismatch: prefix={response_length}, bytes={len(response)}"
        )
    decoded = json.loads(response)
    if decoded.get("id") != 73 or not decoded.get("success"):
        raise RuntimeError(f"unexpected host response: {decoded}")
    if decoded.get("data", {}).get("probe") != "binary\nstdio":
        raise RuntimeError("response payload was corrupted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=Path, help="path to pwdvault-native.exe")
    args = parser.parse_args()
    try:
        run_probe(args.host)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Windows native host smoke: FAIL: {error}")
        return 1
    print(f"Windows native host smoke: PASS: {args.host}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
