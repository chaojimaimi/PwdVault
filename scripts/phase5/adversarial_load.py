#!/usr/bin/env python3
"""Bounded adversarial load generator for the PwdVault loopback bridge."""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.phase5.common import (  # type: ignore
        DEFAULT_HOST,
        DEFAULT_PORT,
        latency_summary,
        require_loopback,
        utc_now,
        write_json,
    )
    from scripts.phase5.native_bridge_probe import default_cases, http_request, json_body
else:
    from .common import DEFAULT_HOST, DEFAULT_PORT, latency_summary, require_loopback, utc_now, write_json
    from .native_bridge_probe import default_cases, http_request, json_body

MAX_CLIENTS = 1000
MAX_RESPONSE = 1024 * 1024 + 64 * 1024


@dataclass
class RequestResult:
    status: int | None
    elapsed_ms: float
    error: str | None = None


def status_from_response(response: bytes) -> int | None:
    try:
        return int(response.split(b"\r\n", 1)[0].split()[1])
    except (IndexError, ValueError):
        return None


async def read_response(reader: asyncio.StreamReader, timeout: float) -> bytes:
    response = bytearray()
    while len(response) <= MAX_RESPONSE:
        try:
            chunk = await asyncio.wait_for(
                reader.read(min(65536, MAX_RESPONSE + 1 - len(response))), timeout
            )
        except ConnectionResetError:
            if response:
                break
            raise
        if not chunk:
            break
        response.extend(chunk)
    if len(response) > MAX_RESPONSE:
        raise RuntimeError("response exceeded load harness safety limit")
    return bytes(response)


async def send_request(host: str, port: int, request: bytes, timeout: float) -> RequestResult:
    started = time.perf_counter()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout)
        response = await read_response(reader, timeout)
        return RequestResult(status_from_response(response), (time.perf_counter() - started) * 1000)
    except Exception as error:
        return RequestResult(None, (time.perf_counter() - started) * 1000, type(error).__name__)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def run_complete_requests(
    host: str,
    port: int,
    requests: list[bytes],
    concurrency: int,
    timeout: float,
) -> list[RequestResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def limited(request: bytes) -> RequestResult:
        async with semaphore:
            return await send_request(host, port, request, timeout)

    return await asyncio.gather(*(limited(request) for request in requests))


async def hold_slow_body(
    host: str,
    port: int,
    hold_seconds: float,
    ready: asyncio.Event,
    counter: list[int],
) -> RequestResult:
    started = time.perf_counter()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.open_connection(host, port)
        body = json_body()
        request = http_request(body=body, content_length=len(body) + 4096)
        headers, _, _ = request.partition(b"\r\n\r\n")
        writer.write(headers + b"\r\n\r\n" + body[:1])
        await writer.drain()
        counter[0] += 1
        ready.set()
        await asyncio.sleep(hold_seconds)
        writer.close()
        await writer.wait_closed()
        try:
            response = await asyncio.wait_for(reader.read(MAX_RESPONSE), 0.25)
        except Exception:
            response = b""
        return RequestResult(status_from_response(response), (time.perf_counter() - started) * 1000)
    except Exception as error:
        return RequestResult(None, (time.perf_counter() - started) * 1000, type(error).__name__)
    finally:
        if writer is not None and not writer.is_closing():
            writer.close()


def summarize(name: str, results: list[RequestResult], expected_success: bool = False) -> dict[str, object]:
    latencies = [result.elapsed_ms for result in results]
    statuses: dict[str, int] = {}
    errors: dict[str, int] = {}
    for result in results:
        statuses[str(result.status)] = statuses.get(str(result.status), 0) + 1
        if result.error:
            errors[result.error] = errors.get(result.error, 0) + 1
    success_count = statuses.get("200", 0)
    status = "PASS"
    if expected_success and success_count != len(results):
        status = "FAIL"
    return {
        "profile": name,
        "status": status,
        "requests": len(results),
        "statuses": statuses,
        "errors": errors,
        "latency": latency_summary(latencies),
    }


async def profile_baseline(host: str, port: int, clients: int, concurrency: int, timeout: float) -> dict[str, object]:
    requests = [http_request() for _ in range(clients)]
    results = await run_complete_requests(host, port, requests, concurrency, timeout)
    summary = summarize("baseline", results, expected_success=True)
    p95 = summary["latency"]["p95_ms"]  # type: ignore[index]
    if p95 is not None and p95 > 500:
        summary["status"] = "FAIL"
        summary["threshold_failure"] = "p95 latency exceeds 500 ms"
    return summary


async def profile_malformed(host: str, port: int, clients: int, concurrency: int, timeout: float, seed: int) -> dict[str, object]:
    matrix = [case.request for case in default_cases()[1:]]
    rng = random.Random(seed)
    requests = [rng.choice(matrix) for _ in range(clients)]
    results = await run_complete_requests(host, port, requests, concurrency, timeout)
    summary = summarize("malformed", results)
    if any(result.error for result in results):
        summary["status"] = "FAIL"
        summary["threshold_failure"] = "one or more malformed requests timed out/failed transport"
    return summary


async def profile_saturation(host: str, port: int, clients: int, timeout: float, hold_seconds: float) -> dict[str, object]:
    slow_count = min(clients, 96)
    ready = asyncio.Event()
    counter = [0]
    slow_tasks = [asyncio.create_task(hold_slow_body(host, port, hold_seconds, ready, counter)) for _ in range(slow_count)]
    try:
        await asyncio.wait_for(ready.wait(), timeout)
        deadline = time.monotonic() + min(timeout, 5)
        while counter[0] < min(slow_count, 72) and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        probes = await run_complete_requests(
            host,
            port,
            [http_request() for _ in range(max(1, clients - slow_count))],
            min(64, max(1, clients - slow_count)),
            timeout,
        )
        slow_results = await asyncio.gather(*slow_tasks)
    finally:
        for task in slow_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*slow_tasks, return_exceptions=True)
    summary = summarize("saturation", probes + slow_results)
    service_unavailable = sum(1 for result in probes if result.status == 503)
    summary["opened_slow_connections"] = counter[0]
    summary["probe_503"] = service_unavailable
    summary["status"] = "PASS" if service_unavailable > 0 else "FAIL"
    if service_unavailable == 0:
        summary["threshold_failure"] = "queue saturation did not produce HTTP 503"
    return summary


async def execute(args: argparse.Namespace) -> dict[str, object]:
    host = require_loopback(args.host)
    profiles = [args.profile] if args.profile != "all" else ["baseline", "malformed", "saturation"]
    started = time.perf_counter()
    results: list[dict[str, object]] = []
    for profile in profiles:
        if profile == "baseline":
            results.append(await profile_baseline(host, args.port, args.clients, args.concurrency, args.timeout))
        elif profile == "malformed":
            results.append(await profile_malformed(host, args.port, args.clients, args.concurrency, args.timeout, args.seed))
        elif profile == "saturation":
            results.append(await profile_saturation(host, args.port, args.clients, args.timeout, args.hold_seconds))
    status = "PASS" if all(result["status"] == "PASS" for result in results) else "FAIL"
    return {
        "suite": "adversarial-load",
        "status": status,
        "started_at": utc_now(),
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "metadata": {
            "host": host,
            "port": args.port,
            "clients": args.clients,
            "concurrency": args.concurrency,
            "seed": args.seed,
        },
        "profiles": results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--clients", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--profile", choices=("baseline", "malformed", "saturation", "all"), default="baseline")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--hold-seconds", type=float, default=3.0)
    parser.add_argument("--seed", type=int, default=20260716)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not 1 <= args.clients <= MAX_CLIENTS:
        parser.error(f"--clients must be between 1 and {MAX_CLIENTS}")
    if not 1 <= args.concurrency <= min(args.clients, 256):
        parser.error("--concurrency must be between 1 and min(clients, 256)")
    return args


def main() -> int:
    args = parse_args()
    try:
        result = asyncio.run(execute(args))
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    write_json(args.output, result)
    print(f"adversarial load: {result['status']} ({args.profile}, {args.clients} clients)")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
