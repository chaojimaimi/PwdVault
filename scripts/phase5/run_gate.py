#!/usr/bin/env python3
"""Orchestrate Phase 5 fast and macOS release validation modes."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scripts.phase5.common import DEFAULT_PORT, redact, sha256_file, utc_now, write_json  # type: ignore
    from scripts.phase5.report import aggregate, discover_results, markdown
else:
    from .common import DEFAULT_PORT, redact, sha256_file, utc_now, write_json
    from .report import aggregate, discover_results, markdown

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NATIVE_HOST_BINARY = PROJECT_ROOT / "extensions/native-host/target/debug/pwdvault-native"


@dataclass
class CommandResult:
    suite: str
    status: str
    command: list[str]
    cwd: str
    returncode: int
    duration_ms: float
    log: str


def port_listening(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.2)
        result = connection.connect_ex(("127.0.0.1", port))
    if result == 0:
        return True
    # Managed/sandboxed runs may prohibit connect() while still allowing
    # read-only process inspection. Avoid treating EPERM as an unused port.
    try:
        observed = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return observed.returncode == 0 and f":{port}" in observed.stdout
    except (OSError, subprocess.SubprocessError):
        return False


def run_command(
    suite: str,
    command: list[str],
    output_dir: Path,
    *,
    cwd: Path = PROJECT_ROOT,
    timeout: int = 900,
    blocked_codes: set[int] | None = None,
) -> CommandResult:
    started = time.perf_counter()
    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )
        returncode = process.returncode
        combined = redact(process.stdout + process.stderr)
        status = "PASS" if returncode == 0 else "BLOCKED" if returncode in (blocked_codes or set()) else "FAIL"
    except subprocess.TimeoutExpired as error:
        returncode = 124
        combined = redact(f"timeout after {timeout}s\n{error.stdout or ''}\n{error.stderr or ''}")
        status = "FAIL"
    except OSError as error:
        returncode = 127
        combined = redact(str(error))
        status = "BLOCKED"
    result = CommandResult(
        suite,
        status,
        command,
        str(cwd),
        returncode,
        (time.perf_counter() - started) * 1000,
        combined[-20000:],
    )
    write_json(output_dir / f"command-{suite}.json", {**asdict(result), "generated_at": utc_now()})
    (output_dir / f"command-{suite}.log").write_text(combined, encoding="utf-8")
    print(f"[{status}] {suite}")
    return result


def write_environment(output_dir: Path) -> None:
    payload = {
        "generated_at": utc_now(),
        "platform": platform.platform(),
        "python": sys.version,
        "machine": platform.machine(),
    }
    write_json(output_dir / "environment.json", {"suite": "environment", "status": "PASS", **payload})


def write_status(output_dir: Path, suite: str, status: str, reason: str) -> None:
    write_json(
        output_dir / f"{suite}.json",
        {"suite": suite, "status": status, "reason": reason, "generated_at": utc_now()},
    )
    print(f"[{status}] {suite}: {reason}")


def write_blocked(output_dir: Path, suite: str, reason: str) -> None:
    write_status(output_dir, suite, "BLOCKED", reason)


def automated_commands() -> list[tuple[str, list[str], Path]]:
    return [
        ("phase5-tool-tests", [sys.executable, "-m", "unittest", "discover", "-s", "scripts/phase5/tests", "-v"], PROJECT_ROOT),
        ("typescript", ["pnpm", "tsc", "--noEmit"], PROJECT_ROOT),
        ("frontend-tests", ["pnpm", "test"], PROJECT_ROOT),
        ("frontend-build", ["pnpm", "build"], PROJECT_ROOT),
        ("rust-fmt", ["cargo", "fmt", "--all", "--check"], PROJECT_ROOT / "src-tauri"),
        ("rust-tests", ["cargo", "test", "--lib"], PROJECT_ROOT / "src-tauri"),
        ("rust-clippy", ["cargo", "clippy", "--all-targets", "--", "-D", "warnings"], PROJECT_ROOT / "src-tauri"),
        ("native-host-tests", ["cargo", "test"], PROJECT_ROOT / "extensions/native-host"),
        ("native-host-clippy", ["cargo", "clippy", "--all-targets", "--", "-D", "warnings"], PROJECT_ROOT / "extensions/native-host"),
        ("native-host-build", ["cargo", "build"], PROJECT_ROOT / "extensions/native-host"),
        ("background-syntax", ["node", "--check", "extensions/chrome/src/background.js"], PROJECT_ROOT),
        ("content-syntax", ["node", "--check", "extensions/chrome/src/content.js"], PROJECT_ROOT),
        ("popup-syntax", ["node", "--check", "extensions/chrome/src/popup/popup.js"], PROJECT_ROOT),
        ("extension-build", ["bash", "extensions/chrome/scripts/build.sh"], PROJECT_ROOT),
        ("extension-source-verify", ["bash", "extensions/tests/verify_package.sh", "--source"], PROJECT_ROOT),
        ("diff-check", ["git", "diff", "--check"], PROJECT_ROOT),
    ]


def package_extension(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise RuntimeError(f"refusing extension symlink: {path}")
            if path.is_file():
                archive.write(path, path.relative_to(source))


def package_and_verify_extensions(output_dir: Path) -> CommandResult:
    artifacts = output_dir / "artifacts"
    chrome_zip = artifacts / "PwdVault-Chrome-Extension.zip"
    firefox_zip = artifacts / "PwdVault-Firefox-Extension.zip"
    try:
        package_extension(PROJECT_ROOT / "extensions/chrome/dist", chrome_zip)
        package_extension(PROJECT_ROOT / "extensions/firefox/dist", firefox_zip)
        metadata = {
            "suite": "extension-artifacts",
            "status": "PASS",
            "artifacts": {
                "chrome": {"path": str(chrome_zip), "sha256": sha256_file(chrome_zip)},
                "firefox": {"path": str(firefox_zip), "sha256": sha256_file(firefox_zip)},
            },
        }
        write_json(output_dir / "extension-artifacts.json", metadata)
    except Exception as error:
        write_json(
            output_dir / "extension-artifacts.json",
            {"suite": "extension-artifacts", "status": "FAIL", "error": str(error)},
        )
        return CommandResult("extension-package-verify", "FAIL", [], str(PROJECT_ROOT), 1, 0, str(error))
    return run_command(
        "extension-package-verify",
        ["bash", "extensions/tests/verify_package.sh", str(chrome_zip), str(firefox_zip)],
        output_dir,
        timeout=120,
    )


def run_gate(args: argparse.Namespace) -> int:
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    write_environment(output_dir)
    failed = False
    runtime_ready = False
    for suite, command, cwd in automated_commands():
        result = run_command(suite, command, output_dir, cwd=cwd)
        if result.status != "PASS":
            failed = True
            if not args.keep_going:
                break

    if not failed or args.keep_going:
        package_result = package_and_verify_extensions(output_dir)
        failed = failed or package_result.status != "PASS"

    service_running = port_listening(args.port)
    if args.mode == "fast" and service_running:
        write_status(
            output_dir,
            "native-host-process-probe",
            "SKIP",
            "port 17429 is occupied; process-level fake bridge probe is reserved for a port-free run",
        )
    elif not failed and NATIVE_HOST_BINARY.is_file() and not service_running:
        result = run_command(
            "native-host-process-probe",
            [
                sys.executable,
                "scripts/phase5/native_host_probe.py",
                "--binary",
                str(NATIVE_HOST_BINARY),
                "--output",
                str(output_dir / "native-host-probe.json"),
            ],
            output_dir,
            blocked_codes={2},
        )
        failed = result.status != "PASS"
    elif args.mode == "release-macos" and service_running:
        result = run_command(
            "native-bridge-probe",
            [
                sys.executable,
                "scripts/phase5/native_bridge_probe.py",
                "--port",
                str(args.port),
                "--output",
                str(output_dir / "native-bridge-probe.json"),
            ],
            output_dir,
            blocked_codes={2},
        )
        failed = failed or result.status != "PASS"
        runtime_ready = result.status == "PASS"
    else:
        write_blocked(output_dir, "native-host-process-probe", "native host binary unavailable")
        failed = True

    if args.mode == "release-macos":
        web_ext = shutil.which("web-ext")
        if web_ext:
            lint_result = run_command(
                "firefox-web-ext-lint",
                [web_ext, "lint", "--source-dir", "extensions/firefox/dist"],
                output_dir,
                timeout=180,
            )
            failed = failed or lint_result.status != "PASS"
        else:
            write_blocked(output_dir, "firefox-web-ext-lint", "web-ext is not installed")
            failed = True
        if sys.platform != "darwin":
            write_blocked(output_dir, "macos-runtime", "release-macos mode requires macOS")
            failed = True
        if not service_running:
            write_blocked(output_dir, "native-bridge-runtime", "PwdVault is not listening on loopback port 17429")
            failed = True
        if not args.pid:
            write_blocked(output_dir, "process-monitor", "--pid is required for release-macos mode")
            failed = True
        if service_running and args.pid and runtime_ready:
            baseline_output = output_dir / "process-baseline.json"
            baseline_duration = min(10.0, max(3.0, args.monitor_duration / 3))
            baseline_result = run_command(
                "process-baseline",
                [
                    sys.executable,
                    "scripts/phase5/monitor_process.py",
                    "--pid",
                    str(args.pid),
                    "--duration",
                    str(baseline_duration),
                    "--output",
                    str(baseline_output),
                ],
                output_dir,
                timeout=int(baseline_duration) + 15,
            )
            failed = failed or baseline_result.status != "PASS"
            monitor_output = output_dir / "process-monitor.json"
            monitor = subprocess.Popen(
                [
                    sys.executable,
                    "scripts/phase5/monitor_process.py",
                    "--pid",
                    str(args.pid),
                    "--duration",
                    str(args.monitor_duration),
                    "--output",
                    str(monitor_output),
                ],
                cwd=PROJECT_ROOT,
            )
            load_result = run_command(
                "adversarial-load",
                [
                    sys.executable,
                    "scripts/phase5/adversarial_load.py",
                    "--profile",
                    "all",
                    "--clients",
                    str(args.clients),
                    "--concurrency",
                    str(min(32, args.clients)),
                    "--output",
                    str(output_dir / "adversarial-load.json"),
                ],
                output_dir,
                timeout=max(900, int(args.monitor_duration) + 60),
            )
            failed = failed or load_result.status != "PASS"
            try:
                monitor_return = monitor.wait(timeout=args.monitor_duration + 15)
                failed = failed or monitor_return != 0
            except subprocess.TimeoutExpired:
                monitor.terminate()
                write_blocked(output_dir, "process-monitor-timeout", "monitor did not stop")
                failed = True
            if baseline_output.is_file() and monitor_output.is_file():
                resource_result = run_command(
                    "resource-thresholds",
                    [
                        sys.executable,
                        "scripts/phase5/evaluate_resources.py",
                        "--baseline",
                        str(baseline_output),
                        "--attack",
                        str(monitor_output),
                        "--output",
                        str(output_dir / "resource-thresholds.json"),
                    ],
                    output_dir,
                    blocked_codes={2},
                )
                failed = failed or resource_result.status != "PASS"
        elif service_running and args.pid and not runtime_ready:
            write_blocked(
                output_dir,
                "adversarial-load",
                "live Phase 5 handshake/rejection probe did not pass; load traffic was not started",
            )
            write_blocked(
                output_dir,
                "resource-thresholds",
                "load traffic was not started because runtime readiness failed",
            )
            failed = True
        if args.browser_evidence:
            browser_result = run_command(
                "browser-evidence",
                [
                    sys.executable,
                    "scripts/phase5/validate_browser_evidence.py",
                    "--input",
                    str(Path(args.browser_evidence).resolve()),
                    "--output",
                    str(output_dir / "browser-e2e.json"),
                ],
                output_dir,
                blocked_codes={2},
            )
            failed = failed or browser_result.status != "PASS"
        else:
            write_blocked(
                output_dir,
                "browser-e2e",
                "Chrome/Firefox real-browser evidence has not yet been supplied to the automated gate",
            )
            failed = True

    summary = aggregate(discover_results(output_dir), args.mode)
    # Command wrappers and their nested probe JSON both appear intentionally:
    # one captures process execution and one captures semantic cases.
    if failed and summary["status"] == "PASS":
        summary["status"] = "FAIL"
    write_json(output_dir / "summary.json", summary)
    (output_dir / "summary.md").write_text(markdown(summary), encoding="utf-8")
    print(f"Phase 5 {args.mode} gate: {summary['status']}")
    print(f"Evidence: {output_dir}")
    return 0 if summary["status"] == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("fast", "release-macos"))
    parser.add_argument("--output", default=f"/tmp/pwdvault-phase5-{int(time.time())}")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--clients", type=int, default=1000)
    parser.add_argument("--monitor-duration", type=float, default=30)
    parser.add_argument("--browser-evidence")
    parser.add_argument("--keep-going", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.clients <= 1000:
        parser.error("--clients must be between 1 and 1000")
    return run_gate(args)


if __name__ == "__main__":
    raise SystemExit(main())
