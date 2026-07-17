# Phase 5 Automation

Dependency-free automation for the Phase 5 Native Messaging release gate.
Every network tool refuses non-loopback destinations and every report redacts
Bearer/64-hex token-shaped values.

## Fast gate

```bash
scripts/phase5/run_macos_gate.sh fast --keep-going \
  --output /tmp/pwdvault-phase5-fast
```

Runs frontend, Rust, Native Host, syntax, extension build/package-source and
automation-tool tests. It also creates hashed Chrome/Firefox zip artifacts and
verifies every packaged reference. If port 17429 is free, it runs the Native Host
against a controlled fake bridge. If a PwdVault instance occupies the port,
that process-level case is `SKIP`; runtime behavior belongs to release mode.

## macOS release gate

Build the frontend and a production-protocol desktop binary, then restart
PwdVault from the exact source under test:

```bash
pnpm build
(cd src-tauri && cargo build --release --features custom-protocol)
./src-tauri/target/release/pwdvault
```

Do not use a plain `cargo build --release` binary for UI validation: without
the `custom-protocol` feature it tries the Vite development URL and displays a
blank WebView when port 1420 is not running. After startup, obtain its PID and
run:

```bash
scripts/phase5/run_macos_gate.sh release-macos \
  --pid <pwdvault-pid> \
  --clients 1000 \
  --monitor-duration 60 \
  --browser-evidence /path/to/browser-evidence.json \
  --keep-going \
  --output /tmp/pwdvault-phase5-release
```

Release mode adds the live HTTP rejection probe, process monitoring and the
baseline/malformed/saturation load profiles. It deliberately reports
`browser-e2e` as `BLOCKED` until Chrome/Firefox evidence is supplied and passes
`validate_browser_evidence.py`. Copy `browser-evidence.example.json`, fill all
required case results/version/artifact hashes, and retain the supporting
screenshots/logs separately. A machine report must never silently replace
real-browser validation.

## Individual tools

```bash
python3 scripts/phase5/native_bridge_probe.py --output /tmp/bridge.json
python3 scripts/phase5/native_host_probe.py \
  --binary extensions/native-host/target/debug/pwdvault-native \
  --output /tmp/host.json
python3 scripts/phase5/adversarial_load.py \
  --profile all --clients 1000 --output /tmp/load.json
python3 scripts/phase5/monitor_process.py \
  --pid <pwdvault-pid> --duration 60 --output /tmp/process.json
python3 scripts/phase5/evaluate_resources.py \
  --baseline /tmp/baseline.json --attack /tmp/process.json \
  --output /tmp/resource-thresholds.json
```

`native_host_probe.py` needs exclusive access to port 17429 and therefore must
run with PwdVault stopped. `native_bridge_probe.py` and the load generator need
the final PwdVault build running. Managed environments may require explicit
permission for loopback connections.

## Tests

```bash
python3 -m unittest discover -s scripts/phase5/tests -v
python3 -m py_compile scripts/phase5/*.py
```

Outputs are JSON plus a generated `summary.md`. `PASS`, `FAIL`, `BLOCKED`, and
`SKIP` remain distinct throughout aggregation.
