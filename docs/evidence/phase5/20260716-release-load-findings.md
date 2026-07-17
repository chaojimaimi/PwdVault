# Phase 5 macOS Load Finding — 2026-07-16

## Execution result

The live Phase 5 HTTP bridge probe passed all 16 cases after correcting the
probe's authentication-first expectation for an unknown protected command.

The first 1,000-client release load run produced:

- baseline: 1,000/1,000 HTTP 200, p95 10.110 ms;
- malformed storm: 1,000 completed, no transport errors, p95 10.256 ms;
- saturation: 96 slow connections opened, 35 probe requests received HTTP 503;
- process survived and RSS/FD returned within their configured recovery bounds.

## P1 finding

Thread count increased from 33 at baseline to 189 at peak (`+156`), exceeding
the `+16` release limit. The application-level 8-worker/64-request queue was
bounded, but `tiny_http` created additional internal connection workers before
requests reached that queue.

This is a real connection-level resource-boundary failure. The release gate
correctly failed; thresholds were not relaxed.

## Remediation implemented

- Removed `tiny_http` from the desktop bridge.
- Replaced it with a direct loopback `TcpListener`.
- Accepted sockets enter a bounded 64-slot queue before parsing.
- Exactly 8 named workers own connection parsing and command execution.
- Queue overflow receives HTTP 503 without creating another worker.
- Each socket has a 5-second read/write timeout.
- Header size, duplicate headers, transfer encoding, method, content type,
  content length, body size, path, protocol, caller label and Bearer auth remain
  explicitly validated.

The remediation passes compilation, Clippy, 26 targeted Native Messaging tests
and the full Rust suite (135 passed, 1 ignored benchmark). A new release binary
was produced at `src-tauri/target/release/pwdvault`.

## Remediation verification result

The remediated `custom-protocol` release binary was restarted and tested again:

- bridge rejection matrix: 16/16 passed;
- baseline: 1,000/1,000 HTTP 200, p95 4.288 ms;
- malformed: 1,000 completed with expected bounded status codes, p95 2.196 ms;
- saturation: 904 overflow probes received HTTP 503; 96 deliberately incomplete
  slow connections were interrupted;
- threads: baseline 28, peak 28, delta 0;
- RSS: baseline/peak/recovery 105,968 KiB, delta 0;
- open files: baseline/recovery 56, delta 0;
- process remained alive.

Both the adversarial-load suite and resource-threshold evaluator report
**PASS**. The connection-level P1 is closed.

## Runtime build correction

The first bare release binary was built without Tauri's production
`custom-protocol` feature and therefore attempted to load the Vite development
URL, producing a blank WebView. `Cargo.toml` now restores the standard
`custom-protocol = ["tauri/custom-protocol"]` mapping. The replacement binary
was built with:

```bash
cargo build --release --features custom-protocol
```
