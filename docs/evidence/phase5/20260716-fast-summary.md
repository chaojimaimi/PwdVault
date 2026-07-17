# Phase 5 Fast Gate Evidence — 2026-07-16

## Result

**PASS**, with the runtime Native Host process probe explicitly **SKIPPED**
because an already-running PwdVault instance occupied port 17429.

Windows remains **DEFERRED**.

## Passed suites

- Phase 5 automation tests: 14 passed.
- TypeScript type check.
- Frontend tests: 57 passed across 19 files.
- Frontend production build.
- Rust formatting.
- Rust library tests: 135 passed, 1 ignored benchmark.
- Rust Clippy with warnings denied.
- Native Host tests: 17 passed.
- Native Host Clippy with warnings denied.
- Native Host debug build.
- Background/content/popup JavaScript syntax.
- Chrome/Firefox extension staging build.
- Extension source/reference validation.
- Hashed Chrome/Firefox archive creation and package verification.
- Git whitespace validation.

## Runtime observation

A separately authorized live bridge probe identified the process currently on
port 17429 as an older pre-Phase-5 runtime: it returned the legacy CORS response
shape and did not expose protocol-version handshake behavior. The corrected
probe now reports this condition as **BLOCKED — rebuild/restart required** and
stops before the rest of the matrix.

This is not counted as a failure of the current source tree, and it is not
counted as runtime validation. Live bridge and adversarial load gates remain
open until the application is rebuilt and restarted from the final source.

## Raw evidence

Sanitized raw output for this run was written outside the repository to:

```text
/private/tmp/pwdvault-phase5-fast-20260716-r3
```

The directory contains individual command JSON/logs, environment metadata and
the generated `summary.json`/`summary.md`.
