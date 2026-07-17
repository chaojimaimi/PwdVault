# Phase 5 Progress — Browser Extension and Native Messaging

**Plan source:** `PwdVault-Comprehensive-Optimization-Plan-v1.0.5.md` §5.5  
**Updated:** 2026-07-16  
**Status:** Core security implementation complete; cross-platform browser E2E and adversarial load gates remain open

## 1. Delivered scope

### 1.1 Cross-browser Native Host manifests

- Chrome manifests use `allowed_origins` with `chrome-extension://<id>/`.
- Firefox manifests use `allowed_extensions` with the stable
  `pwdvault@pwdvault.app` add-on ID.
- Manifest JSON is serialized with `serde_json` rather than string
  interpolation.
- Windows uses distinct files:
  - `com.pwdvault.app.chrome.json`
  - `com.pwdvault.app.firefox.json`
- The two browser registry keys therefore cannot overwrite one another's
  manifest.
- Firefox registration defaults to the stable manifest add-on ID when an old
  config file contains only the Chrome ID.
- Obsolete loopback `host_permissions` were removed from both extension
  manifests.

### 1.2 Self-contained Chrome/Firefox packages

- The local build script now preserves the manifest's `src/` layout and works
  without macOS-only `sed -i ''` behavior.
- Firefox staging dereferences the shared source/icon symlinks into ordinary
  files.
- `verify_manifest.py` checks manifest references and recursively checks static
  JavaScript module imports.
- Archive verification rejects symlinks and missing/non-regular references.
- Locally generated Chrome and Firefox zip files pass the package verifier.

### 1.3 Caller-bound pairing

- The native host derives caller identity only from browser launch arguments:
  - Chrome: validated 32-character extension origin;
  - Firefox: native-host manifest path plus the exact stable add-on ID.
- Request JSON can no longer select or spoof caller identity.
- The host supplies a stable `X-PwdVault-Caller` label to the loopback bridge.
- Pairing state is isolated per caller and contains:
  - six-digit code;
  - 128-bit random session nonce;
  - 30-second TTL;
  - five code attempts.
- A wrong caller or nonce does not consume the owner's challenge.
- Success consumes the challenge; replay and expired challenges fail.
- The extension carries the session nonce from `pair` to `pair_confirm`.
- Settings now exposes **Revoke Extension Access**. Confirmation rotates the
  in-memory API token and cancels all pending pairing sessions without changing
  vault data.

### 1.4 Transport and resource limits

- Replaced thread-per-request dispatch with:
  - 8 fixed workers;
  - a bounded queue of 64 requests;
  - HTTP 503 when the queue is full.
- The bridge now requires:
  - `POST`;
  - `Content-Type: application/json`;
  - present, non-zero, bounded and matching `Content-Length`;
  - `/api/<command>` path matching the parsed command.
- CORS/preflight handling was removed because the extension no longer connects
  directly to HTTP.
- Every JSON response includes `Cache-Control: no-store`.
- The native host retains 30-second TCP read/write timeouts, caps inbound
  frames at 10 MiB and outbound browser frames at 1 MiB.
- Native host request/response byte buffers and server request strings are
  cleared on drop/use where practical.
- Origin is now documented as a caller label, not an authentication boundary.

### 1.5 Protocol compatibility

- Added protocol version `1` to every extension request.
- Both host and desktop reject missing/unsupported versions with an upgrade
  message.
- Added an unauthenticated, origin-checked `handshake` returning app version,
  protocol version and capabilities.
- Added stable response fields `error_code`, `error_message` and `retry_after`.
- The legacy `error` string remains temporarily for compatibility.

### 1.6 Extension sender and secret boundaries

- Added testable `sender-auth.js` and `token-storage.js` modules.
- Messages require `sender.id === chrome.runtime.id`.
- Popup pages retain explicit management access.
- Content scripts may request only:
  - `GET_ENTRIES_FOR_URL`;
  - `GET_ENTRY`.
- Content-provided URLs are ignored; filtering derives the domain from
  `sender.tab.url`.
- `GET_ENTRY` fetches metadata first and requests the secret only after exact
  normalized-domain authorization.
- Token storage prefers `storage.session`, explicitly restricted to
  `TRUSTED_CONTEXTS` where supported.
- `storage.local` is used only if its access can be restricted; otherwise the
  token is memory-only. Old local tokens are restricted and migrated, or
  deleted if restriction is unavailable.
- Lock broadcasts `VAULT_LOCKED` to tabs; content scripts clear cached entries,
  overlays and autofill prompts.

### 1.7 Extension UI hardening included in this phase

- Entry headers support Enter/Space and expose `aria-expanded`.
- Toast uses a polite live region.
- Popup honors `prefers-reduced-motion`.
- Existing Phase 3 pending/dirty protections and Phase 4 design tokens,
  touch targets and focus-visible behavior remain in place.

## 2. Verification completed

| Gate | Result |
|---|---|
| Rust library tests | 135 passed, 1 ignored benchmark |
| Rust Clippy | Passed with `-D warnings` |
| Native host tests | 17 passed |
| Native host Clippy | Passed with `-D warnings` |
| Frontend/extension tests | 57 passed across 19 files |
| TypeScript | `pnpm tsc --noEmit` passed |
| Production frontend build | Passed |
| Extension JavaScript syntax | background/content/popup passed `node --check` |
| Chrome source/package verification | Passed |
| Firefox source/package verification | Passed; release archive contains ordinary files |
| Manifest/module references | 10 references per package validated |
| Git whitespace check | Passed |

New security-focused coverage includes:

- browser argv caller parsing and malformed/missing caller rejection;
- payload caller-spoof regression;
- protocol version rejection;
- caller A/B pairing isolation, nonce, expiry, attempts and replay;
- content-script command allowlist and cross-domain entry rejection;
- trusted session/local/memory-only token storage selection;
- browser-specific manifest fields and distinct Windows filenames.

## 3. Boundaries and open release gates

The following are deliberately **not** reported as complete:

1. **Real browser E2E:** Chrome and Firefox `sendNativeMessage` flows have not
   yet been smoke-tested end to end on both macOS and Windows in this phase.
2. **Windows registry runtime validation:** filename generation is unit-tested,
   but registry writes have not been executed on a Windows runner/VM.
3. **Browser lint/load:** `web-ext` is not installed in the current workspace;
   Firefox `web-ext lint` and actual Chrome/Firefox package loading remain
   release gates.
4. **Adversarial load:** the worker/queue/body/frame limits are explicit in
   code, but the acceptance test with 1,000 slow/malformed connections has not
   been run. Direct slow-HTTP/slowloris behavior must be measured before the
   release gate is closed.
5. **Socket/pipe migration:** loopback TCP port 17429 remains. Unix domain
   socket / Windows named pipe migration and current-user ACL validation remain
   the planned follow-up allowed by §5.5.8.
6. **Fully typed command DTO:** protocol version, handshake and stable error
   fields are implemented, but the request body still uses a string command
   plus optional fields. Converting every command to a tagged Rust/JS DTO is a
   separate compatibility change.
7. **Full popup decomposition:** the first security-sensitive modules were
   extracted, but the proposed `state/actions/screens/accessibility` split is
   not complete.
8. **Native clipboard ownership:** unchanged from Phase 3; it is outside the
   Native Messaging scope and remains a separate platform task.

## 4. Acceptance status against §5.5.9

| Acceptance criterion | Status | Evidence / remaining work |
|---|---|---|
| macOS/Windows Chrome+Firefox Native Messaging smoke | Open | macOS Chrome/Firefox are the current gate; Windows is explicitly deferred |
| All package references are ordinary files | Passed locally | Recursive source/archive verifier |
| Chrome/Firefox lint and browser load | Partial | JSON/package checks pass; `web-ext` and browser load pending |
| Windows registry keys point to distinct manifests | Partial | Unit-tested filenames; Windows runtime check pending |
| Caller isolation, expiry, replay, attempt limit | Passed | Rust pairing tests |
| 1,000 slow/malformed connections bounded | Open | Static 8+64 bounds landed; adversarial load measurement pending |
| Cross-domain content entry ID rejected | Passed in unit tests | Real-browser negative test still recommended |
| Token unreadable from content-script storage | Passed by design/unit tests | Real Chrome/Firefox inspection still recommended |
| Disconnected/pairing/locked/loading/error/empty matrix | Partial | Existing UI states plus lock cleanup; cross-browser E2E matrix pending |

## 5. Recommended next execution step

Do not start general Phase 6 refactoring yet. First run a focused Phase 5 release
gate. The executable macOS-first procedure, with Windows explicitly deferred,
is documented in `PHASE5-MACOS-RELEASE-VALIDATION-PLAN.md`.

The release gate covers:

1. install/load both packaged extensions;
2. register each browser's native host and verify the generated manifest;
3. run handshake → pair → unlock → same-domain fill → cross-domain rejection →
   lock cleanup → revoke → re-pair;
4. inspect extension storage from a content script;
5. execute the bounded malformed/slow-connection load harness;
6. record browser/platform versions and evidence.

After those gates pass, either close Phase 5 or deliver socket/pipe transport as
the explicitly deferred security patch before entering Phase 6.

## 6. Automation execution update — 2026-07-16

- Added the Phase 5 automation toolkit under `scripts/phase5/`.
- Added 14 dependency-free tests for loopback restriction, redaction, HTTP
  request construction, stale-runtime detection, Native Messaging frames,
  monitoring and report status propagation.
- Executed the `fast` gate successfully: all engineering suites and the exact
  Chrome/Firefox archive verifier passed; the runtime Native Host process probe
  was explicitly skipped because port 17429 was occupied.
- A separately authorized bridge probe found that the currently running app is
  an older pre-Phase-5 binary. Live HTTP/load results are therefore blocked
  until the app is rebuilt and restarted from current source.
- Sanitized evidence summary: `docs/evidence/phase5/20260716-fast-summary.md`.

## 7. First adversarial load result and remediation — 2026-07-16

- Live bridge rejection matrix: 16/16 passed.
- Baseline and malformed 1,000-request profiles passed at approximately 10 ms
  p95; queue saturation returned HTTP 503 and recovered.
- Release gate found a P1 connection-layer limit failure: process threads rose
  from 33 to 189 because `tiny_http` spawned internal connection workers before
  the application's bounded request queue.
- Removed `tiny_http` and replaced it with a direct `TcpListener`, 8 fixed
  connection workers, a 64-socket queue, queue-overflow 503, five-second socket
  timeouts and explicit HTTP parsing limits.
- Remediation verification: compilation, Clippy, 26 targeted Native Messaging
  tests and the full Rust suite pass.
- Remaining gate: restart the newly built release binary and repeat the same
  bridge/load/resource run. This rerun is now complete and passed: thread, RSS
  and FD deltas were all zero; 904 saturation probes received HTTP 503.
  Evidence: `docs/evidence/phase5/20260716-release-load-findings.md`.

## 8. Production WebView build correction — 2026-07-16

- Direct `cargo build --release` produced a binary that still targeted the
  Vite `http://localhost:1420` development URL, causing a blank WebView.
- Restored the standard Cargo `custom-protocol` feature mapping to
  `tauri/custom-protocol`.
- Rebuilt with `cargo build --release --features custom-protocol`; frontend
  production build and the full Rust suite pass.
- Release/runtime validation commands now explicitly require the
  `custom-protocol` feature.
