# Phase 5 macOS Release Validation and Adversarial Load Test Plan

**Applies to:** PwdVault v1.0.5 Phase 5  
**Prepared:** 2026-07-16  
**Primary platform:** macOS  
**Browsers:** Google Chrome and Mozilla Firefox  
**Windows:** Explicitly deferred; see §12  
**Purpose:** Close the remaining Phase 5 release gates without starting Phase 6

## 1. Outcome and release decision

This plan produces one of three decisions:

1. **PASS — Phase 5 macOS gate closed:** every mandatory macOS criterion passes
   and all evidence is retained.
2. **CONDITIONAL PASS:** only a documented, non-security browser compatibility
   issue remains, with an owner and delivery date. Security failures cannot be
   waived into this category.
3. **FAIL — release frozen:** any P0/P1 defect, caller/sender/token boundary
   bypass, unbounded resource growth, crash, deadlock, data corruption or
   missing mandatory evidence freezes the release.

Passing this plan closes the **macOS portion** of §5.5.9 only. It does not imply
Windows validation and does not authorize claiming full cross-platform
completion.

## 2. Scope

### 2.1 In scope

- Release-style macOS app and Native Messaging host packaging.
- Self-contained Chrome and Firefox extension artifacts.
- Native Host registration and generated manifest inspection.
- Chrome/Firefox handshake, pairing, unlock, same-domain access, lock, revoke
  and re-pair flows.
- Disconnected, pairing, locked, loading, error, empty and unlocked UI states.
- Negative tests for caller identity, protocol version, sender authorization,
  cross-domain entry access and token storage isolation.
- HTTP bridge method/path/header/body limits.
- 1,000-client slow/malformed connection tests.
- Thread, file-descriptor, RSS, latency, auto-lock and recovery observations.
- Evidence capture and defect triage.

### 2.2 Out of scope

- Windows registry/runtime validation in this execution.
- Unix domain socket / Windows named pipe migration.
- General Phase 6 performance or frontend refactoring.
- Real credential import or production user data.
- Store publication, notarization and Apple Developer signing.
- Native clipboard ownership work deferred from Phase 3.

## 3. Safety boundaries

1. Use a disposable macOS user profile or dedicated test machine where
   practical.
2. Back up and move aside any existing PwdVault test vault before execution.
   Never point the test build at a real vault.
3. Use synthetic values only:
   - master password: generated for this run;
   - entry passwords: clearly marked test-only random values;
   - no real usernames, tokens or recovery data.
4. Do not record pairing codes, API tokens, master passwords or entry secrets
   in screenshots, terminal output or committed evidence.
5. Load tests target `127.0.0.1:17429` only. The harness must reject a non-loopback
   destination.
6. Run the load suite only after functional browser evidence is captured; it
   may intentionally exhaust the local bridge.
7. Stop immediately if another application is listening on port 17429.

## 4. Required environment and evidence

Record the following before testing:

```bash
sw_vers
uname -a
system_profiler SPHardwareDataType
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --version
/Applications/Firefox.app/Contents/MacOS/firefox --version
rustc --version
cargo --version
node --version
pnpm --version
```

Required tools:

- Xcode Command Line Tools;
- Rust/Cargo and the repository's pinned frontend dependencies;
- Chrome and Firefox current test versions;
- `zip`, `unzip`, `python3`, `lsof`, `ps`, `top`;
- Mozilla `web-ext` for Firefox linting;
- optional: Activity Monitor for corroborating process observations.

Evidence root:

```text
docs/evidence/phase5/<YYYYMMDD-HHMM>/
├── environment.txt
├── build/
├── chrome/
├── firefox/
├── security-negative/
├── load/
└── summary.md
```

Evidence may remain outside Git if it contains machine paths or large logs.
The committed `summary.md` must contain hashes and sanitized conclusions, not
secrets.

For every executable case retain:

- case ID, start/end time and operator;
- app/browser versions and artifact SHA-256;
- exact command or manual steps;
- expected and actual result;
- screenshot or sanitized log where appropriate;
- PASS/FAIL/BLOCKED;
- defect link for failures.

## 5. Test stages and stop/go gates

| Stage | Content | Proceed when |
|---|---|---|
| V0 | Clean-state and automated preflight | All existing tests/builds pass |
| V1 | Release artifact and manifest validation | Artifacts are self-contained and lintable |
| V2 | Chrome Native Messaging E2E | Chrome functional/security cases pass |
| V3 | Firefox Native Messaging E2E | Firefox functional/security cases pass |
| V4 | Protocol and local HTTP negative tests | Rejections are deterministic and sanitized |
| V5 | Adversarial load | Resource, responsiveness and recovery limits pass |
| V6 | Evidence review and release decision | No unresolved P0/P1 and evidence is complete |

Do not continue from a failed stage if continuing could invalidate evidence or
damage state. Record and fix the defect, rebuild artifacts, then restart from
V0 unless the fix is demonstrably isolated to documentation.

### 5.1 Suggested execution schedule

| Work block | Estimate | Deliverable |
|---|---:|---|
| Harness implementation and review | 0.5–1 day | HTTP/frame probes, load generator, process monitor |
| V0/V1 build and artifact validation | 0.5 day | Hashed archives, lint and Native Host manifest evidence |
| Chrome V2 plus security negatives | 0.5 day | Completed Chrome case sheet |
| Firefox V3 plus security negatives | 0.5 day | Completed Firefox case sheet |
| V4/V5 three-run load suite | 0.5–1 day | JSON metrics, resource graphs and integrity results |
| Defect fixes and V6 sign-off | Variable | Signed summary and residual-risk list |

One engineer can execute the plan, but security-negative and load-result review
should receive an independent second-person review before the gate is signed.
If no independent reviewer is available, record that limitation explicitly in
the final residual-risk section.

## 6. V0 — Automated preflight

Run from the repository root:

```bash
pnpm tsc --noEmit
pnpm test
pnpm build

(cd src-tauri && cargo fmt --all --check)
(cd src-tauri && cargo test --lib)
(cd src-tauri && cargo clippy --all-targets -- -D warnings)

cargo test --manifest-path extensions/native-host/Cargo.toml
cargo clippy --manifest-path extensions/native-host/Cargo.toml --all-targets -- -D warnings

node --check extensions/chrome/src/background.js
node --check extensions/chrome/src/content.js
node --check extensions/chrome/src/popup/popup.js
git diff --check
```

Acceptance:

- zero unexpected test failures;
- Clippy and TypeScript return zero;
- production build succeeds;
- no new package-lock or dependency drift;
- the exact counts are written to evidence rather than assumed from the prior
  run.

## 7. V1 — Release artifacts and Native Host registration

### 7.1 Build artifacts

```bash
bash extensions/chrome/scripts/build.sh
pnpm tauri build --bundles app
```

Create Chrome and Firefox archives from their staged `dist` directories and
verify them:

```bash
mkdir -p /tmp/pwdvault-phase5-artifacts
(cd extensions/chrome/dist && zip -qr /tmp/pwdvault-phase5-artifacts/chrome.zip .)
(cd extensions/firefox/dist && zip -qr /tmp/pwdvault-phase5-artifacts/firefox.zip .)

bash extensions/tests/verify_package.sh \
  /tmp/pwdvault-phase5-artifacts/chrome.zip \
  /tmp/pwdvault-phase5-artifacts/firefox.zip

web-ext lint --source-dir extensions/firefox/dist
shasum -a 256 /tmp/pwdvault-phase5-artifacts/*.zip
```

If `web-ext` is unavailable, V1 is **BLOCKED**, not passed. Install it in the
controlled test environment, record `web-ext --version`, and rerun. Do not add
an unpinned project runtime dependency solely for this test tool.

### 7.2 Load the exact staged artifacts

Do not load `extensions/chrome/src` or the Firefox symlink tree. Extract and
load the exact archives being evaluated:

```bash
mkdir -p /tmp/pwdvault-phase5-artifacts/chrome-unpacked
mkdir -p /tmp/pwdvault-phase5-artifacts/firefox-unpacked
unzip -q /tmp/pwdvault-phase5-artifacts/chrome.zip \
  -d /tmp/pwdvault-phase5-artifacts/chrome-unpacked
unzip -q /tmp/pwdvault-phase5-artifacts/firefox.zip \
  -d /tmp/pwdvault-phase5-artifacts/firefox-unpacked
```

- Chrome: `chrome://extensions` → Developer mode → Load unpacked.
- Firefox: `about:debugging#/runtime/this-firefox` → Load Temporary Add-on →
  select the extracted `manifest.json`.
- Record extension IDs, browser warnings and extension error pages.
- Any manifest warning related to missing files, permissions, service worker or
  Native Messaging is a failure until explained and accepted.

### 7.3 Register and inspect Native Host

1. Copy the Chrome unpacked extension ID.
2. Register both browsers:

```bash
bash extensions/chrome/scripts/install-native-host.sh \
  <chrome-extension-id> pwdvault@pwdvault.app
```

3. Launch the packaged application once so registration runs.
4. Inspect:

```bash
CHROME_NM="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.pwdvault.app.json"
FIREFOX_NM="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts/com.pwdvault.app.json"

python3 -m json.tool "$CHROME_NM"
python3 -m json.tool "$FIREFOX_NM"
ls -l "$CHROME_NM" "$FIREFOX_NM"
```

Validate manually:

- both `path` values are absolute and point to the bundled
  `pwdvault-native` regular executable;
- the host is executable by the current user;
- Chrome contains only `allowed_origins` with the observed Chrome ID;
- Firefox contains only `allowed_extensions` with
  `pwdvault@pwdvault.app`;
- manifest and config files are not group/world writable;
- restarting/reinstalling the app refreshes paths idempotently;
- `lsof -nP -iTCP:17429 -sTCP:LISTEN` shows only the test PwdVault process.

V1 acceptance:

- both exact release archives pass the checker;
- Firefox lint returns zero errors;
- both browsers load without relevant manifest errors;
- both Native Host manifests are correct and permissions are restricted;
- hashes and sanitized manifest copies are retained.

## 8. V2/V3 — Browser E2E matrix

Run the full matrix once in Chrome and once in Firefox. Use a fresh browser
profile for each browser, then repeat the persistence-sensitive subset after a
browser restart.

### 8.1 Local test sites and data

Serve two distinct local hostnames. Prefer `a.localhost` and `b.localhost`; if
the browser/system does not resolve them independently, add temporary test-only
hosts entries through the normal administrator process and remove them after
the run.

```bash
python3 -m http.server 18080 --bind 127.0.0.1 \
  --directory extensions/chrome
```

Open:

- `http://a.localhost:18080/test-page.html`
- `http://b.localhost:18080/test-page.html`

Create synthetic entries:

| ID label | URL | Purpose |
|---|---|---|
| A-LOGIN | `http://a.localhost:18080/login` | authorized same-domain fill |
| B-LOGIN | `http://b.localhost:18080/login` | cross-domain negative test |
| EMPTY-URL | empty | must not be available to a content script by ID |

The operator should record entry IDs in a temporary uncommitted test note and
delete it after the run.

### 8.2 Functional state matrix

| Case | Action | Expected result |
|---|---|---|
| E2E-01 Disconnected | Quit PwdVault, open popup | Clear disconnected state; no endless spinner or secret data |
| E2E-02 Handshake | Start packaged app, initiate pairing | Protocol 1 succeeds; no direct HTTP permission is requested |
| E2E-03 Pairing | Enter displayed six-digit code | Pair succeeds once; popup transitions predictably |
| E2E-04 Locked | Pair while vault is locked | Status is locked; entry lists/secrets are not returned |
| E2E-05 Unlock | Unlock with synthetic master password | Unlocked state and normal list appear |
| E2E-06 Empty | Use an empty test vault | Explicit empty state, not loading or generic error |
| E2E-07 Loading | Reload/open popup during a delayed request | Loading state is visible and controls do not double-submit |
| E2E-08 Error | Stop app during an operation | Sanitized recoverable error; no raw path/token/stack trace |
| E2E-09 Same domain | On `a.localhost`, request/fill A-LOGIN | Username/password fill only after user action |
| E2E-10 Multiple entries | Add two A-domain entries | Correct chooser/count; selected entry fills |
| E2E-11 Lock cleanup | Open overlay/show a secret, then lock from desktop | Overlay, cached entries and visible secret disappear |
| E2E-12 Worker restart | Stop/restart extension service worker only | Token survives worker suspension and connection resumes |
| E2E-13 Browser restart | Fully restart browser | Session token is absent; re-pair is requested by design |
| E2E-14 Revoke | Pair, then use Settings → Revoke Extension Access | Existing extension token fails; pending state is cleared |
| E2E-15 Re-pair | Pair again after revoke | New pairing succeeds; old token remains invalid |
| E2E-16 Accessibility | Keyboard-only popup core flow at 200% zoom | No clipped action; Enter/Space expansion and focus visible |

### 8.3 Browser DevTools evidence

For Chrome, inspect the extension service worker from `chrome://extensions`.
For Firefox, inspect it from `about:debugging`. Record:

- service worker/background console contains no uncaught exception;
- handshake response reports protocol 1 and expected capabilities;
- no request is made directly from the extension to port 17429;
- no remote external resource request occurs;
- manifest has no loopback `host_permissions`;
- errors use `error_code/error_message` and contain no secret data.

## 9. Security-negative browser cases

These cases are mandatory in both browsers where the browser exposes the
required developer console.

### 9.1 Cross-domain arbitrary ID

From the content-script context on `a.localhost`, send `GET_ENTRY` using the
temporary B-LOGIN ID.

Expected:

- response is rejected with `Entry is not authorized for this site` or the
  equivalent stable error;
- B secret is never returned or copied;
- A-domain access still works afterward;
- background logs show metadata authorization before any secret request.

Repeat with EMPTY-URL. It must also be rejected.

### 9.2 Content-provided URL spoof

From `a.localhost`, send `GET_ENTRIES_FOR_URL` with a payload URL pointing to
`b.localhost`.

Expected: background ignores the payload URL and derives `a.localhost` from
`sender.tab.url`; B-LOGIN is absent.

### 9.3 Content-script command escalation

Attempt content-script messages for:

- `GET_ENTRIES`;
- `EXPORT_VAULT`;
- `UPDATE_SETTINGS`;
- `CREATE_ENTRY`;
- `LOCK_VAULT`.

Expected: every request is rejected by sender authorization and produces no
state change.

### 9.4 Token storage isolation

From a content-script context attempt to read `pwdvault_api_token` from both
`storage.session` and `storage.local`.

Expected:

- the token is unavailable/inaccessible;
- `storage.local` contains no legacy readable token;
- trusted extension background context may use the session token;
- after browser restart the session token is gone;
- screenshots/logs must not expose the actual token even in the trusted
  background context.

### 9.5 Pairing misuse

- Request one pairing challenge and wait more than 30 seconds before confirm:
  confirm must fail.
- Submit five wrong codes against a new challenge: the correct code must fail
  afterward.
- Start a fresh challenge and complete it once: replay must fail.
- Starting Firefox pairing must not invalidate an active Chrome challenge, and
  vice versa.

The last case requires both browsers open concurrently and is the real-browser
counterpart to the caller-isolation unit test.

## 10. V4 — Protocol and local HTTP rejection matrix

Create a standard-library-only harness at
`scripts/phase5/native_bridge_probe.py`. It must default to loopback, refuse
non-loopback targets, apply per-case timeouts and redact authorization values.

The probe sends raw HTTP and records status, bounded response size and elapsed
time for:

| Case | Mutation | Expected |
|---|---|---|
| HTTP-01 | `GET /api/handshake` | 405 |
| HTTP-02 | missing Content-Type | 415 |
| HTTP-03 | non-JSON Content-Type | 415 |
| HTTP-04 | missing Content-Length | 411 or deterministic parser rejection |
| HTTP-05 | zero Content-Length | 411 |
| HTTP-06 | declared/actual length mismatch | sanitized rejection; no hang beyond timeout |
| HTTP-07 | length above 10 MiB | immediate bounded rejection |
| HTTP-08 | invalid JSON | stable request rejection |
| HTTP-09 | missing protocol version | explicit upgrade error |
| HTTP-10 | protocol version 0/2/large | explicit upgrade error |
| HTTP-11 | path/command mismatch | 404 |
| HTTP-12 | missing Origin label | forbidden |
| HTTP-13 | missing caller on pair | pairing rejected |
| HTTP-14 | unauthenticated protected command | unauthorized |
| HTTP-15 | unauthenticated unknown command | unauthorized without revealing command existence |
| HTTP-16 | newline/header injection attempt | parser rejects; no injected header observed |

Also add a native-frame probe for the host executable:

- zero-length frame;
- invalid UTF-8/JSON;
- missing protocol version;
- unsupported protocol version;
- declared frame above 10 MiB;
- server response above 1 MiB using a controlled fake loopback server.

The host must exit or return a bounded JSON error without frame desynchronization,
unbounded allocation or secret-bearing diagnostics.

## 11. V5 — Adversarial load test

### 11.1 Harness design

Create `scripts/phase5/adversarial_load.py` using Python's standard library or
`asyncio`; no application runtime dependency is required. The harness must:

- refuse non-loopback targets;
- cap its own concurrency and memory;
- use deterministic seeds and record them;
- support `--clients`, `--duration`, `--profile` and `--output`;
- close every socket in `finally` blocks;
- never print Bearer tokens or secrets;
- emit JSON plus human-readable summaries;
- return non-zero when an acceptance threshold fails.

Add `scripts/phase5/monitor_process.sh` or an equivalent sampler that records at
one-second intervals:

- PID and elapsed time;
- total threads and names where available;
- RSS and CPU;
- open file descriptors;
- established/listening port-17429 sockets;
- probe handshake latency and success rate.

Before attack traffic, collect a 60-second idle baseline. During every profile,
run a separate legitimate handshake probe every second.

### 11.2 Load profiles

#### LOAD-01 — Baseline throughput

- 1,000 complete handshake requests;
- concurrency 32;
- valid headers/body/caller label;
- no authentication required.

Purpose: establish normal latency/error rate before adversarial traffic.

#### LOAD-02 — Queue saturation

- 1,000 clients total;
- at least 100 concurrent valid requests;
- mix fast handshake requests with deliberately blocked request bodies;
- hold bodies long enough to occupy all 8 workers and the 64-slot queue.

Expected:

- excess complete requests receive 503 rather than creating new workers;
- exactly the configured worker pool remains present;
- app does not crash or deadlock;
- after release, the queue drains and valid requests recover.

#### LOAD-03 — Slow body / slowloris

- 1,000 connection attempts in controlled waves;
- valid headers with a non-zero Content-Length;
- send body bytes slowly, pause mid-body or send no body;
- include disconnect-before-body and disconnect-mid-body variants.

Purpose: verify the actual `tiny_http` connection behavior, not merely the
application queue. If sockets or internal threads grow beyond limits, Phase 5
fails even though the explicit worker count is eight.

#### LOAD-04 — Malformed request storm

- 10,000 bounded requests over 60 seconds;
- rotate the HTTP-01 through HTTP-16 mutations;
- maximum individual request size 64 KiB except the declared oversize case.

Expected: deterministic bounded responses, no panic, no log amplification with
secrets, and no sustained resource growth.

#### LOAD-05 — Pairing abuse

- exceed 10 pair requests in one minute;
- mix callers, wrong nonce, wrong caller, expired session and five wrong codes;
- keep one legitimate Chrome/Firefox session active.

Expected:

- rate limiting activates;
- caller B cannot consume caller A's challenge;
- wrong caller/nonce does not reduce A's attempts;
- the app remains usable and can pair again after the rate-limit window.

#### LOAD-06 — Frame and body boundaries

Exercise sizes around each limit:

- request: limit minus 1, exact limit, limit plus 1;
- response: 1 MiB minus 1, exact 1 MiB, 1 MiB plus 1;
- body: 10 MiB minus 1, exact 10 MiB, declared 10 MiB plus 1.

Use synthetic payloads only. Confirm no integer wrap, excessive preallocation or
truncated-success response.

#### LOAD-07 — Recovery and auto-lock

While LOAD-02/03/04 runs:

- interact with the desktop UI;
- confirm activity tracking remains responsive;
- allow the configured short auto-lock interval to expire;
- verify lock occurs within tolerance;
- stop traffic and repeat handshake, unlock and same-domain fill.

### 11.3 Quantitative acceptance thresholds

Measure all deltas against the 60-second idle baseline on the same machine.

| Metric | Mandatory threshold |
|---|---|
| Named application HTTP workers | Exactly 8; never increases with clients |
| Total PwdVault process threads | Peak no more than baseline + 16; investigate any `tiny_http` growth |
| Request queue | Effective capacity no more than 64; overflow returns 503 |
| RSS | Peak delta ≤128 MiB; 60 seconds after test ≤ baseline +32 MiB |
| Open FDs | No monotonic growth; 30 seconds after test ≤ baseline +10 |
| Crash/panic/deadlock | Zero |
| Corrupted/lost vault data | Zero |
| Secret/token in logs | Zero |
| LOAD-01 error rate | 0%; p95 ≤500 ms on the reference machine |
| Legitimate probe during attack | May receive 503, but must complete/fail within 35 s; no indefinite hang |
| Recovery | ≥99% success within 10 s after attack sockets close; p95 ≤1 s |
| Auto-lock | Fires within configured deadline +2 s after activity stops |
| UI responsiveness | No permanent freeze; lock/recovery actions usable after queue drains |

These thresholds are release requirements, not descriptions of current
behavior. A failure—especially excess sockets/threads in LOAD-03—means the
current bounded request queue is insufficient and a connection-level limit or
socket transport fix is required.

Run each profile three times. A flaky pass counts as a failure until explained.
Between runs restart PwdVault and confirm baseline returns.

### 11.4 Post-load integrity checks

After every run:

1. stop the harness and confirm all test sockets close;
2. wait 60 seconds and capture recovery metrics;
3. lock, unlock and list all synthetic entries;
4. create/update/delete one synthetic entry;
5. export a test backup and validate import into a new disposable vault;
6. rerun Rust/frontend smoke tests if a panic or integrity warning appeared;
7. inspect logs for passwords, token-shaped 64-hex values, raw request bodies
   and stack traces.

## 12. Windows deferral boundary

Windows is skipped for this execution and is not a failure of the macOS gate.
The following remain explicitly open:

- Chrome/Firefox Native Messaging E2E on supported Windows versions;
- registry keys and distinct manifest paths;
- executable path quoting with spaces and non-ASCII user profiles;
- Windows ACLs for config, manifests and host executable;
- Chrome `--parent-window` launch argument compatibility;
- Windows browser restart/token behavior;
- adversarial load behavior and process-handle recovery;
- eventual named-pipe transport.

The release summary must say **“Phase 5 macOS gate passed; Windows validation
deferred”**, never “Phase 5 cross-platform validation passed.”

Windows work may resume when a clean Windows runner/VM with Chrome and Firefox
is available. It should reuse the same case IDs, synthetic data and evidence
schema, adding Windows registry/ACL-specific cases rather than rewriting this
plan.

## 13. Defect severity and retest policy

| Severity | Examples | Release action |
|---|---|---|
| P0 | Secret/token disclosure, vault corruption, caller/sender bypass | Immediate stop; release frozen |
| P1 | Cross-domain secret access, unbounded resource growth, crash/deadlock, revoke failure | Release frozen until fixed and full V0–V6 rerun |
| P2 | Recoverable browser-specific functional failure, inaccessible core action | Fix before macOS gate closes |
| P3 | Cosmetic issue with no accessibility/security impact | May defer with owner/date |

Security or transport changes require:

- targeted regression test;
- full automated V0;
- affected browser matrix rerun;
- all load profiles touching the changed layer;
- new artifact hashes and evidence. Old evidence cannot be reused for rebuilt
  binaries or extension archives.

## 14. Final exit checklist

Phase 5 macOS validation may be marked passed only when all boxes are checked:

- [ ] V0 automated gates pass on the final source state.
- [ ] Exact Chrome/Firefox archives are hashed and self-contained.
- [ ] Firefox `web-ext lint` passes.
- [ ] Both archives load in their target browsers without relevant errors.
- [ ] Both generated Native Host manifests and permissions are correct.
- [ ] Chrome E2E-01 through E2E-16 pass.
- [ ] Firefox E2E-01 through E2E-16 pass.
- [ ] Cross-domain, URL spoof, command escalation and token isolation cases pass.
- [ ] Expiry, attempts, replay and concurrent caller isolation pass in browsers.
- [ ] HTTP/frame rejection matrix passes.
- [ ] LOAD-01 through LOAD-07 pass three consecutive runs.
- [ ] Auto-lock, UI recovery and post-load vault integrity pass.
- [ ] Logs/evidence contain no secrets.
- [ ] No unresolved P0/P1/P2 defects remain.
- [ ] `summary.md` records macOS PASS and Windows DEFERRED accurately.

Only after this checklist is signed off should the team either close the macOS
portion of Phase 5 or schedule the explicitly deferred socket/pipe work. Phase 6
should not absorb unresolved security or load failures from this gate.

## 15. Automation implementation status

The first automation tranche is implemented under `scripts/phase5/`:

- `run_macos_gate.sh` / `run_gate.py` — fast and release-macos orchestration;
- `native_bridge_probe.py` — live HTTP rejection matrix;
- `native_host_probe.py` — process-level frame/caller/response-limit probe;
- `adversarial_load.py` — baseline, malformed and saturation profiles, capped
  at 1,000 loopback clients;
- `monitor_process.py` — RSS/CPU/thread/FD/socket sampling;
- `evaluate_resources.py` — automatic baseline/attack threshold evaluation;
- `report.py` — JSON and Markdown aggregation;
- dependency-free unit tests and explicit token redaction.

Remaining automation work before this plan is fully executable:

1. add real Chrome and Firefox E2E drivers/evidence ingestion;
2. expand load profiles to three-run orchestration and automatic baseline-delta
   threshold enforcement;
3. add post-load vault CRUD/export/import integrity automation.

The first live runtime rerun completed on 2026-07-16: all 16 bridge cases,
all three 1,000-client load profiles and all resource thresholds passed. Items
1–3 remain open.
