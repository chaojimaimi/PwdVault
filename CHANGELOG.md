# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.1.8] - 2026-09-19

### Security

- The three exclusive vault windows (cloud-sync merge, master-password
  change, recovery-key reseal) are now mutually exclusive. Previously two
  overlapping windows could interleave and either corrupt the integrity
  digest (vault locked out until restore) or silently drop remotely merged
  entries. Digest writes are now verified against the current digest before
  refresh and fail closed on stale-key writes; a lock requested during a
  window is never silently undone.
- Browser extension: popup "Auto-fill" now verifies the entry's domain
  against the active page (content-side, fail-closed) before injecting
  credentials — an unrelated entry can no longer be filled into a lookalike
  page from the popup. Context-menu and keyboard-shortcut fills are
  unchanged.
- Recovery-key and biometric wrap-key material is zeroized along all
  handling paths (IPC boundary through key derivation).

### Changed

- WebDAV sync now requires `https://`. Plain-http server URLs are rejected
  when connecting a new server ("WebDAV server URL must use https:// — plain
  http would expose your cloud-drive password"), and an already-persisted
  http configuration fails on the next sync with the same guidance: open
  Settings → Sync and update the server URL to its https form.
- Windows: cloud-sync credentials (the WebDAV password and the Baidu token)
  are now encrypted at rest with Windows DPAPI. Entries in the credential
  file are stored as `dpapi1:`-prefixed blobs instead of plain base64; the
  first credential write after updating re-encrypts the whole file.

### Behavior notes / downgrade

- A credential file written by the new Windows version contains `dpapi1:`
  entries that older versions cannot read: an old client reports the sync
  credentials as unavailable/corrupt ("encrypted by the Windows version").
  Run matching (current) versions on all installations that share a synced
  vault profile. Conversely, files written on Windows stay readable on
  Linux: reading one is refused per credential, and rewriting a credential
  preserves the Windows-encrypted entries untouched.

### Fixed

- The unlock screen no longer masks a rate-limit lockout as "Invalid
  password"; the backend lockout copy (with retry seconds) is shown.
- The vault list now reloads after a completed cloud sync, so entries and
  groups pulled from another device are visible without relocking.
- The extension register-form detection honors `autocomplete="new-password"`
  as a hard signal, and the popup password-strength meter now uses the same
  algorithm as the desktop app.
- TOTP codes no longer get stuck when a code fetch fails (retry with
  backoff; polling stops for not-configured entries), and the TOTP secret
  field is masked with a reveal toggle.
- Miscellaneous: unanchored `www.` stripping in the extension, popup toast
  timer race, pairing failures now show connection-specific guidance,
  quick-create generator honors the configured default length, group
  manager reload errors are handled, group rename input and tabs are
  labeled for screen readers.

### Added (P2 hardening batch)

- React hooks linting (react-hooks rules-of-hooks=error / exhaustive-deps=warn)
  and jsx-a11y recommended rules are now enforced in ESLint; the dependency-
  array gaps they surfaced were fixed (VaultScreen / GroupManager / Generator
  mount effects via a latestRef pattern, GroupSelector explicit deps, Security
  status probe stabilized with useCallback), and six `autoFocus` props were
  converted to equivalent programmatic focus.
- Clipboard auto-clear now uses the Tauri clipboard plugin inside the desktop
  app (works while the window is unfocused), and a failed scheduled clear is
  retried once and then surfaced via a one-time toast instead of failing
  silently. Capabilities grant only `clipboard-manager:allow-write-text` /
  `allow-read-text`.
- CI: least-privilege `permissions` blocks across quality.yml and release.yml
  (read-only for all build/test jobs; release-writing jobs keep their scopes),
  CodeQL results are uploaded to code scanning again, the workspace test suite
  runs on Windows in CI (new `quality-rust-windows` job), and a dead
  generate-only updater-feed step was removed from the release pipeline.
- Frontend: `VaultError` TS type regenerated from the full 22-variant Rust
  enum, `isVaultError` type guard added, rate-limit rejections surface as
  "Too many attempts — retry in Ns".
- Browser extension: the context-menu (right-click) actions no longer fail
  silently — the vault-locked state, a missing entry, and unreachable pages
  now give on-page feedback or a service-worker warning.
- Test files are type-checked (`pnpm typecheck` covers app and tests; CI uses
  the chained script).

## [1.1.7] - 2026-09-18

### Added

- In-app automatic updates: the app now checks a signed update feed on
  startup (when "Check for updates" is enabled), shows a banner with
  download progress, and installs the new version after signature
  verification — no manual download required. Update packages are minisign
  signed in CI; the public key ships inside the app (see
  docs/UPDATER-KEYS.md).
- WebDAV/Baidu sync: first-release bootstrap now creates the remote
  directory automatically and the updater feed is published with every
  release.
- Behavior note: 1.1.6 clients do not have the updater — update this one
  time by installing 1.1.7 manually; from 1.1.8 on, updates arrive in-app.

### Fixed

- Sync: the first-ever Connect no longer fails with
  SYNC_CREDENTIALS_MISSING (the WebDAV password is persisted before the
  backend is resolved).
- Sync: WebDAV servers that answer 409 (missing ancestor collection —
  Nutstore/jianguoyun) on the first status probe no longer abort the
  initial connect.
- Touch ID setup no longer fails with -34018 on unsigned local builds
  (legacy login-keychain fallback with the same biometric access control).
- clippy on the latest stable toolchain (drop_non_drop, unused imports in
  split test modules).

## [1.1.6] - 2026-09-16

### Added

- Change master password: the whole vault is re-encrypted in a single
  transaction under a freshly benchmarked KDF parameter set, serialized
  against concurrent writes through an exclusive session drain, and a
  timestamped `.bak` of the database file is taken automatically. Enabling
  recovery requires re-entering the recovery key as proof of custody.
- Touch ID unlock (macOS): a random wrap key is stored in the macOS Keychain
  under a biometric access control (current fingerprint set, this device
  only); the master key is wrapped with AES-256-GCM and unlocked through the
  same integrity verification chain as password unlock. Requires the current
  master password to enable; legacy (unmigrated) vaults must migrate first.
- Recovery key (Emergency Kit): a random 256-bit recovery key is shown exactly
  once at enable time (copy or export as a text file). If the master password
  is ever forgotten, the recovery key unlocks the vault and sets a new master
  password — all from the lock screen, no other machine required.
- New Security section in Settings and a recovery entry point on the lock
  screen; all nine security commands are desktop-only and are never exposed
  to the browser extension bridge.
- TOTP two-factor code support: store a TOTP secret on any entry (paste a
  base32 secret or an `otpauth://` URI) and read live 6-digit codes with a
  countdown in the entry editor (RFC 6238, SHA-1/SHA-256). TOTP secrets are
  encrypted like passwords and re-encrypted on master password change.
- Cloud sync across your own devices (WebDAV today; Baidu Netdisk backend
  included — requires registering your own open-platform AppKey, see
  `docs/BAIDU-SETUP.md`). Zero-knowledge by design: the cloud only ever sees
  a self-contained encrypted container; merging happens on-device with
  last-writer-wins semantics and rolling versioned snapshots (last 10 kept)
  so nothing is ever silently lost. Connecting a device requires the
  container password once; subsequent syncs are password-free.
- Soft delete: removed entries/groups are retained as tombstones so deletions
  merge correctly across devices. Exports exclude deleted items.
- Behavior notes: vaults written by 1.1.6 cannot be read by older app
  versions (extra record fields); sync containers are version-gated so
  mismatched app versions will not sync with each other.

### Security

- Close a vault-integrity bypass: a deleted vault header no longer falls back
  to silent legacy migration — unlock now fails closed with migration guidance,
  the migration branch verifies any existing digest before re-baselining, and
  plaintext record decoding is restricted to the legacy migration path so
  injected plaintext entries can no longer be accepted at runtime. Users
  upgrading from pre-1.0.5 vaults that were never opened by v1.0.5+ must first
  migrate with PwdVault 1.1.4, or restore from a backup.
- Refuse `init_vault` when a verification row already exists on disk,
  preventing a startup race from overwriting an existing vault.
- Alert in the UI when the extension bridge server cannot bind its port
  (previously a silent log entry), since a pre-bound port could capture
  unlock requests including the master password.
- Cap decoded blob sizes (1 MiB) before bincode deserialization of on-disk
  records, preventing allocation abuse from tampered databases.
- Import policy: backups whose KDF parameters fall below the OWASP floor
  (19 MiB / 2 iterations) are now rejected at import. Vault unlock is
  unaffected — vaults created with legacy parameters keep unlocking; newly
  generated exports/parameters always meet the floor. Note: backups exported
  by old versions on very slow machines (t=1) can no longer be re-imported —
  unlock the vault and re-export to produce a compliant backup.
- Narrow the WebView filesystem scope: import/export can only read/write the
  user's home directory tree, external volumes, and temp folders, and can
  never touch the vault's own data directory (macOS Library path and Windows
  LOCALAPPDATA), limiting blast radius if the WebView is compromised.
- Browser extension: the autofill prompt no longer prefetches the plaintext
  password on page load — the secret is fetched only when the user clicks
  Fill; authorization now uses the frame's own URL; register/change-password
  forms gate automatic prompts; a failed pairing confirm or reopening the
  popup while its code is still live no longer rotates the desktop app's
  pairing code (only "Get New Code" does); the generator slider no longer
  spawns a native host process per pixel of drag.
- Compare pairing codes and nonces in constant time; validate native-host
  command names against a strict `[a-z_]` whitelist; cap update-check
  response bodies at 1 MiB.

### Fixed

- Touch ID setup no longer fails with "Security framework error -34018" on
  unsigned local builds: the Keychain store now falls back from the
  data-protection keychain (which requires signed entitlements) to the legacy
  login keychain, which enforces the same biometric access control.
- Auto-lock now counts local user activity (typing, pointer) via a throttled
  `touch_activity` IPC, not only vault API calls, so editing an entry no
  longer risks a silent mid-edit lock and reload.
- Clipboard auto-clear timers are reset on re-copy of the same value, and the
  content-script variant compares digests instead of keeping plaintext in a
  closure.
- Manual lock uses try/finally so the UI always returns to the unlock screen
  even if the backend call errors.
- The extension server now binds its port with SO_REUSEADDR and retries
  address-in-use errors (1s/2s/4s), surviving the TIME_WAIT window after an
  app restart; other bind errors fail fast into the existing warning toast.
- Pairing errors are no longer misleading: a host-launch failure shows
  "Cannot reach the PwdVault desktop app…", a server rejection shows the
  server's message, and only a real protocol mismatch shows the
  update-your-app guidance.
- Floating autofill button positions correctly while scrolling and removes
  itself when the login form disappears.
- Nested dialogs closing out of order no longer leave the app invisible to
  screen readers (inert/aria-hidden snapshot is owned by the first dialog
  and restored only when the last one closes).
- EntryScreen quick generator now honors the default generator settings; the
  extension generator slider label is addressed by id instead of a fragile
  DOM-order selector.
- Remove dead `KeyStore` module, unused strength color metadata, and
  non-constant-time pairing comparisons; harden startup unwrap points
  (`current_dir`, window icon) and add a re-entrancy guard to Restore
  Backup; `AccessibleDialog` now supports nested dialogs (inert reference
  counting, stack-top Escape handling).

## [1.1.5] - 2026-07-22

### Fixed

- Register Chrome and Firefox Native Messaging manifests in both the 32-bit
  and 64-bit HKCU registry views, replacing stale legacy entries that Chrome
  queries before the current 64-bit registration.
- Add a Windows registry integration test and a user-safe inspection/repair
  script for both Chrome Native Messaging registry views.
- Remove the baked white matte from the application and browser-extension
  icons, regenerate transparent PNG/ICO/ICNS assets, and enforce transparent
  corner pixels in the quality workflow.

## [1.1.4] - 2026-07-21

### Fixed

- Put Windows Native Messaging stdin/stdout into mandatory `O_BINARY` mode
  before reading or writing Chrome's length-prefixed protocol frames.
- Add a Windows process-level smoke test that launches the packaged Host with
  Chrome arguments, forwards a handshake through a mock loopback server, and
  validates the exact framed response bytes.

## [1.1.3] - 2026-07-21

### Fixed

- Build the Windows Native Messaging host with the statically linked MSVC CRT
  so Chrome and Firefox can launch it on systems without a separately installed
  Visual C++ Redistributable.
- Add a Windows PE release gate that rejects missing, wrong-architecture,
  non-stdio, or dynamically VC++-linked Native Host binaries before packaging.
- Run a dedicated Windows Native Host build/test job on every push and pull
  request, closing the platform gap that allowed the v1.1.2 loader failure.
- Translate Chrome's generic Native Messaging communication failure into an
  actionable desktop-update/reinstall message.

## [1.1.2] - 2026-07-19

### Fixed

- Restore desktop backup/export IPC compatibility by using Tauri's camelCase
  command arguments for export and import passwords.
- Preserve historical entries with an empty URL by normalizing blank optional
  URLs to `None` across create, update, export, and import boundaries.
- Authorize the minimal Tauri filesystem commands required by the system file
  picker (`write_file`, `read_file`, and `stat`) so encrypted backups can be
  saved and restored on desktop platforms.
- Surface stage-specific backup generation and file-save errors instead of a
  generic `Export failed` notification, with structured backend diagnostics.

## [1.1.1] - 2026-07-19

### Fixed

- Preserve historical username-only/empty-password records during encrypted
  backup export/import without weakening new-entry validation.
- Make Chrome/Firefox extension ZIP generation deterministic and fail release
  workflows on missing, linked, or invalid package content.
- Correct Firefox MV3 background loading and store metadata; strict `web-ext`
  lint now passes with zero warnings.
- Harden extension popup markup rendering and quote escaping.
- Repair Quality/CodeQL/Release gates, dependency audit registry selection, and
  10-source Cargo/product version consistency.

## [1.1.0] - 2026-07-18

### PwdVault Comprehensive Optimization Plan v1.0.5 (Phases 0–5)

Implementation of `docs/PwdVault-Comprehensive-Optimization-Plan-v1.0.5.md`.
Each phase has a dedicated progress document under `docs/PHASE{n}-PROGRESS.md`.

#### Phase 1 — Transaction, Session & Integrity (§5.1)

- **§5.1.1** `VaultSession` state machine with RwLock-backed lease mechanism; replaces scattered `keystore`/`mac_key`/`last_activity`/`op_lock` fields with a unified concurrency model across Tauri IPC, HTTP, and auto-lock.
- **§5.1.2** `VaultStore::write()` atomic single-transaction pattern; business mutations and digest refresh now commit in one redb `WriteTransaction`, eliminating the crash window that left stale digests.
- **§5.1.2** Removed `last_used_at` write-amplification from `get_entry_secret` (frontend confirmed not using it).
- **§5.1.3** Two-phase unlock: keys stay in local `Zeroizing` scope until all verification (rate limit → password → header → digest → migration → settings) passes, then published atomically via `session.unlock()`.
- **§5.1.4** AEAD-authenticated `VaultHeader` with `integrity_required` flag; AES-GCM AAD = `table_name || record_id || record_format_version` per record; digest version bumped to v4; migration refuses to auto-refresh baseline for unknown/missing digests; pre-migration backup `vault.db.{timestamp}.bak`.
- **§5.1.5** `SecretKey` (`ZeroizeOnDrop`, non-Copy/Clone) adopted across all key paths; `KeyStore::with_key` closure borrowing; `Zeroizing` buffers for master key, subkeys, migration plaintext, codec serialization; error/log redaction.

#### Phase 2 — Unified Input Boundary & Backup Security (§5.2)

- **§5.2.1** Centralized `ValidationPolicy` shared by Tauri IPC, HTTP, and Native Messaging; stable `InvalidInput { code, message }` error codes; group references validated, names unique case-insensitively.
- **§5.2.2** `KdfPolicy` validates Argon2 params before memory allocation (16–256 MiB, 1–10 iterations, 1–8 parallelism, 1 GiB combined ceiling); extreme values rejected in the fast pre-derivation path.
- **§5.2.3** Backup v2 envelope with `PWDVAULT` magic, `argon2id`/`aes-256-gcm` identifiers, header authenticated as AES-GCM AAD; import ordering bounded (size → lengths → algorithms → derivation → decryption → payload validation → single-transaction replacement); ciphertext capped at 10 MiB.
- **§5.2.4** Explicit migration registry (`LegacyToV1`, sequential `vN→vN+1`); unknown/skipped versions fail closed; corrupt stored settings return error instead of silent default fallback.
- **§5.2.5** Unix file permissions: data/log dirs `0700`, sensitive files `0600`; database pre-created with restrictive permissions before redb opens it; native-messaging manifest/config use same helpers; startup repairs app-owned paths. (Windows ACL pending.)

#### Phase 3 — Frontend Data Fidelity & Privacy (§5.3)

- **§5.3.1** Independent `idle | loading | success | error` status for entries/groups/settings; loading failures no longer render as empty data; boot detection failure shows fatal error with Retry.
- **§5.3.2** Update-network access gated on unlocked vault + successful settings load + `check_updates=true` + trusted feed + once-per-startup; private builds default `VITE_UPDATE_CHECK_ENABLED=false`.
- **§5.3.3** `GroupSelector` consumes `VaultContext` (no private API copy); create/delete refreshes global groups and entries; deleting selected filter returns to All.
- **§5.3.4** Backend `UpdateEntryRequest` with optional password and `update_notes` flag; metadata-only patches preserve encrypted secrets without decryption; edit screens fetch password/notes on demand only.
- **§5.3.5** Clipboard timeout retains SHA-256 digest, not plaintext; clears only if digest still matches; username copying no longer uses sensitive auto-clear path. (Native pasteboard change-count tracking deferred.)
- **§5.3.6** Generator/Settings reject all-charset-disabled state; Entry/Settings/extension Create track dirty state and warn before navigation.

#### Phase 4 — UI, Design System & Accessibility (§5.4)

- **§5.4.1** Local theme bootstrap resolves System/Light/Dark before React; removed Google Fonts and inline scripts; subscribes to `prefers-color-scheme`.
- **§5.4.2** Shared `screen-shell` / `screen-scroll-region` contract; `100dvh`, `flex:1`, `min-height:0`, 350px compaction.
- **§5.4.3** DESIGN.md semantic tokens (`--color-on-primary/on-danger/on-success`); WCAG AA contrast verified; 40px touch targets.
- **§5.4.4** `StrengthMeter` rebuilt on native `<progress>` with `role=meter`, value text, visible label.
- **§5.4.5** Portal-based `AccessibleDialog`: initial focus, Tab trapping, Escape, overlay close, focus restoration, background `inert`; restore requires typing `RESTORE`.
- **§5.4.6** Form/list/notification semantics: explicit labels, real removal buttons, alert/invalid relationships, polite live regions, `role=alert` for errors.
- **§5.4.7** Extension a11y: `aria-expanded` entry headers, polite toast, `prefers-reduced-motion`.

#### Phase 5 — Browser Extension & Native Messaging (§5.5)

- **§5.5.1** Cross-browser native host manifests: Chrome `allowed_origins`, Firefox `allowed_extensions` with stable `pwdvault@pwdvault.app` ID; serde_json serialization; Windows distinct per-browser filenames; obsolete loopback `host_permissions` removed.
- **§5.5.2** Self-contained Chrome/Firefox packages: `src/` layout preserved, Firefox symlinks dereferenced, `verify_manifest.py` / `verify_extension_identity.py` validate references recursively.
- **§5.5.3** Caller-bound pairing: identity derived only from browser launch args; per-caller state with 6-digit code, 128-bit nonce, 30s TTL, 5 attempts; wrong caller/nonce does not consume challenge; `Revoke Extension Access` rotates token and cancels sessions.
- **§5.5.4** Transport limits: 8 fixed workers, 64-request queue (HTTP 503 on overflow), `tiny_http` replaced with direct `TcpListener`; POST + `Content-Type` + bounded `Content-Length` + path match enforced; `Cache-Control: no-store`; 10 MiB inbound / 1 MiB outbound frame caps.
- **§5.5.5** Protocol version 1 on every request; unauthenticated origin-checked `handshake`; stable `error_code`/`error_message`/`retry_after` response fields.
- **§5.5.6** Extension sender/secret boundaries: `sender-auth.js`, `token-storage.js`, `connection-errors.js`; content scripts restricted to `GET_ENTRIES_FOR_URL`/`GET_ENTRY`; cross-domain entry rejected; `storage.session` preferred with `TRUSTED_CONTEXTS`; `VAULT_LOCKED` broadcast clears tab caches.
- **§5.5.7** Phase 5 automation toolkit (`scripts/phase5/`): adversarial load, native bridge/host probes, resource monitor, evidence validator. First adversarial load (1000 malformed requests) passed at ~10ms p95; remediation removed thread-per-request and bounded the queue.

### Pre-optimization baseline (2026-07-04)

The following changes were the v1.0.5 baseline before the comprehensive optimization plan was applied.

#### Phase 6 — Performance, Modularization & Release Engineering (§5.6)

- **§5.6.1** Frontend: removed useApp() facade (9 screens subscribe directly); two-tier search (substring fast-path + Fuse fallback) with useDeferredValue; react-virtuoso list virtualization; memoized EntryRow; GroupManager pre-aggregated count Map; 10k search <100ms verified.
- **§5.6.2** Backend: list_all_entries_bulk / list_all_groups_bulk (single read txn); all N+1 patterns eliminated; init/unlock/import/export on spawn_blocking; cancellable update check; criterion baseline (list 1k=3.7ms, digest 1k=0.8ms).
- **§5.6.3** Workspace: 4-crate split (domain ← infrastructure ← application ← tauri-app); lib.rs 1310→292 lines; golden contract test for IPC↔NM consistency.
- **§5.6.4** CI/CD: 6-job quality pipeline (frontend/rust/native-host/security/version + CodeQL SAST); ESLint; pnpm audit; gitleaks; cargo deny; Actions pinned to SHA.
- **§5.6.5** Version: native-host aligned; bump-version.sh --check; CI hard-fail on 7-source mismatch.
- **§5.6.6** Release: signing framework with graceful degradation (prerelease when unsigned); Chrome Web Store + Firefox AMO upload; SBOM (CycloneDX) + SHA-256 + artifact attestation.

## [1.0.5] - 2026-07-04

### Security

- **B1 元数据加密**: PasswordEntry 与 Group 整体使用 AES-256-GCM 加密（entry_codec / group_codec），title/username/url/tags 等元数据不再以明文存储于 redb
- **B2 全库完整性 MAC**: HMAC-SHA256 全库摘要，unlock 时校验，写操作后刷新，检测任何篡改
- **B3 Zeroizing 替换 unsafe**: 使用 `Zeroizing<String>` 替代 `as_bytes_mut()`，敏感数据出作用域自动清零；移除所有 unsafe 块
- **B4 缩短明文密码生命周期**: `get_entry` 拆分为 `get_entry_meta`（无密码）与 `get_entry_secret`（按需解密），前端 selectedEntry 仅存 meta
- **B5 CSP 去 unsafe-inline**: `style-src 'self'`，动态样式改用 CSS 变量
- **B6 错误信息脱敏**: `VaultError::public_message()` 统一脱敏，HTTP/扩展路径不泄露内部路径

### Architecture

- **A1 Service 层抽取**: 新增 `src-tauri/src/service/`，Tauri commands 与 HTTP handler 共享业务逻辑
- **A2 HTTP 加固 + pair 配对确认**: 6 位配对码、60s 过期、一次性消费，防止 token 枚举
- **A3 keystore 移入 AppState**: 移除全局 static，测试可并行运行（`--test-threads=4` 通过）
- **A4 事件驱动自锁**: deadline-based sleep 替代 30s 轮询，消除锁延迟

### Code Quality

- **C1/C2 tracing 结构化日志**: 引入 tracing + tracing-appender，日志按日滚动至 `<app_data>/logs/pwdvault.log`
- **C3/C4 常量集中**: 新建 `constants.rs`，移除各模块硬编码常量
- **D1 拆分 Context**: AuthContext / VaultContext / SettingsContext 三域分离，AppContext 保持向后兼容
- **D2 数据缓存层**: `useEntries` hook 提供 O(1) 查找 + 乐观更新
- **D3 文档同步**: CLAUDE.md 更新测试数量、移除 test-threads=1 约束

## [1.0.4] - 2026-07-04

## [1.0.3] - 2026-06-17

### Added

- **Native Messaging bridge architecture** — Extension now communicates via the official Chrome/Firefox Native Messaging API instead of direct HTTP fetch
  - New host binary (`extensions/native-host/`) bridges stdio (NM protocol) to the desktop app's HTTP API on 127.0.0.1:17429
  - Host binary bundled into the app via Tauri `resources`; auto-registered with browsers on app startup (`native_host_setup.rs`)
  - Extension carries Bearer token in body field `auth_token` (NM has no HTTP headers); host lifts it into an `Authorization` header
  - `install-native-host.sh` script writes extension IDs to a config file for browser manifest registration
  - Cross-platform registration: file-based on macOS/Linux, registry-based on Windows (`winreg`)

### Fixed

- **pair rate-limit deadlock (pre-existing, v1.0.1)** — The pair handler re-locked `pair_last_reset` Mutex within its own guard scope, deadlocking on first call. Now reads/writes in separate scopes.
- **Body reader over-read (pre-existing)** — `request.as_reader().take(MAX_BODY_SIZE)` blocked on short bodies. Now limited to declared Content-Length.
- **Tauri resources executable bit** — Host binary lost +x when bundled. `register_native_host()` now auto-fixes permissions on every launch.

### Changed

- Removed dead legacy native-host code (stdio→TCP forwarder, stale manifest templates, Chrome-only install script)
- Updated docs (CLAUDE.md, extensions/chrome/README.md, TEST_RESULTS.md) to reflect the NM architecture
- Extension zip repackaged with flat structure (no top-level `dist/` directory)
- Bump version to 1.0.3 across all files

### Known Issues

- Stage 3 (Unix socket / named pipe transport) deferred — TCP port 17429 still open (loopback only)
- Extension IDs unstable in development (load unpacked); use `install-native-host.sh` to configure
- 9-10 pre-existing unit test failures from global-state pollution (keystore/auth singletons)

## [1.0.2] - 2026-06-03

### Fixed

- **Security: remove_group cascade** — Deleting a group now clears `group_id` on all associated entries (prevents orphaned references)
- **Security: Tauri get_entry zeroization** — Plaintext password and notes are zeroized after building response, matching the HTTP API path
- **Security: generate_password explicit error** — Returns error instead of silent fallback when all character types are disabled
- **Architecture: vault.ts HTTP fallback removed** — Eliminated unauthenticated HTTP fallback path; non-Tauri environments now throw a clear error
- **Extension: popup.js DOM hardening** — Password no longer stored in `data-value` attribute; uses `data-id` + memory cache lookup
- **Extension: CSS blur replaced** — Hidden passwords render as Unicode bullet characters instead of blurred plaintext
- **Extension: innerHTML eliminated** — Content script and popup use `textContent` / `createElement` for all user data
- **Extension: host_permissions narrowed** — Restricted to `localhost:17429` only

## [0.3.1] - 2026-04-30

### Added

- **F2: Update notification** — Checks GitHub Releases for newer versions on startup
  - Badge displayed in settings when update is available
  - Uses `ureq` + `semver` crates for version comparison
- **F4: Rate limiting** — 5 failed unlock attempts triggers 60-second lockout
  - Applied to both Tauri unlock command and HTTP API
  - Rate limit state resets on successful unlock

### Changed

- **Theme system redesign** — Replaced Classic/Cyber/Hybrid themes with Light/Dark
  - Two themes: Light (default) and Dark, following OS preference
  - `:root` defines shared tokens; `[data-theme]` overrides colors only
  - Updated `themes.css` and `DESIGN.md` to reflect two-theme system
- **Modular CSS** — Split monolithic `App.css` (1300+ lines) into 6 files:
  - `themes.css` (design tokens), `base.css` (reset/scrollbar/accessibility)
  - `components.css` (buttons/inputs/modals/toasts), `screens.css` (entry/generator)
  - `vault.css` (vault list/search/groups), `groups.css` (group manager)
  - `settings.css` (settings/theme/import-export)
- **New components**: `BackHeader.tsx`, `Icons.tsx`, `StrengthMeter.tsx`, `UpdateNotification.tsx`
- **Browser extension** synced with Light/Dark theme system
- **Cleanup**: Removed stale v0.2.0 release artifacts

## [0.3.0] - 2026-04-17

### Added

- **E2: Fuzzy search** — fuse.js based search across title, username, URL, tags
  - Desktop app and browser extension both use consistent Fuse.js config
  - Weighted search keys: title (0.4), username (0.3), url (0.2), tags (0.1)
- **E4: Settings screen** — User-configurable vault behavior
  - Auto-lock timeout (1–60 minutes) persisted to database
  - Default password generator options (length, character types)
  - Dynamic auto-lock reads timeout from settings instead of hardcoded constant
  - Backward compatible: pre-v0.3 vaults fallback to default settings
- **E1: Encrypted import/export** — Backup and restore vault data
  - Export creates `.pvault` file encrypted with user-chosen export password
  - Export password is independent of master password (portable backups)
  - AES-256-GCM encryption with Argon2id key derivation
  - Import replaces current vault data with confirmation prompt
  - Settings, groups, and entry timestamps preserved on import
  - Tauri file dialog for save/open + browser fallback download

## [0.2.0] - 2026-04-15

### Added

- **Design system implementation**: Three visual themes (Classic, Cyber, Hybrid) fully applied to all screens
  - Type scale variables (`--text-h1` through `--text-micro`) per DESIGN.md
  - Spacing tokens (`--space-xs` through `--space-2xl`, 4px base unit)
  - Icon style tokens (`--icon-style`: solid / hollow / glow per theme)
- **Group tabs UI**: Replaced `<select>` dropdown with horizontal scrollable group filter tabs
  - Active tab highlighted with primary color
  - Manage groups gear icon in tabs bar
  - "Create group" prompt when no groups exist
  - Search input with magnifying glass icon
- **Theme-specific effects**:
  - Cyber: hollow entry icons (border + glow outline)
  - Hybrid: password fields in primary color, subtle hover glow
- **DMG packaging**: macOS DMG installer now built alongside .app bundle

### Changed

- All hardcoded `px`/`rem` values in App.css replaced with CSS custom properties
- VaultScreen layout: search bar → group tabs → entry list (cleaner hierarchy)
- Removed inline styles from VaultScreen (proper CSS classes)
- Font sizes, padding, gaps all driven by design tokens from themes.css
- **ConfirmationModal**: Redesigned edit-confirmation dialog with diff-style change display, icon header, proper CSS classes (removed all inline styles)
- **DeleteConfirmModal**: Redesigned with danger icon header, consistent modal layout
- **GroupManager**: Redesigned with card-based layout, folder icons with entry counts, visible action buttons (border + background)
  - Rename button: input bg + border, hover → primary color highlight
  - Delete button: input bg + border, hover → danger color highlight
  - New group: inline input bar with primary border accent

### Release Artifacts

- `releases/PwdVault_0.2.0_aarch64.dmg` (3.6MB)
- `releases/PwdVault-macOS-v0.2.0.zip` (3.5MB)
- `releases/PwdVault-Extension-v0.2.0.zip` (20.8KB)

## [0.1.3] - 2026-04-14 (Published)

### Release

- Built release artifacts (macOS): `releases/PwdVault_0.1.3_aarch64.dmg`, `releases/PwdVault-macOS-v0.1.3.zip`.
- Frontend and Rust backend tests pass; production build verified (`pnpm build`, `pnpm tauri build`).
- See `releases/RELEASE_NOTES_v0.1.3.0.md` for full details and installation instructions.

## [0.1.3] - 2026-03-31

### Added

- **Rust test suite**: 48 unit tests covering crypto, database, lib.rs commands, and HTTP API (native_messaging.rs)
- **Frontend test suite**: 17 tests for password strength calculator and vault API client
- **Shared paths module** (`paths.rs`): Eliminates duplicate `get_db_path()`/`ensure_db_dir()` between lib.rs and native_messaging.rs
- **Vitest + Testing Library**: Frontend test infrastructure with jsdom environment

### Changed

- All `.unwrap()` calls on mutex locks replaced with `.expect("descriptive message")` in both lib.rs and native_messaging.rs
- `lock_vault` HTTP command now uses `state.lock_vault()` for atomic key clearing (same as Tauri command)
- Test command requires `-- --test-threads=1` due to global keystore state

### Test Coverage

- `lib.rs`: 10 tests (AppState, generate_password, VaultError, vault lifecycle, CRUD)
- `native_messaging.rs`: 20 tests (all 13 API endpoints + locked state checks + edge cases)
- `crypto/`: 10 tests (cipher, kdf, keystore, verification)
- `database/`: 5 tests (init, CRUD, list, count, delete)
- Frontend: 17 tests (passwordStrength, vault API client)

## [0.1.2] - 2026-03-31

### Fixed

- **Auto-lock race condition**: Key clearing and activity reset now execute atomically within the same mutex scope, preventing inconsistent state
- **Removed debug prints**: Cleaned all `eprintln!("[DEBUG]...")` from production code paths

## [0.1.1] - 2026-03-31

### Fixed

- **Version display**: About dialog now correctly shows 0.1.1 (was showing 0.0.1)
- **Tray menu state**: Lock/Unlock menu text updates dynamically based on vault state
- **Browser extension create entry**: Added "Add Password" UI to extension popup

### Added

- **Auto-lock**: Vault automatically locks after 10 minutes of inactivity
- **Background server**: HTTP server stays alive when window is closed (browser extension keeps working)

### Changed

- All vault operations (Tauri + HTTP API) reset the auto-lock activity timer
- Tray menu "Lock Vault" / "Unlock Vault" toggles based on current vault state

## [0.0.1] - 2026-03-26

### Added

- Initial project scaffold with Tauri v2 + React 19 + TypeScript
- Basic Vite build configuration
- Development environment setup
