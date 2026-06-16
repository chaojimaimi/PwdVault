# PwdVault

A secure, local-first password manager built with Tauri + React.

**Last Updated**: 2026-05-01
**Repository**: https://github.com/chaojimaimi/PwdVault (Private)
**Release**: https://github.com/chaojimaimi/PwdVault/releases/tag/v1.0.0
**Current Version**: `v1.0.0`
**Current Branch**: `main`

---

## 1. Project Architecture & Key Files

### Tech Stack
- **Frontend**: React 19 + TypeScript + Vite
- **Backend**: Tauri v2 + Rust
- **Database**: redb (pure Rust, ACID-compliant, embedded)
- **Encryption**: AES-256-GCM + Argon2id key derivation
- **Browser Extension**: Chrome extension via HTTP API (port 17429)
- **CI/CD**: GitHub Actions (macOS + Windows builds)

### Directory Structure
```
PwdVault/
├── src/                          # React frontend
│   ├── App.tsx                   # Main app component with screen routing
│   ├── main.tsx                  # React entry point
│   ├── api/
│   │   └── vault.ts              # Unified Tauri/HTTP API client
│   ├── context/
│   │   └── AppContext.tsx        # Global state management
│   ├── screens/
│   │   ├── SetupScreen.tsx       # Initial vault creation
│   │   ├── UnlockScreen.tsx      # Master password input
│   │   ├── VaultScreen.tsx       # Password list view with group tabs + fuzzy search
│   │   ├── EntryScreen.tsx       # Add/Edit password entry with strength meter
│   │   ├── GeneratorScreen.tsx   # Password generator with strength display
│   │   ├── GroupManager.tsx      # Create/rename/delete groups
│   │   ├── SettingsScreen.tsx    # Auto-lock timeout, default generator options
│   │   └── ImportExportScreen.tsx # Encrypted backup/restore (.pvault)
│   ├── styles/
│   │   ├── themes.css            # Design tokens (shared + Light/Dark color overrides)
│   │   ├── base.css              # Global reset, scrollbar, accessibility
│   │   ├── components.css        # Buttons, inputs, modals, toasts, icons
│   │   ├── screens.css           # Entry/generator screen layouts
│   │   ├── vault.css             # Vault list, search, group tabs
│   │   ├── groups.css            # Group manager styles
│   │   └── settings.css          # Settings, theme selector, import/export
│   ├── types/
│   │   └── index.ts              # TypeScript type definitions
│   └── utils/
│       ├── passwordStrength.ts    # Password strength calculator
│       ├── clipboard.ts          # Clipboard with 30s auto-clear
│       └── toast.ts              # Toast notification system
│
├── src-tauri/                    # Rust backend
│   ├── src/
│   │   ├── main.rs               # Binary entry point
│   │   ├── lib.rs                # Tauri commands + state + system tray
│   │   ├── native_messaging.rs   # HTTP server (port 17429) for browser extension
│   │   ├── paths.rs              # Shared path utilities (db path resolution)
│   │   ├── crypto/               # Encryption module
│   │   │   ├── mod.rs
│   │   │   ├── cipher.rs         # AES-256-GCM encryption
│   │   │   ├── kdf.rs            # Argon2id key derivation
│   │   │   ├── keystore.rs       # In-memory key management
│   │   │   └── verification.rs   # Password verification
│   │   └── database/             # Database module
│   │       └── mod.rs            # redb tables and operations
│   ├── Cargo.toml                # Rust dependencies
│   └── tauri.conf.json           # Tauri configuration
│
├── extensions/                   # Browser extension
│   ├── chrome/                   # Chrome extension
│   │   ├── manifest.json          # MV3 manifest
│   │   ├── src/
│   │   │   ├── background.js      # HTTP API communication
│   │   │   ├── content.js         # Auto-fill + form detection + floating button
│   │   │   ├── content.css
│   │   │   └── popup/            # Popup UI (search, copy, show/hide password)
│   │   └── icons/
│   ├── firefox/                   # Firefox extension (MV3, symlinks to chrome/)
│   │   ├── manifest.json          # Firefox MV3 manifest with gecko settings
│   │   ├── src → ../chrome/src/   # Symlink to shared source
│   │   └── icons → ../chrome/icons/ # Symlink to shared icons
│
├── .github/workflows/
│   └── release.yml               # CI: macOS + Windows + extension builds
├── releases/                     # Local release artifacts
├── scripts/
│   └── bump-version.sh           # Version sync across 6 files
├── DESIGN.md                     # Design system specification (Light/Dark themes)
├── VERSION                       # 4-digit version: 1.0.0.0
├── CHANGELOG.md
├── password_generator_analysis.md # Password generator security analysis & fixes
└── CLAUDE.md                     # This file
```

### Key Architectural Decisions

1. **Unified API Client** (`src/api/vault.ts`):
   - Detects Tauri environment via `window.__TAURI_INTERNALS__`
   - Falls back to HTTP API (port 17429) for browser extension or dev testing

2. **Shared AppState**:
   - Tauri desktop app and HTTP server share the same `Arc<AppState>`

3. **System Tray** (`src-tauri/src/lib.rs`):
   - Close window hides to tray, keeps HTTP server running
   - Tray menu: Show, Lock Vault, Quit
   - Left-click tray icon restores window

4. **Browser Extension Communication** (HTTP API):
   - Extension uses `fetch()` to `http://127.0.0.1:17429/api/{command}`
   - No native messaging host needed, simpler cross-browser support

5. **Security Model**:
   - Master password never stored on disk
   - Argon2id key derivation (64MB memory, 3 iterations)
   - AES-256-GCM with unique nonce per encryption
   - Clipboard auto-clear after 30 seconds
   - Key zeroized on lock/quit

---

## 2. Current Status

### v1.0.0 (2026-05-01) — Released

**Completed: Phase G — v1.0 Release Preparation**
- **G1** Firefox extension — MV3 adaptation with gecko-specific manifest, symlink to shared source
- **G2** Test credential cleanup — verified no leaked credentials
- **G3** Documentation update — CHANGELOG, CLAUDE.md, README.md all current
- **G4** Security checklist — CSP hardened, keystore .expect(), cargo audit in CI, .env in .gitignore
- **G5** CSP policy — replaced `null` with restrictive policy (script-src 'self', connect-src localhost only)
- **F2** Update notification — checks GitHub Releases for newer versions
- **F4** Rate limiting — 5 failed unlocks → 60s lockout

### v0.3.1 (2026-04-30)

**Completed: Frontend Redesign + Security Features**
- Light/Dark dual-theme system replacing Classic/Cyber/Hybrid
- Modular CSS: `App.css` (1300+ lines) split into 6 files
- New components: `BackHeader.tsx`, `Icons.tsx`, `StrengthMeter.tsx`, `UpdateNotification.tsx`
- Browser extension synced with Light/Dark theme system

### v0.3.0 (2026-04-17) — Released

**Completed: Phase E — User Features**
- **E1** Encrypted import/export — `.pvault` backup files with independent export password, AES-256-GCM + Argon2id
- **E2** Fuzzy search — fuse.js weighted search across title/username/URL/tags
- **E4** Settings screen — auto-lock timeout (1–60 min), default generator options, persisted to redb
- Added `ImportExportScreen`, `SettingsScreen`, `GroupManager` screens
- Added `themes.css` two-theme design system (Light/Dark)
- Browser extension updated with export/import API + group support + theme switching
- Security hardening: zeroization of plaintext passwords/notes, correct adaptive KDF params

### v0.2.0 (2026-04-15)

**Completed: Phase D — Project Identity**
- **D1** Rewrote README.md
- **D2** Brand icon verified across extension + Tauri
- **D3** CI DMG packaging for macOS
- **D4** Version sync script (`scripts/bump-version.sh`)
- Design system: three themes (Classic/Cyber/Hybrid) with CSS custom properties
- VaultScreen UX: group tabs, search input, redesigned modals
- Release: DMG (3.6MB) + app bundle (3.5MB) + extension (20.8KB)

### v0.1.3 (2026-04-01)

- Auto-lock race condition fix
- 48 Rust tests + 17 frontend tests
- Password generator security fix (shuffle-guarantee algorithm + OsRng)

### v0.1.1 (2026-03-31)
- Auto-lock (10 min timeout), tray menu state sync, browser extension create entry

### v0.1.0 Release (2026-03-27)
- Initial release: Tauri v2 + React 5 screens, AES-256-GCM + Argon2id, redb, HTTP API, Chrome extension, CI/CD

**Test Suite Summary:**

| Module | Tests | Command |
|--------|-------|---------|
| Rust (total) | 53+ | `cd src-tauri && cargo test -- --test-threads=1` |
| crypto | 10 | cipher (4), kdf (3), keystore (2), verification (2) |
| database | 5 | init, CRUD, list, count, delete |
| lib.rs | 18+ | AppState, generate_password, VaultError, vault lifecycle, CRUD, export/import |
| native_messaging | 20+ | 15 API endpoints + locked state checks + export/import |
| Frontend (total) | 17 | `pnpm test` |
| passwordStrength | 10 | scoring, penalties, edge cases |
| vault API client | 7 | HTTP fallback, error handling, request structure |

> **Note**: Rust tests require `-- --test-threads=1` due to global in-memory keystore shared across tests.

---

## 3. Roadmap

### Phase G — v1.0 Release ✅ Completed
- [x] **G1** Firefox extension (MV3, gecko manifest, shared source via symlink)
- [x] **G2** Clean up test credentials from docs (verified clean)
- [x] **G3** Update CHANGELOG + CLAUDE.md
- [x] **G4** Security checklist (CSP hardened, cargo audit in CI, .env in .gitignore, keystore .expect())
- [x] **G5** Tighten CSP in tauri.conf.json (null → restrictive policy)

### Phase D — Project Identity (v0.2.0) ✅ Completed
- [x] **D1** Rewrite README.md with actual project info
- [x] **D2** Design PwdVault brand icon (SVG lock+shield, generate all sizes)
- [x] **D3** CI DMG packaging for macOS
- [x] **D4** Version sync script (`scripts/bump-version.sh`)

### Phase E — User Features (v0.3.0) ✅ Completed
- [x] **E1** Encrypted import/export (JSON backup/restore)
- [x] **E2** Fuzzy search (`fuse.js`, threshold=0.3)
- [x] **E3** Categories/folders (replaced by groups — implemented as `group_id` field)
- [x] **E4** Settings screen (auto-lock timeout, default generator options, redb `settings` table)

### Phase F — Distribution & Security (partial)
- [ ] **F1** macOS signing + notarization (requires Apple Developer account) — *skipped*
- [x] **F2** Update notification (checks GitHub Releases on startup)
- [ ] **F3** Linux build (.deb + .AppImage) — *skipped*
- [x] **F4** HTTP API rate limiting (5 failed unlocks → 60s lockout)

### Future (post-v1.0)
- [ ] Biometric unlock (Touch ID / Windows Hello)
- [ ] Secure notes
- [ ] Breach monitoring (HIBP API)
- [ ] TOTP/2FA generator
- [ ] Multi-device sync (self-hosted)
- [ ] Mobile apps (Tauri Mobile)

---

## 4. Important Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Database | redb | Pure Rust, no external deps, ACID-compliant |
| Key storage | Memory only | Max security, key gone on power off |
| Extension comm | Native Messaging → stdio host → HTTP API (port 17429) | Official browser API; host binary bridges stdio to the existing HTTP server |
| Cloud sync | None (local-first) | Simpler, no server costs, max privacy |
| System tray | Close-to-tray | Keeps HTTP server alive for extension |

---

## 5. Development Commands

```bash
# Development
source ~/.cargo/env && pnpm tauri dev

# Build macOS
pnpm tauri build --bundles app

# Build all platforms
pnpm tauri build

# Type check
pnpm tsc --noEmit

# Rust tests (must run single-threaded due to global keystore)
cd src-tauri && cargo test -- --test-threads=1

# Frontend tests
pnpm test

# Frontend tests (watch mode)
pnpm test:watch

# Trigger CI build
git tag vX.Y.Z && git push origin main --tags
```

---

## 6. Security Notes

- Master password is zeroized after key derivation
- All sensitive data encrypted with AES-256-GCM before database storage
- Verification header validates master password without revealing key
- Nonces randomly generated per encryption operation
- Database file locked exclusively while open
- Clipboard auto-clears after 30 seconds
- Key zeroized on vault lock or app quit

---

## 7. Session Log

### 2026-05-01 (Phase G — v1.0.0 Release)
**Tag**: `v1.0.0`

**G5: CSP Hardening:**
- Replaced `null` CSP in `tauri.conf.json` with restrictive policy
- `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' http://127.0.0.1:17429`

**G4: Security Checklist:**
- `keystore.rs`: 4× `.unwrap()` → `.expect("keystore lock poisoned")`
- `native_messaging.rs`: Added CORS wildcard security justification comment
- `.gitignore`: Added `.env` and `.env.*`
- `.github/workflows/release.yml`: Added `security-audit` job with `cargo audit`

**G1: Firefox Extension:**
- Created `extensions/firefox/manifest.json` with `browser_specific_settings.gecko`
- Symlinks: `src → ../chrome/src/`, `icons → ../chrome/icons/`
- Updated `build.sh` to package both Chrome and Firefox extensions
- Updated `bump-version.sh` for 7th file (Firefox manifest)
- CI now builds both Chrome and Firefox extension artifacts

**G3: Documentation:**
- CHANGELOG.md: Added v0.3.1 entry (Light/Dark redesign, F2, F4, modular CSS)
- CLAUDE.md: Updated version, roadmap, directory structure, session log
- README.md: Updated status to v1.0.0, added Firefox install section, updated roadmap

### 2026-04-30 (v0.3.1)
- Frontend redesign: Light/Dark dual-theme system replacing Classic/Cyber/Hybrid
- Modular CSS: App.css split into 6 files (themes, base, components, screens, vault, groups, settings)
- F2: Update notification (ureq + semver version comparison)
- F4: Rate limiting (5 failed unlocks → 60s lockout)
- New components: BackHeader, Icons, StrengthMeter, UpdateNotification
- Browser extension synced with Light/Dark theme system

### 2026-04-17 (Phase E — v0.3.0 Release)
**Commit**: `a86edc6` · **Tag**: `v0.3.0` · **GitHub Release**: published

**E1: Encrypted Import/Export:**
- `export_vault` / `import_vault` Tauri commands + HTTP API endpoints
- `.pvault` file format: AES-256-GCM encrypted JSON with Argon2id key derivation
- Export password independent of master password (portable backups)
- Import restores entries + groups + settings with confirmation prompt
- Security: zeroization of plaintext passwords/notes, adaptive KDF params stored in backup
- `ImportExportScreen.tsx` — Tauri dialog for file save/open, browser fallback
- Browser extension: `exportVault` / `importVault` API wrappers

**E2: Fuzzy Search:**
- fuse.js weighted search: title (0.4), username (0.3), url (0.2), tags (0.1)
- Consistent config between desktop app and browser extension

**E4: Settings Screen:**
- `SettingsScreen.tsx` — auto-lock timeout (1–60 min), default generator options
- Settings persisted to redb `settings` table
- Dynamic auto-lock reads timeout from settings
- Backward compatible: pre-v0.3 vaults fallback to defaults

**CI/CD:**
- GitHub Actions v0.3.0 build: macOS DMG + app bundle, Windows exe, extension zip
- All 4 jobs passed; GitHub Release published with artifacts

### 2026-04-16 (Browser Extension Fixes)
**Commits**: `0c381e3`, `25e787c`

- Fixed browser extension group display inconsistency with desktop app
- Fixed password generator button not showing generated password UI
- Added theme switching support to browser extension
- Fixed tray menu Lock/Unlock state sync after vault lock

### 2026-04-01 (Phase A/B/C — Quality & Tests)
**Commits**: `d748292`

**Phase A (v0.1.2) — Bug Fixes:**
- Fixed auto-lock race condition: `clear_key()` + activity reset now atomic under same mutex
- Removed all `eprintln!("[DEBUG]...")` from production code

**Phase B (v0.1.3) — Rust Test Coverage:**
- Extracted `paths.rs` shared module (eliminated ~40 lines duplicate code)
- Added 48 Rust tests covering crypto, database, lib.rs commands, and all 13 HTTP API endpoints
- Replaced all `.unwrap()` with `.expect("descriptive message")` in lib.rs and native_messaging.rs
- Unified `lock_vault` HTTP command to use `state.lock_vault()` atomic method

**Phase C (v0.1.3) — Frontend Tests:**
- Configured Vitest + Testing Library + jsdom
- 17 frontend tests: passwordStrength calculator and vault API client

**Phase D (v0.1.3) — Password Generator Security Fix:**
- Fixed character type guarantee issue: implemented shuffle-guarantee algorithm ensuring all selected character types are included
- Upgraded random number generation from thread_rng to OsRng for stronger entropy
- Added 11 comprehensive password generator tests covering all scenarios
- Updated both lib.rs and native_messaging.rs with consistent implementation
- Created detailed technical analysis document (`password_generator_analysis.md`)

**Phase E (v0.1.3) — Release Packaging:**
- Fixed TypeScript test compilation error (added missing `tags` property)
- Rebuilt macOS application bundle (3.5MB)
- Rebuilt Chrome extension package (21KB)
- Updated release artifacts in `/releases/` directory
- Updated CLAUDE.md with v0.1.3 release information

**Technical Notes:**
- Rust tests require `-- --test-threads=1` due to global in-memory keystore
- Tauri v2 `MenuItem<R: Runtime>` generic prevents direct storage; solved with closure type erasure (`Box<dyn Fn(&str) + Send + Sync>`)
- Password generator now guarantees 100% coverage of selected character types using shuffle-guarantee algorithm

### 2026-03-26 (Phase 1 — Crypto & Core)
**Duration**: Full day
**Commits**: `c0b00c2`, `3010745`, `cabb999`

- Complete encryption system (AES-256-GCM + Argon2id)
- Working desktop application with 5 screens
- HTTP API for browser extension
- All CRUD operations functional
- Pushed to GitHub private repo

### 2026-03-27 (Phase 2 — UI/UX & Release)
**Duration**: Full day
**Commits**: `555a6ae`, `7d06b04`, `1831119`, `ec2c9bc`
**Branch**: `feature/phase1-crypto` → merged to `main`

**Parallel Development (3 worktrees):**
- Password strength indicator (`src/utils/passwordStrength.ts`)
- Chrome Popup UI enhancement (search, show/hide, copy, URL)
- Content script + clipboard integration (auto-fill prompt, MutationObserver, keyboard shortcuts)

**Infrastructure:**
- System tray with close-to-tray behavior
- Fixed browser extension communication (native messaging → HTTP API)
- Added missing HTTP API commands (`update_entry`, `remove_entry`, `get_entry_count`)
- GitHub Actions CI/CD (macOS + Windows builds)
- GitHub Release v0.1.0 with macOS/Windows installers + Chrome extension

**Bugs Fixed:**
1. Extension `background.js` used native messaging but desktop provides HTTP API — rewrote to use `fetch()`
2. HTTP API missing 3 commands — added `update_entry`, `remove_entry`, `get_entry_count`
3. macOS bundle identifier ended with `.app` — changed to `com.pwdvault.desktop`
4. GitHub Actions CI failed — missing `pnpm/action-setup@v4` before `actions/setup-node@v4`

**Build Outputs:**
- macOS `.app`: 9.8 MB
- Windows `.exe`: 2.3 MB
- Chrome extension `.zip`: 20 KB

### 2026-04-13 (Tests & GroupManager)

- Added unit tests for `GroupManager` (create, rename, delete)
- Frontend test suite stabilized; Rust backend tests remain green

### 2026-04-14 (Phase D — Project Identity + Design System)

**Phase D — Project Identity (v0.2.0):**
- Created `scripts/bump-version.sh` — version sync across 6 files
- Updated `.github/workflows/release.yml` — DMG packaging for macOS
- Rewrote `README.md` (~120 lines) and created `LICENSE` (MIT)
- Verified brand icon consistency across extension + Tauri
- Bumped all versions to v0.2.0

**Bug Fixes (Groups + Delete):**
- Fixed GroupSelector/GroupManager: replaced `prompt()`/`confirm()` with inline UI (Tauri WebView doesn't support browser native dialogs)
- Fixed "Vault is already unlocked" error: added `groupManager` route in App.tsx + made `set_key()` idempotent
- Fixed entries not showing after adding to groups: added `LegacyPasswordEntry` fallback deserialization for bincode v1 backward compatibility
- Fixed delete button not working: created `DeleteConfirmModal` component replacing `confirm()`

**Design System (/design-consultation):**
- Competitive research: 1Password, Bitwarden, KeePassXC design analysis
- Created three-theme design system documented in `DESIGN.md`:
  - **Classic** (default): Industrial Refined — cyan #0EA5E9, Plus Jakarta Sans
  - **Cyber**: CyberForge — neon cyan #00F0FF + magenta #FF0080, Space Grotesk
  - **Hybrid**: Warm-tech fusion — cyan #06B6D4 + rose #F472B6, subtle glow
- All themes switchable via `data-theme` CSS attribute
- Preview pages generated at `/tmp/design-consultation-preview-pwdvault*.html`

### 2026-04-15 (Design System Implementation + UX Polish)

**Design System Applied (themes.css + App.css):**
- Added type scale CSS variables: `--text-h1` (1.5rem) through `--text-micro` (0.6875rem) per DESIGN.md
- Added spacing tokens: `--space-xs` (4px) through `--space-2xl` (32px) per DESIGN.md
- Added `--icon-style` token per theme: solid (Classic), hollow (Cyber), glow (Hybrid)
- Replaced all hardcoded `px`/`rem` in App.css with CSS custom properties
- Cyber theme: hollow entry icons (transparent bg + border + glow color)
- Hybrid theme: password fields in primary color, subtle hover glow on buttons
- Hybrid theme: radial gradient background (cyan top-left + rose bottom-right)

**VaultScreen UX Redesign:**
- Replaced `<select>` dropdown group filter with horizontal scrollable group tabs
- Active tab: primary-dim background + primary color text + primary border
- Search input with magnifying glass SVG icon
- Group management via gear icon (⚙) in tabs bar
- "Create group" prompt shown when no groups exist
- Removed all inline styles from VaultScreen component

**ConfirmationModal & DeleteConfirmModal Redesign:**
- Replaced all inline styles with CSS classes
- Edit confirmation: icon header (pen icon in primary-dim circle), diff-style change list (~~old~~ → **new**), checkbox + Save/Cancel buttons
- Delete confirmation: danger icon header (trash in danger-dim circle), message body, Cancel/Delete buttons
- Consistent modal layout: header → content → footer

**GroupManager Redesign:**
- Card-based layout: each group as a card with folder icon, name, and entry count
- Action buttons always visible with `background: var(--color-input)` + `border: 1px solid var(--color-border)`
- Rename: 32px icon button, hover → primary color highlight
- Delete: 32px icon button, hover → danger color highlight
- New group: inline input bar with primary border accent, Enter/Escape key support
- Header + button in top-right for creating groups (consistent with vault page pattern)

**Release Artifacts:**
- `PwdVault_0.2.0_aarch64.dmg` (3.6MB) — macOS DMG installer
- `PwdVault-macOS-v0.2.0.zip` (3.5MB) — macOS .app bundle
- `PwdVault-Extension-v0.2.0.zip` (20.8KB) — Chrome extension

---

## Plugin Tools (Mandatory)

代码开发任务必须主动根据情况择优调用以下插件工具，不需要用户提醒：

| 阶段 | 推荐工具 |
|------|----------|
| 规划 | gstack `/plan-eng-review`、planner agent |
| 编码 | superpowers 代码生成、ECC TDD 技能 |
| 审查 | `code-reviewer` agent、gstack `/review` |
| 安全 | `security-reviewer` agent、ECC 安全技能 |
| 测试 | gstack `/qa`、`tdd-guide` agent |
| 构建 | `build-error-resolver` agent |

简单/单文件修改可酌情跳过，复杂多文件功能必须调用。

---

## Design System
Always read DESIGN.md before making any visual or UI decisions.
All font choices, colors, spacing, and aesthetic direction are defined there.
Two themes available: Light (default), Dark. Automatically follows OS preference.
Do not deviate without explicit user approval.
In QA mode, flag any code that doesn't match DESIGN.md.

---

## Native Messaging Architecture (v1.0.3+)

### Current Architecture

The browser extension communicates with the desktop app via the official
**Native Messaging API**, not direct HTTP fetch:

```
extension (background.js)
  │ chrome.runtime.sendNativeMessage('com.pwdvault.app', {...})
  │   (Bearer token carried in body field 'auth_token' — NM has no headers)
  ▼
pwdvault-native (host binary, stdio, serde-only deps)
  │ 4-byte length-prefixed JSON  →  HTTP POST 127.0.0.1:17429
  │   (injects Origin header + lifts auth_token → Authorization: Bearer)
  ▼
desktop app (tiny_http server on 17429, unchanged business logic)
  ▼
encrypted vault (redb)
```

### Key Files

| File | Role |
|------|------|
| `extensions/native-host/src/main.rs` | Host binary: stdio↔HTTP bridge |
| `extensions/chrome/src/background.js` | Extension: sendNativeMessage transport |
| `src-tauri/src/native_host_setup.rs` | Manifest generation + browser registration |
| `src-tauri/src/lib.rs` `register_native_host()` | Auto-register on startup (chmod +x, read IDs from config) |
| `extensions/chrome/scripts/install-native-host.sh` | Write extension IDs to config file |

### Setup for Development

The extension ID is unstable when loading unpacked. To connect:

```bash
# 1. Load extension in Chrome, copy the ID from chrome://extensions/
# 2. Write the ID to the config file:
bash extensions/chrome/scripts/install-native-host.sh <chrome-extension-id> [firefox-id]
# 3. Restart the desktop app — it reads the config and writes browser manifests
```

Config file: `~/Library/Application Support/com.pwdvault.app/native-host.json`
Format: `{"chrome": "<id>", "firefox": "<id>"}`

### Known Issues / Deferred

- **Stage 3 (socket transport) skipped**: The HTTP TCP port 17429 is still
  open (loopback only). Converting to Unix domain socket / Windows named pipe
  is deferred as a non-blocking optimization. NM's `allowed_origins` already
  provides the source-locking security benefit.
- **Extension ID stability**: `allowed_origins` uses the dev extension ID from
  config. After store publication with fixed IDs, update `native_host_setup.rs`.
- **Pre-existing test failures**: 9-10 unit tests fail due to global-state
  pollution (keystore/auth token singletons). These are unrelated to the NM
  change and existed before. Run tests with `--test-threads=1` to avoid.
- **macOS code signing**: The host binary is unsigned in local builds. CI
  release builds may need codesign/notarize steps for distribution.
- **Tauri resources executable bit**: `bundle.resources` does not preserve +x;
  `register_native_host()` auto-fixes this on every launch.
