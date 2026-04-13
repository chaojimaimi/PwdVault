# PwdVault

A secure, local-first password manager built with Tauri + React.

**Last Updated**: 2026-04-13
**Repository**: https://github.com/chaojimaimi/PwdVault (Private)
**Release**: https://github.com/chaojimaimi/PwdVault/releases/tag/v0.1.3
**Current Version**: `v0.1.3` (local)
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
│   │   ├── VaultScreen.tsx       # Password list view with copy buttons
│   │   ├── EntryScreen.tsx       # Add/Edit password entry with strength meter
│   │   └── GeneratorScreen.tsx   # Password generator with strength display
│   ├── styles/
│   │   └── App.css               # Global styles (dark theme)
│   ├── types/
│   │   └── index.ts              # TypeScript type definitions
│   └── utils/
│       ├── passwordStrength.ts    # Password strength calculator
│       ├── clipboard.ts         # Clipboard with 30s auto-clear
│       └── toast.ts             # Toast notification system
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
│   └── native-host/              # Native messaging host (legacy, unused)
│
├── .github/workflows/
│   └── release.yml               # CI: macOS + Windows builds
├── releases/                     # Local release artifacts
│   ├── PwdVault-macOS-v0.1.3.zip    # macOS app (3.5MB)
│   ├── PwdVault-Extension-v0.1.3.zip # Chrome extension (21KB)
│   └── USAGE.md
├── VERSION                       # 4-digit version: 0.0.1.0
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

### v0.1.3 (local, 2026-04-01)

**Completed: Phase A (v0.1.2) — Bug Fixes**
- Auto-lock race condition fix: `clear_key()` + activity reset now atomic under same mutex
- Removed debug `eprintln!` from production code

**Completed: Phase B (v0.1.3) — Rust Test Coverage**
- Extracted `paths.rs` shared module (eliminated duplicate `get_db_path`/`ensure_db_dir`)
- 48 Rust tests passing: crypto (10), database (5), lib.rs (13), native_messaging (20)
- All `.unwrap()` on mutex locks replaced with `.expect("descriptive message")`
- Unified `lock_vault` to use `state.lock_vault()` atomic method

**Completed: Phase C (v0.1.3) — Frontend Tests**
- Vitest + Testing Library + jsdom configured
- 17 frontend tests passing: passwordStrength (10), vault API client (7)

**Completed: Phase D (v0.1.3) — Password Generator Security Fix**
- Fixed character type guarantee issue: implemented shuffle-guarantee algorithm ensuring all selected character types are included
- Upgraded random number generation from thread_rng to OsRng for stronger entropy
- Added 11 comprehensive password generator tests covering all scenarios
- Updated both lib.rs and native_messaging.rs with consistent implementation
- See `password_generator_analysis.md` for detailed technical analysis

### v0.1.1 (2026-03-31)
- Auto-lock (10 min timeout), tray menu state sync, browser extension create entry

### v0.1.0 Release (2026-03-27)
- Initial release: Tauri v2 + React 5 screens, AES-256-GCM + Argon2id, redb, HTTP API, Chrome extension, CI/CD

**Test Suite Summary:**

| Module | Tests | Command |
|--------|-------|---------|
| Rust (total) | 53 | `cd src-tauri && cargo test -- --test-threads=1` |
| crypto | 10 | cipher (4), kdf (3), keystore (2), verification (2) |
| database | 5 | init, CRUD, list, count, delete |
| lib.rs | 18 | AppState, generate_password (11), VaultError, vault lifecycle, CRUD |
| native_messaging | 20 | 13 API endpoints + locked state checks |
| Frontend (total) | 17 | `pnpm test` |
| passwordStrength | 10 | scoring, penalties, edge cases |
| vault API client | 7 | HTTP fallback, error handling, request structure |

> **Note**: Rust tests require `-- --test-threads=1` due to global in-memory keystore shared across tests.

---

## 3. Roadmap (v0.1.3 → v1.0)

### Phase D — Project Identity (v0.2.0, ~1 day)
- [ ] **D1** Rewrite README.md with actual project info
- [ ] **D2** Design PwdVault brand icon (SVG lock+shield, generate all sizes)
- [ ] **D3** CI DMG packaging for macOS
- [ ] **D4** Version sync script (`scripts/bump-version.sh`)

### Phase E — User Features (v0.3.0, ~3 days)
- [ ] **E1** Encrypted import/export (JSON backup/restore)
- [ ] **E2** Fuzzy search (`fuse.js`, threshold=0.3)
- [ ] **E3** Categories/folders (`category` field on PasswordEntry, client-side filtering)
- [ ] **E4** Settings screen (auto-lock timeout, default generator options, redb `settings` table)

### Phase F — Distribution & Security (v0.4.0, ~3 days)
- [ ] **F1** macOS signing + notarization (requires Apple Developer account)
- [ ] **F2** Tauri auto-update plugin (depends on F1)
- [ ] **F3** Linux build (.deb + .AppImage)
- [ ] **F4** HTTP API rate limiting (5 failed unlocks → 60s lockout)

### Phase G — v1.0 Release (~1 day)
- [ ] **G1** Firefox extension adaptation
- [ ] **G2** Clean up test credentials from docs
- [ ] **G3** Update CHANGELOG + CLAUDE.md for v1.0
- [ ] **G4** Security checklist (`cargo audit`, review dependencies)
- [ ] **G5** Tighten CSP in tauri.conf.json (replace `null` with proper policy)

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
| Extension comm | HTTP API (port 17429) | Cross-browser, no native host manifest |
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
