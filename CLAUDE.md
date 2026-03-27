# PwdVault

A secure, local-first password manager built with Tauri + React.

**Last Updated**: 2026-03-27
**Repository**: https://github.com/chaojimaimi/PwdVault (Private)
**Release**: https://github.com/chaojimaimi/PwdVault/releases/tag/v0.1.0
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
│   ├── PwdVault-macOS-v0.1.0.zip
│   ├── PwdVault-Extension-v0.1.0.zip
│   └── USAGE.md
├── VERSION                       # 4-digit version: 0.0.1.0
├── CHANGELOG.md
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

### v0.1.0 Release (2026-03-27)

**Completed Features:**

| Module | Feature | Status |
|--------|---------|--------|
| Desktop App | Tauri v2 + React with 5 screens | Done |
| Desktop App | System tray (close-to-tray, show/lock/quit) | Done |
| Desktop App | Password strength indicator | Done |
| Desktop App | Clipboard auto-clear (30s) + toast notifications | Done |
| Desktop App | Vault list copy buttons (username/password) | Done |
| Crypto | AES-256-GCM + Argon2id | Done |
| Crypto | In-memory key management + zeroization | Done |
| Database | redb with CRUD operations | Done |
| HTTP API | 11 endpoints (all verified) | Done |
| Extension | Popup UI (search, show/hide, copy, URL open) | Done |
| Extension | Content script auto-fill (form detection, prompt bar, floating button) | Done |
| Extension | Keyboard shortcuts (Ctrl+Shift+L) | Done |
| Extension | Clipboard auto-clear in overlay | Done |
| CI/CD | GitHub Actions (macOS + Windows) | Done |
| Distribution | GitHub Release v0.1.0 | Done |

**API Endpoints:**
`setup_vault`, `init_vault`, `unlock_vault`, `lock_vault`, `is_vault_initialized`, `is_vault_unlocked`, `create_entry`, `get_entry`, `list_all_entries`, `update_entry`, `remove_entry`, `get_entry_count`, `generate_password`

**Release Artifacts:**
- `PwdVault_0.0.1_x64-setup.exe` (2.3 MB) — Windows installer
- `PwdVault.app` (9.8 MB) — macOS application
- `PwdVault-Extension-v0.1.0.zip` (20 KB) — Chrome extension
- `USAGE.md` — Usage instructions

---

## 3. TODO / Roadmap

### Phase 3 — Quality & Polish

- [ ] **Unit tests** — Crypto module, database operations, API layer
- [ ] **E2E tests** — Desktop app critical flows (setup, unlock, CRUD, lock)
- [ ] **App icon design** — Replace default Tauri icon with PwdVault branding
- [ ] **DMG packaging** — Fix DMG build script for macOS distribution
- [ ] **Version sync** — Align VERSION file with tauri.conf.json/Cargo.toml
- [ ] **Update README.md** — Replace generic Tauri template with actual project info

### Phase 4 — Features

- [ ] **Import/export** — Encrypted JSON backup/restore
- [ ] **Fuzzy search** — Replace exact match with fuzzy scoring
- [ ] **Categories/folders** — Organize entries into groups
- [ ] **Password history** — Track previous passwords per entry
- [ ] **Firefox extension** — Test and adapt Chrome extension for Firefox
- [ ] **Settings screen** — Configurable timeout, port, encryption params

### Phase 5 — Security & Distribution

- [ ] **macOS signing & notarization** — Apple Developer account ($99/yr)
- [ ] **Windows code signing** — OV/EV certificate for SmartScreen
- [ ] **Auto-update** — Tauri updater plugin with signature verification
- [ ] **Biometric unlock** — Touch ID / Face ID / Windows Hello
- [ ] **Security audit** — External review before public release

### Phase 6 — Growth

- [ ] **Secure notes** — Encrypted free-text storage
- [ ] **Breach monitoring** — Have I Been Pwned API integration
- [ ] **TOTP/2FA** — One-time password generator
- [ ] **Multi-device sync** — Optional self-hosted sync server
- [ ] **Mobile apps** — iOS/Android via Tauri Mobile

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

# Rust tests
cd src-tauri && cargo test

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
