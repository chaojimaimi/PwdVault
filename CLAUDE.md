# PwdVault

A secure, local-first password manager built with Tauri + React.

**Last Updated**: 2026-03-26
**Repository**: https://github.com/chaojimaimi/PwdVault (Private)
**Current Branch**: `feature/phase1-crypto`

---

## 1. Project Architecture & Key Files

### Tech Stack
- **Frontend**: React 19 + TypeScript + Vite
- **Backend**: Tauri v2 + Rust
- **Database**: redb (pure Rust, ACID-compliant, embedded)
- **Encryption**: AES-256-GCM + Argon2id key derivation
- **Browser Extension**: Chrome/Firefox extension via HTTP server (port 17429)

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
│   │   ├── VaultScreen.tsx       # Password list view
│   │   ├── EntryScreen.tsx       # Add/Edit password entry
│   │   └── GeneratorScreen.tsx   # Password generator
│   ├── styles/
│   │   └── App.css               # Global styles
│   └── types/
│       └── index.ts              # TypeScript type definitions
│
├── src-tauri/                    # Rust backend
│   ├── src/
│   │   ├── main.rs               # Binary entry point
│   │   ├── lib.rs                # Tauri commands + state management
│   │   ├── native_messaging.rs   # HTTP server for browser extension
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
│   ├── chrome/                   # Chrome extension files
│   │   ├── manifest.json
│   │   ├── src/
│   │   │   ├── background.js
│   │   │   ├── content.js
│   │   │   └── popup/
│   │   └── native-host/
│   └── native-host/              # Native messaging host (Rust)
│
├── VERSION                       # 4-digit version (MAJOR.MINOR.PATCH.MICRO)
├── CHANGELOG.md                  # Version history
└── CLAUDE.md                     # This file
```

### Key Architectural Decisions

1. **Unified API Client** (`src/api/vault.ts`):
   - Detects Tauri environment via `window.__TAURI_INTERNALS__`
   - Falls back to HTTP API (port 17429) for browser extension or dev testing
   - Single codebase works in both desktop app and browser

2. **Shared AppState**:
   - Tauri desktop app and HTTP server share the same `Arc<AppState>`
   - Contains: `database: Mutex<Option<Arc<Database>>>` and `verification_data: Mutex<Option<VerificationData>>`
   - Prevents double database locking issues

3. **Database Path** (Platform-specific):
   - macOS: `~/Library/Application Support/com.pwdvault.app/vault.db`
   - Windows: `%LOCALAPPDATA%/PwdVault/vault.db`
   - Linux: `~/.local/share/pwdvault/vault.db`

4. **Security Model**:
   - Master password never stored on disk
   - Key derived with Argon2id (memory: 64MB, iterations: 3)
   - Encryption key held in memory only while vault is unlocked
   - Passwords encrypted with AES-256-GCM (unique nonce per encryption)

---

## 2. Current Status & Progress

### Completed Features (2026-03-26)
- [x] Tauri v2 desktop application with React frontend
- [x] Vault initialization with master password
- [x] Vault unlock/lock functionality
- [x] Password entry CRUD operations
- [x] Password generator (configurable length, character types)
- [x] AES-256-GCM encryption for sensitive data
- [x] Argon2id key derivation
- [x] HTTP server for browser extension communication (port 17429)
- [x] Unified API client (Tauri + HTTP)
- [x] Platform-specific database paths
- [x] Database lock conflict resolution
- [x] Chrome extension skeleton
- [x] Project pushed to GitHub (private repo)

### Bugs Fixed Today
1. **Rust cfg attribute bug**: `get_db_path()` was incorrectly structured - `.join("vault.db")` wasn't being executed. Fixed by wrapping cfg blocks in `let base_dir = {...}`.

2. **Tauri state type mismatch**: Commands expected `State<AppState>` but `.manage()` stored `Arc<AppState>`. Fixed by updating all command signatures to `State<'_, Arc<AppState>>`.

3. **Database already open error**: Both Tauri and HTTP server tried to open database. Fixed by checking if database is already loaded in `setup_vault` before attempting to open.

4. **Error display `[object Object]`**: Error handling in frontend was converting objects to strings incorrectly. Fixed with `formatError()` function.

### Test Credentials
- Master password: `TestMaster123`
- Test entry: "Test Website" (https://example.com, username: testuser)

---

## 3. TODO / Backlog

### High Priority (Next Session)
- [ ] Browser extension completion (Chrome/Firefox)
  - [ ] Popup UI for quick password access
  - [ ] Content script for auto-fill
  - [ ] Native messaging integration with desktop app
- [ ] Password copy to clipboard with timeout clear
- [ ] Password strength indicator

### Medium Priority
- [ ] Entry search improvements (fuzzy search)
- [ ] Categories/folders for organizing entries
- [ ] Import/export functionality (encrypted backup)
- [ ] Password history tracking
- [ ] Biometric unlock (Touch ID / Face ID / Windows Hello)

### Low Priority / Future
- [ ] Secure notes storage
- [ ] Password breach monitoring (Have I Been Pwned API)
- [ ] Multi-device sync (optional, self-hosted)
- [ ] Dark mode theme
- [ ] Mobile apps (iOS/Android via Tauri Mobile)

---

## 4. Important Decisions

### Decision 1: redb vs SQLite
**Chosen**: redb
**Reason**: Pure Rust, no external dependencies, ACID-compliant, simpler deployment. Trade-off: less feature-rich than SQLite, but sufficient for password manager use case.

### Decision 2: In-memory Key Storage
**Chosen**: Store derived key in memory only, never persist
**Reason**: Maximizes security - if computer is powered off or app crashes, key is gone. User must re-enter master password. Trade-off: slightly less convenient, but significantly more secure.

### Decision 3: Browser Extension Communication
**Chosen**: HTTP server on localhost (port 17429)
**Reason**: Works with both Chrome and Firefox, no native messaging host manifest complexity. Trade-off: requires desktop app running for extension to work.

### Decision 4: No Cloud Sync (for now)
**Chosen**: Local-first, no cloud sync
**Reason**: Simpler architecture, no server costs, maximum privacy. User can backup via encrypted export. Cloud sync can be added later as optional feature.

---

## 5. Development Commands

```bash
# Start development server (desktop app)
source ~/.cargo/env && pnpm tauri dev

# Build production release
pnpm tauri build

# Run Rust tests
cd src-tauri && cargo test

# Type check frontend
pnpm tsc --noEmit

# Git workflow
git status
git add -A
git commit -m "feat: description"
git push origin feature/phase1-crypto
```

---

## 6. Security Notes

- Master password is zeroized after key derivation
- All sensitive data (passwords, notes) encrypted before database storage
- Verification header stored to validate master password without revealing key
- Nonces are randomly generated for each encryption operation
- Database file is locked exclusively while open
- `vault.db` is excluded from git tracking (user data)

---

## 7. Session Log

### 2026-03-26 (Phase 1 - Crypto & Core)
**Duration**: Full day
**Commits**: 3 commits
- `c0b00c2` - Initialize PwdVault
- `3010745` - Add project configuration files
- `cabb999` - Implement core password manager functionality

**Lines Changed**: 12,075 additions, 205 deletions
**Files**: 45 files

**Key Achievements**:
- Complete encryption system (AES-256-GCM + Argon2id)
- Working desktop application
- HTTP API for browser extension
- All CRUD operations functional
- Pushed to GitHub private repo

**Next Session Focus**:
- Browser extension popup UI
- Auto-fill functionality
- Clipboard integration