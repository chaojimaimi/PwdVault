# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).


## [1.0.2.0] - 2026-06-03

### Fixed
- **Security: remove_group cascade** — Deleting a group now clears `group_id` on all associated entries (prevents orphaned references)
- **Security: Tauri get_entry zeroization** — Plaintext password and notes are zeroized after building response, matching the HTTP API path
- **Security: generate_password explicit error** — Returns error instead of silent fallback when all character types are disabled
- **Architecture: vault.ts HTTP fallback removed** — Eliminated unauthenticated HTTP fallback path; non-Tauri environments now throw a clear error
- **Extension: popup.js DOM hardening** — Password no longer stored in `data-value` attribute; uses `data-id` + memory cache lookup
- **Extension: CSS blur replaced** — Hidden passwords render as Unicode bullet characters instead of blurred plaintext
- **Extension: innerHTML eliminated** — Content script and popup use `textContent` / `createElement` for all user data
- **Extension: host_permissions narrowed** — Restricted to `localhost:17429` only

## [0.3.1.0] - 2026-04-30

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


## [0.3.0.0] - 2026-04-17

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

## [0.2.0.0] - 2026-04-15

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


## [0.1.3.0] - 2026-04-14 (Published)

### Release
- Built release artifacts (macOS): `releases/PwdVault_0.1.3_aarch64.dmg`, `releases/PwdVault-macOS-v0.1.3.zip`.
- Frontend and Rust backend tests pass; production build verified (`pnpm build`, `pnpm tauri build`).
- See `releases/RELEASE_NOTES_v0.1.3.0.md` for full details and installation instructions.


## [0.1.3.0] - 2026-03-31

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

## [0.1.2.0] - 2026-03-31

### Fixed
- **Auto-lock race condition**: Key clearing and activity reset now execute atomically within the same mutex scope, preventing inconsistent state
- **Removed debug prints**: Cleaned all `eprintln!("[DEBUG]...")` from production code paths

## [0.1.1.0] - 2026-03-31

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

## [0.0.1.0] - 2026-03-26

### Added
- Initial project scaffold with Tauri v2 + React 19 + TypeScript
- Basic Vite build configuration
- Development environment setup