# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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