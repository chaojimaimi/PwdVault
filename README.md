# PwdVault

A secure, local-first password manager built with Tauri v2, React, and Rust.

All data is encrypted with AES-256-GCM and stored locally using an embedded database. No cloud sync, no accounts, no telemetry.

## Features

- **AES-256-GCM encryption** with Argon2id key derivation (64MB memory, 3 iterations)
- **Local-first** — all data stays on your device in an encrypted redb database
- **Browser auto-fill** via Chrome extension (detects login forms, fills credentials)
- **System tray** — close-to-tray keeps the background server running for the extension
- **Auto-lock** — vault locks after 10 minutes of inactivity
- **Clipboard security** — copied passwords auto-clear after 30 seconds
- **Password generator** — configurable length, character types, strength meter
- **Groups & tags** — organize entries with folders and labels
- **Zero-knowledge** — master password is never stored on disk; key is zeroized on lock

## Security

| Component | Detail |
|-----------|--------|
| Encryption | AES-256-GCM with unique random nonce per operation |
| Key derivation | Argon2id (64MB memory, 3 iterations) |
| Key storage | Memory only — never written to disk |
| Database | redb (pure Rust, ACID-compliant, embedded) |
| Master password | Verified via encrypted header, then zeroized |
| Clipboard | Auto-clears after 30 seconds |
| Lock | Memory key immediately zeroized |

## Installation

### macOS

1. Download `PwdVault-macOS-v*.dmg` from [Releases](https://github.com/chaojimaimi/PwdVault/releases)
2. Open the DMG and drag PwdVault to Applications
3. First launch: right-click → Open → Open (Gatekeeper bypass for unsigned apps)
4. Or run: `xattr -cr /Applications/PwdVault.app`

### Windows

1. Download the `.exe` installer from [Releases](https://github.com/chaojimaimi/PwdVault/releases)
2. Run the installer

### Chrome Extension

1. Download and unzip `PwdVault-Extension-v*.zip`
2. Open `chrome://extensions/` and enable **Developer mode**
3. Click **Load unpacked** and select the extracted folder

The extension communicates with the desktop app via HTTP API on `http://127.0.0.1:17429`. The desktop app must be running (system tray is fine).

## Development

### Prerequisites

- [Node.js](https://nodejs.org/) LTS
- [pnpm](https://pnpm.io/)
- [Rust](https://rustup.rs/) stable

### Setup

```bash
git clone https://github.com/chaojimaimi/PwdVault.git
cd PwdVault
pnpm install
```

### Run

```bash
pnpm tauri dev
```

### Build

```bash
# macOS DMG
pnpm tauri build --bundles dmg

# Windows installer
pnpm tauri build

# All platforms
pnpm tauri build
```

### Test

```bash
# Frontend tests
pnpm test

# Rust tests (single-threaded due to global keystore)
cd src-tauri && cargo test -- --test-threads=1
```

### Version Bump

```bash
./scripts/bump-version.sh 0.2.0 --changelog
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, TypeScript, Vite |
| Backend | Tauri v2, Rust |
| Database | redb (pure Rust, ACID, embedded) |
| Encryption | AES-256-GCM, Argon2id |
| Browser extension | Chrome MV3, HTTP API |
| CI/CD | GitHub Actions (macOS + Windows) |

## Project Status

Early development (v0.2.0). See [CHANGELOG.md](CHANGELOG.md) for details.

### Roadmap

- Encrypted import/export
- Fuzzy search
- Settings screen
- macOS code signing & notarization
- Auto-update
- Firefox extension
- Biometric unlock (Touch ID / Windows Hello)
- TOTP/2FA generator

## Data Files

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/com.pwdvault.app/vault.db` |
| Windows | `%LOCALAPPDATA%/PwdVault/vault.db` |
| Linux | `~/.local/share/pwdvault/vault.db` |

## License

[MIT](LICENSE)
