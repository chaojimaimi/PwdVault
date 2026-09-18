# PwdVault

A secure, local-first password manager built with Tauri v2, React, and Rust.

All data is encrypted with AES-256-GCM and stored locally using an embedded
database. **No accounts, no vendor servers, no telemetry.** Optional
multi-device sync goes through *your own* cloud storage (WebDAV or Baidu
Netdisk) as an end-to-end encrypted container — the cloud only ever sees
ciphertext.

## Features

- **AES-256-GCM encryption** with Argon2id key derivation (adaptive
  parameters, OWASP floor enforced on all new records)
- **Local-first** — all data stays on your device in an encrypted redb
  database
- **Touch ID unlock** (macOS) — biometric quick unlock via a Keychain-wrapped
  key; the master password itself is never stored
- **Recovery key (Emergency Kit)** — a random 256-bit key shown once at
  enable time; if the master password is ever forgotten, it restores access
  from the lock screen
- **Change master password** — full-vault re-encryption in a single
  transaction with automatic database backup
- **TOTP/2FA codes** — store a secret per entry (base32 or `otpauth://` URI)
  and read live 6-digit codes with a countdown
- **Multi-device sync** — end-to-end encrypted container on your own WebDAV
  (坚果云/Nextcloud/…) or Baidu Netdisk; deterministic last-writer-wins merge
  with rolling versioned snapshots, no account required
- **Browser auto-fill** via Chrome/Firefox extension (detects login forms,
  fills credentials; TOTP-aware)
- **System tray** — close-to-tray keeps the background server running for the
  extension
- **Auto-lock** — configurable (1–60 min), counts local keyboard/pointer
  activity, not just app requests
- **Clipboard security** — copied passwords auto-clear after 30 seconds
- **Password generator** — configurable length, character types, strength
  meter
- **Groups & tags** — organize entries with folders and labels
- **Fuzzy search** — weighted across titles, usernames, URLs and tags
- **Encrypted backups** — portable `.pvault` export with an independent
  export password, plus integrity-checked import
- **Zero-knowledge** — master password is never stored on disk; keys are
  zeroized on lock

## Security

| Component | Detail |
|-----------|--------|
| Encryption | AES-256-GCM with unique random nonce per operation; records bound by AAD |
| Key derivation | Argon2id (default 64 MB / 3 iterations; adaptive with an OWASP-floor import policy) |
| Key storage | Memory only, zeroized on lock. Optional Touch ID wrap key lives in the macOS Keychain behind a biometric access control |
| Integrity | AEAD-sealed vault header + HMAC digest over all tables; tampering fails unlock closed |
| Database | redb (pure Rust, ACID-compliant, embedded) |
| Master password | Verified via encrypted header, then zeroized |
| Sync | End-to-end encrypted container on your own cloud drive; the provider sees only ciphertext |
| Clipboard | Auto-clears after 30 seconds |
| Lock | Memory keys immediately zeroized; extension bridge loopback-only with per-browser pairing |

The browser extension never talks to the cloud and never sees sync
credentials — it is a client of the local vault on its own machine only.

## Desktop App

| Platform | Install | Biometric unlock | Cloud sync |
|----------|---------|------------------|------------|
| macOS 11+ (Apple Silicon) | `.dmg` | Touch ID | WebDAV / Baidu Netdisk |
| Windows 10/11 | NSIS `.exe` | — (Windows Hello planned) | WebDAV / Baidu Netdisk |
| Linux | build from source | — | WebDAV / Baidu Netdisk |

Grab the artifacts from
[GitHub Releases](https://github.com/chaojimaimi/PwdVault/releases) (the
Windows build is produced by CI; macOS local builds are unsigned — see
[docs/UNSIGNED-INSTALL.md](docs/UNSIGNED-INSTALL.md)).

### Sync in one minute

1. Settings → Sync → pick **WebDAV** (e.g. 坚果云: `https://dav.jianguoyun.com/dav/`
   with an app-specific password) and connect — the first device creates the
   encrypted container using the **container password** you choose.
2. On another device, install PwdVault, connect with the *same* WebDAV
   settings and container password — it pulls the full snapshot and merges.
3. Edit anywhere, press **Sync now** — deterministic last-writer-wins
   arbitration per entry, with the last 10 encrypted snapshots kept on the
   cloud for recovery.

## Browser Extension

Load `extensions/chrome/dist` (unpacked) or `extensions/firefox/dist`, pair
it with the running desktop app once (pairing code), and it auto-fills from
the local vault. The extension never talks to the cloud and never sees sync
credentials.

## Development

### Prerequisites

- [Node.js](https://nodejs.org/) LTS
- [pnpm](https://pnpm.io/)
- [Rust](https://rustup.rs/) stable (keep it current — CI gates run on the
  latest stable clippy)

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

# Rust workspace tests (parallel-safe per-AppState session)
cd src-tauri && cargo test --workspace --locked

# Native Messaging host tests
cd extensions/native-host && cargo test --locked
```

### Version Bump

```bash
./scripts/bump-version.sh 1.1.6 --changelog
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 19, TypeScript, Vite |
| Backend | Tauri v2, Rust (workspace: domain / infrastructure / application) |
| Database | redb (pure Rust, ACID, embedded) |
| Encryption | AES-256-GCM, Argon2id, HKDF subkeys, HMAC integrity layer |
| Cloud sync | WebDAV + Baidu Netdisk adapters over an encrypted snapshot container |
| Browser extension | Chrome/Firefox MV3, Native Messaging bridge |
| CI/CD | GitHub Actions (macOS + Windows + extension, fmt/clippy/deny gates) |

## Project Status

v1.1.6. See [CHANGELOG.md](CHANGELOG.md) for details.

### Roadmap

- macOS code signing & notarization (enables the data-protection Keychain)
- Windows Hello biometric unlock
- Secure notes & attachments
- Breach monitoring (HIBP)
- Scheduled background sync (today: manual + on-unlock)

## Data Files

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/com.pwdvault.app/vault.db` |
| Windows | `%LOCALAPPDATA%/PwdVault/vault.db` |
| Linux | `~/.local/share/pwdvault/vault.db` |

## License

[MIT](LICENSE)
