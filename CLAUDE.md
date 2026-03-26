# PwdVault

A secure, local-first password manager built with Tauri + React.

## Development

```bash
# Install dependencies
pnpm install

# Start development server
pnpm tauri dev
```

## Build

```bash
# Build for production
pnpm tauri build
```

## Tech Stack

- **Frontend**: React 19 + TypeScript + Vite
- **Backend**: Tauri v2 + Rust
- **Database**: redb (pure Rust, ACID)
- **Encryption**: AES-256-GCM + Argon2id

## Project Structure

```
src/              # React frontend
src-tauri/        # Rust backend
  src/
    lib.rs        # Tauri commands
    main.rs       # Entry point
  Cargo.toml      # Rust dependencies
```

## Security

- Master password never stored
- AES-256-GCM encryption for all sensitive data
- Argon2id key derivation with adaptive parameters
- Zeroizing strings for password handling