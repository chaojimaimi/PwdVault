PwdVault Release Notes — v0.1.3.0

Release date: 2026-04-14

Summary
- This release packages the desktop application (Tauri) and verifies frontend/backend tests.
- Frontend: React 19 + Vite build produced `dist/` artifacts.
- Backend: Rust (Tauri) native binary built and bundled for macOS (arm64).

Artifacts (local)
- `releases/PwdVault_0.1.3_aarch64.dmg` — macOS DMG installer (arm64)
- `releases/PwdVault-macOS-v0.1.3.zip` — compressed `.app` bundle (macOS)

Verification
- Frontend tests: `pnpm test` — all passed (23/23).
- Rust tests: `cd src-tauri && cargo test -- --test-threads=1` — all passed (57/57).
- Production build: `pnpm build` succeeded; `pnpm tauri build` produced bundles.

Install (macOS)
- Mount the DMG and drag `PwdVault.app` to `/Applications`, or unzip the zip and move `PwdVault.app` to `/Applications`.

Notes
- Version file: `VERSION` currently contains `0.1.3.0`.
- If you want me to tag a GitHub release and push assets, I can prepare the release payload; please confirm.
