# Security Advisory Allowlist

> **Source**: Phase 6 Step 5 (§5.6.4)
> **Config**: `deny.toml` `[advisories].ignore`
> **Policy**: Each ignored RUSTSEC advisory must have a reason, an owner, and
> an expiry date. Expired entries cause `cargo deny check` to fail.

## Active allowlist

| RUSTSEC ID | Package | Reason | Expiry | Owner |
|------------|---------|--------|--------|-------|
| RUSTSEC-2024-0370 | bincode 1.x | Unmaintained; used for redb value serialization; no drop-in replacement; migration to bincode 2 or postcard planned | 2026-12-31 | backend |

## Review process

1. On each `cargo deny check` run in CI, expired entries fail the build.
2. To add a new ignore: append to `deny.toml`, add a row here, and open a PR
   explaining why the advisory cannot be fixed immediately.
3. To remove an ignore: delete from `deny.toml` and this table after the
   vulnerable dependency is upgraded or replaced.

## Known transitive warnings (not ignored, tracked for awareness)

The Tauri and GTK3 dependency trees on Linux produce RUSTSEC warnings for
older transitive crates (e.g. `linux-raw-sys`, `aes-soft` when hardware AES
is unavailable). These are upstream issues in Tauri's dependency closure and
resolve when Tauri updates its lockfile. They do not affect the macOS/Windows
release builds.
