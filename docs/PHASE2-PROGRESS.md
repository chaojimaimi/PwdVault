# Phase 2 Implementation Progress

> **Document**: 统一输入边界与备份安全
> **Plan**: PwdVault-Comprehensive-Optimization-Plan-v1.0.5.md §5.2.1–5.2.7
> **Date**: 2026-07-16
> **Status**: ⚠️ Core implementation and macOS/Linux acceptance complete; Windows ACL acceptance pending

---

## Summary

Phase 2 centralizes untrusted-input validation, bounds Argon2 resource use,
introduces an authenticated backup v2 envelope, makes format evolution
explicit, and restricts sensitive files on Unix platforms. New exports use v2;
published v1 backups remain importable in read-only compatibility mode.

The implementation is complete for the current macOS/Linux development
environment. The cross-platform acceptance criterion is not closed because a
current-user-only Windows ACL implementation and Windows automation have not
yet been added.

## Implemented Scope

### ValidationPolicy

- Added one service-layer validation policy shared by Tauri IPC and the HTTP /
  Native Messaging adapter.
- Added stable `InvalidInput` error codes and public error messages.
- Enforced limits and invariants for master/export/import passwords, entries,
  tags, groups, IDs, settings, password-generator options, and backup payloads.
- Group references must exist, group names are unique case-insensitively, and
  invalid values are rejected rather than silently clamped.
- Backup record counts, field limits, duplicate IDs, and group references are
  checked before the first database write.

### KdfPolicy

- Validates Argon2 parameters before constructing `argon2::Params` or
  allocating derivation memory.
- Allowed memory: 16–256 MiB; iterations: 1–10; parallelism: 1–8.
- Enforces a combined `memory × iterations` ceiling equivalent to 1 GiB.
- Extreme values such as `u32::MAX` are rejected in the fast pre-derivation
  path.

### Backup v2 and v1 Compatibility

- New exports use version 2 with `PWDVAULT` magic, `argon2id`, and
  `aes-256-gcm` algorithm identifiers.
- The canonical envelope header is authenticated as AES-GCM AAD; nonce and
  ciphertext tampering also fail authentication.
- Import ordering is bounded: envelope/file size → Base64 and binary lengths →
  algorithm/KDF validation → derivation → decryption → payload validation →
  single-transaction replacement.
- Ciphertext is capped at 10 MiB; desktop/browser UI rejects files above
  14 MiB before reading/parsing them.
- Existing v1 fixtures remain importable; all new exports are v2.

### Database Format Evolution

- Existing record envelopes retain explicit record format versions.
- Added an explicit migration registry with `LegacyToV1` and sequential
  `vN -> vN+1` planning.
- Unknown future and skipped versions fail closed and are never written.
- Settings use defaults only when the record is absent; corrupt stored settings
  now return a deserialization error.

### Sensitive File Permissions

- On Unix, application data/log directories are restricted to `0700` and
  sensitive files to `0600`.
- Database creation pre-creates the file with restrictive permissions before
  redb opens it.
- Native Messaging manifest/config creation uses the same permission helpers.
- Existing application-owned paths are repaired on startup without changing
  permissions on an already-existing unrelated parent directory.

## §5.2.7 Acceptance Criteria Verification

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Tauri、HTTP、import 使用同一非法输入策略和稳定错误码 | ✅ | All entry points converge on service-layer `ValidationPolicy`; `InvalidInput` exposes stable codes |
| 2 | 空或过短主密码无法创建 vault | ✅ | Initialization calls master-password validation; short-password regression test passes |
| 3 | 极端 KDF 参数快速拒绝且不先分配大内存 | ✅ | Pre-derivation `KdfPolicy` validation and `<50 ms` extreme-parameter test pass |
| 4 | v2 header、nonce、ciphertext 篡改均失败 | ✅ | Automated v2 tamper tests cover all three regions |
| 5 | 超大备份、超多记录、超长字段、无效 settings 在首次写入前拒绝 | ✅ | Envelope/payload policies run before single import transaction; oversized backup regression test passes |
| 6 | v1 fixture 可读，v2 round-trip 通过 | ✅ | Both compatibility and round-trip tests pass |
| 7 | macOS/Linux 权限自动化及 Windows ACL 验证 | ⚠️ Partial | Unix `0700`/`0600` test passes; Windows current-user-only ACL is pending |

## Verification Results

| Gate | Result |
|---|---|
| Rust main app `cargo check --tests` | Passed |
| Rust main app tests | 133 passed, 1 ignored benchmark |
| Main app `cargo fmt --check` / Clippy `-D warnings` | Passed |
| Native host tests | 14 passed |
| Native host `cargo fmt --check` / Clippy `-D warnings` | Passed |
| TypeScript | Passed |
| Frontend tests | 31 passed across 8 files |
| Frontend production build | Passed; existing Vite mixed-import warning only |
| Extension source package verification | Passed; existing Firefox source symlinks are resolved but remain unsuitable as raw distribution content |
| `cargo audit --no-fetch` (main app) | Exit 0; 21 explicitly allowed warnings, no unallowed vulnerability finding |
| `cargo audit --no-fetch` (native host) | Passed with no findings |

## Remaining Boundaries and Risks

1. **Windows ACL** — implement secure creation and startup repair using an ACL
   that grants access only to the current user, then verify it on a Windows CI
   runner. Until this passes, Phase 2 is not fully cross-platform complete.
2. **HTTP import size mismatch** — the HTTP request body is capped at 10 MiB,
   while a 10 MiB ciphertext expands when Base64 encoded in JSON. Large
   extension imports may therefore be rejected by the transport before backup
   validation. Resolve this with bounded transport/protocol work in Phase 5.
3. **RustSec allowlist** — the main app currently reports 21 allowed warnings,
   mainly Tauri/Linux GTK3 transitive dependencies plus bincode 1.x. Phase 6
   must assign owner, rationale, and expiry to each allowlist category.
4. **Independent security review** — Phase 1 session/transaction work and Phase
   2 parsing/KDF/backup boundaries should receive independent review before a
   stable release.

## Release Decision

Stable release remains frozen. Development/nightly validation may continue,
but Windows ACL acceptance, Phase 3 data-trust/privacy requirements, the Phase
5 Native Messaging release boundary, Phase 6 release gates, and independent
security review remain required before declaring a stable security release.
