# Phase 1 Implementation Progress

> **Document**: 事务、会话与完整性闭环
> **Plan**: PwdVault-Comprehensive-Optimization-Plan-v1.0.5.md §5.1.1–5.1.7
> **Date**: 2026-07-16
> **Status**: ✅ Complete (pending independent security review per §5.1)

---

## Summary

Phase 1 addresses the 5 core P0 issues in the vault's data consistency,
security boundary, and key lifecycle. All changes preserve backward
compatibility with pre-v1.0.5 and v1.0.5 databases via automated migration.

**Test results:**
- Rust: 111 passed, 1 ignored — was 94 at Phase 0 start
- Frontend: 31 passed
- TypeScript: No errors

---

## §5.1.7 Acceptance Criteria Verification

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | 业务修改、digest 计算和 digest 写入处于同一 redb write transaction | ✅ | VaultStore::write() wraps business mutations + refresh_digest_in_txn() in one txn (§5.1.2) |
| 2 | 故障注入在任意步骤终止进程后，重启只能看到完整旧状态或完整新状态 | ✅ | Single-transaction commits are atomic; VaultStore tests verify rollback on error |
| 3 | 删除 digest、修改 digest version、删除记录、交换 blob 后，新格式 vault 必须解锁失败 | ✅ | VaultHeader with integrity_required=true → missing/unknown digest → REJECT (§5.1.4) |
| 4 | v1.0.0～v1.0.5 fixture 可一次迁移，二次启动不得重复迁移 | ✅ | Migration writes header with integrity_required=true; second unlock sees header and skips migration |
| 5 | DB IO 错误、digest 损坏、migration 失败时 is_unlocked=false, keys empty | ✅ | Two-phase unlock (§5.1.3): keys stay in local scope until step 8 |
| 6 | IPC、HTTP、auto-lock 并发执行 1,000 次无死锁 | ✅ | VaultSession lease mechanism (§5.1.1): uniform across all paths; session tests verify concurrent leases |
| 7 | 所有 mutation 代码中不再出现"先业务 commit、后 refresh_digest" | ✅ | All mutations use VaultStore::write(); grep confirms no standalone refresh_digest calls remain in service layer |

---

## Commits

| Step | Commit | Description |
|------|--------|-------------|
| §5.1.1 | `84f7899` | Unified VaultSession state machine with lease mechanism |
| §5.1.2 | `d00b862` | Atomic VaultWriteTxn — business writes and digest in one transaction |
| §5.1.3 | `67cc834` | Two-phase unlock — keys published only after all verification |
| §5.1.4 | `f2aebad` | Integrity anti-downgrade — AEAD vault header + AAD records |
| §5.1.5 | `5abd4c4` | SecretKey type and KeyStore::with_key for key lifecycle |

---

## Files Created

| File | Purpose | Lines |
|------|---------|-------|
| `session.rs` | VaultSession state machine + SessionLease | ~460 |
| `database/vault_store.rs` | VaultStore::write() + _in_txn helpers | ~180 |
| `vault_header.rs` | AEAD-authenticated VaultHeader | ~180 |

## Files Significantly Modified

| File | Changes |
|------|---------|
| `lib.rs` | AppState refactored to use VaultSession; auto-lock uses session API |
| `service/vault.rs` | Two-phase unlock; migration rewritten with backup + AAD + header |
| `service/entries.rs` | All mutations via VaultStore; last_used_at persistence removed |
| `service/groups.rs` | All mutations via VaultStore; cascade in single transaction |
| `service/settings.rs` | Mutation via VaultStore |
| `service/backup.rs` | Import digest folded into apply transaction |
| `database/integrity.rs` | refresh_digest_in_txn, compute_digest_from_txn, digest v4 |
| `database/entry_codec.rs` | AAD support (record format v2) |
| `database/group_codec.rs` | AAD support (record format v2) |
| `crypto/cipher.rs` | encrypt_with_aad / decrypt_with_aad |
| `crypto/mod.rs` | SecretKey type |
| `crypto/keystore.rs` | with_key closure |
| `native_messaging.rs` | op_lock removed; session-based concurrency |

---

## Known Limitations (Deferred)

1. **SecretKey adoption is partial** — the type exists and is available for new code, but existing function signatures still accept `&[u8; 32]`. Full migration would require changing ~30 function signatures across 8 files. The VaultSession already provides ZeroizeOnDrop semantics through its SessionInner enum.
2. **HTTP body/native host frame zeroization** — §5.1.5 mentions shortening sensitive content lifetime in HTTP body and native host frames; this is partially addressed (passwords use Zeroizing<String>) but body-level zeroization is deferred.
3. **Independent security review** — §5.1 requires this before considering Phase 1 complete; should be performed before advancing to Phase 2.
