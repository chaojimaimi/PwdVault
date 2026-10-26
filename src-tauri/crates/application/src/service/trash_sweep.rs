//! Trash auto-purge (WP3, v1.5.0) — opt-in physical deletion of expired
//! tombstones, driven by the ADAPTERS after a successful unlock.
//!
//! WHY a standalone module: the application layer has no emit capability, so
//! the sweep is a pure function returning the purge count; the Tauri unlock
//! commands and the Native Messaging dispatcher unlock arm (the only callers)
//! surface `trash-auto-purged(count)` themselves and own the `AppHandle`.
//! It also must NOT live in `entries.rs` (over the 800-line module cap —
//! see the plan's module-placement discipline).
//!
//! Known limitation (documented in the settings UI copy): the scan only runs
//! right after an unlock, because `deleted_at` lives inside the encrypted
//! blob and is unreadable while locked. An always-unlocked vault therefore
//! never sweeps, and a changed setting takes effect at the next unlock.
//! `recover_vault` / `change_password` reach the same key-publish path but
//! deliberately do NOT sweep — the next unlock catches up.

use std::sync::Arc;

use crate::service::vault::get_db;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::database::{list_all_entries_bulk, load_settings, vault_store};

/// One sweep deletes at most this many rows per call. Deliberately equal to
/// the purge-ledger cap (`database::MAX_PURGED_LEDGER`) so "one unlock deletes
/// one batch" keeps the unlock path's added latency strictly bounded — a
/// larger backlog shrinks by one batch per unlock. (A pre-existing ledger
/// near the cap can still evict this batch's oldest records — the eviction
/// tradeoff documented on `record_purged_entries_in_txn`.)
pub const MAX_TRASH_SWEEP_BATCH: usize = 500;

/// Physically delete tombstones whose `deleted_at` is at least
/// `trash_auto_purge_days` old — an arbitrary bounded batch (table order;
/// there is no oldest-first guarantee), one batch per call.
/// Returns the number of rows removed (0 when the feature is off or nothing
/// expired). Live entries NEVER enter the scan; ledger-suppressed rows (sync
/// refills of already-purged ids) are swept too — same semantics as
/// `empty_trash`, and the delete + ledger record share ONE transaction so a
/// crash can never leave a deleted row without its ledger record (otherwise
/// the next sync would pull the remote tombstone right back into the trash).
///
/// `now` is unix seconds and comes from the caller so tests can pin the
/// clock. A locked vault fails at the session lease (the adapters only call
/// this after a successful unlock; the error is logged there, never surfaced).
pub fn run_trash_auto_purge(state: &Arc<AppState>, now: i64) -> Result<usize, VaultError> {
    let db = get_db(state)?;

    // Settings first and lease-free: with the feature off (the default) the
    // sweep short-circuits before touching the session, so a locked vault
    // with days=0 is a clean Ok(0), not a spurious VaultLocked error.
    let days = load_settings(&db)?.trash_auto_purge_days;
    if days == 0 {
        return Ok(0);
    }

    let lease = state.lease()?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    let cutoff = now.saturating_sub(i64::from(days) * 86_400);
    let mut expired_ids: Vec<String> = list_all_entries_bulk(&db, key, None)?
        .into_iter()
        // Tombstones only (`deleted_at` set); live entries never enter the
        // scan, no matter how stale their `updated_at`. At exactly the cutoff
        // the entry counts as expired (age >= N days).
        .filter(|entry| {
            entry
                .deleted_at
                .is_some_and(|deleted_at| deleted_at <= cutoff)
        })
        .map(|entry| entry.id)
        .collect();

    // Single bounded batch per call; the remainder waits for the next unlock.
    if expired_ids.len() > MAX_TRASH_SWEEP_BATCH {
        expired_ids.truncate(MAX_TRASH_SWEEP_BATCH);
    }
    if expired_ids.is_empty() {
        return Ok(0);
    }

    let count = expired_ids.len();
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        for id in &expired_ids {
            vault_store::remove_entry_in_txn(txn, id)?;
        }
        vault_store::record_purged_entries_in_txn(txn, &expired_ids, now)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(count)
}

#[cfg(test)]
#[path = "trash_sweep_tests.rs"]
mod tests;
