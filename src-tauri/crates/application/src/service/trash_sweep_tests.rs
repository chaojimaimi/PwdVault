//! Tests for the trash auto-purge sweep (WP3, v1.5.0).
//!
//! Coverage mapped from the plan: days=0 short-circuit (no scan, works
//! locked), expiry boundary (exactly-at-cutoff expires), single-transaction
//! ledger discipline (remote replay stays dead), locked-vault rejection,
//! live entries never enter the scan, the 500-row batch cap, and count
//! correctness.

use std::sync::Arc;

use super::{run_trash_auto_purge, MAX_TRASH_SWEEP_BATCH};
use crate::service::list_deleted_entries;
use crate::AppState;
use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
use pwdvault_infrastructure::database::{self, vault_store, PasswordEntry, Settings};
use pwdvault_infrastructure::vault_header::VaultHeader;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "trash-sweep-test-password";
const DAY: i64 = 86_400;

type Harness = (Arc<AppState>, TempDir, [u8; 32], [u8; 32]);

/// Unlocked AppState over a fresh database (csv_import_tests harness shape),
/// with the keys kept out so tests can insert sealed rows directly.
fn unlocked_state() -> Harness {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(database::init_database(dir.path().join("trash_sweep.db")).unwrap());
    let salt = [0x61; 16];
    let params = AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        pwdvault_infrastructure::crypto::kdf::derive_key_with_params(TEST_PASSWORD, &salt, &params)
            .unwrap();
    let verification =
        pwdvault_infrastructure::crypto::create_verification_header(&master_key, salt, params)
            .unwrap();
    let (enc_key, mac_key) =
        pwdvault_infrastructure::crypto::kdf::derive_subkeys(&master_key, &salt);

    database::vault_store::VaultStore::new(&db)
        .write(&mac_key, |txn| {
            database::vault_store::save_verification_data_in_txn(txn, &verification)?;
            pwdvault_infrastructure::vault_header::save_header_in_txn(
                txn,
                &VaultHeader::new_initial(),
                &enc_key,
            )?;
            database::vault_store::save_settings_in_txn(txn, &Settings::default())?;
            Ok(())
        })
        .unwrap();

    let state = Arc::new(AppState::default());
    *state.database.lock().unwrap() = Some(db);
    *state.verification_data.lock().unwrap() = Some(verification);
    state.session.unlock(enc_key, mac_key);
    (state, dir, enc_key, mac_key)
}

/// Locked variant: same database, session never unlocked.
fn locked_state() -> Harness {
    let (state, dir, enc_key, mac_key) = unlocked_state();
    state.lock_vault();
    (state, dir, enc_key, mac_key)
}

fn set_purge_days(state: &Arc<AppState>, mac_key: &[u8; 32], days: u32) {
    let db = state.database.lock().unwrap().clone().unwrap();
    let settings = Settings {
        trash_auto_purge_days: days,
        ..Settings::default()
    };
    database::vault_store::VaultStore::new(&db)
        .write(mac_key, |txn| {
            database::vault_store::save_settings_in_txn(txn, &settings)?;
            Ok(())
        })
        .unwrap();
}

/// Insert a sealed row directly (service-level helpers can't backdate
/// `deleted_at`, and the boundary tests need exact timestamps).
fn insert_entry(
    state: &Arc<AppState>,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
    entry: PasswordEntry,
) {
    let db = state.database.lock().unwrap().clone().unwrap();
    database::vault_store::VaultStore::new(&db)
        .write(mac_key, |txn| {
            vault_store::save_entry_in_txn(txn, enc_key, &entry)?;
            Ok(())
        })
        .unwrap();
}

fn tombstone(id: &str, deleted_at: i64) -> PasswordEntry {
    let mut entry = PasswordEntry::new(
        format!("title-{id}"),
        Some("https://example.test".to_string()),
        format!("user-{id}"),
    );
    entry.id = id.to_string();
    entry.encrypted_password = vec![1, 2, 3, 4]; // inner blob, never decrypted here
    entry.updated_at = deleted_at; // LWW: the tombstone bump
    entry.deleted_at = Some(deleted_at);
    entry
}

fn live_entry(id: &str) -> PasswordEntry {
    let mut entry = PasswordEntry::new(
        format!("title-{id}"),
        Some("https://example.test".to_string()),
        format!("user-{id}"),
    );
    entry.id = id.to_string();
    entry.encrypted_password = vec![1, 2, 3, 4];
    entry
}

fn purged_ids(state: &Arc<AppState>) -> std::collections::HashSet<String> {
    let db = state.database.lock().unwrap().clone().unwrap();
    vault_store::purged_entry_ids(&db).unwrap()
}

#[test]
fn days_zero_short_circuits_without_scanning_even_when_locked() {
    let (state, _dir, enc_key, mac_key) = locked_state();
    set_purge_days(&state, &mac_key, 0);
    // An expired tombstone exists, but days=0 must not even look at it —
    // and the locked session must not surface as an error either.
    insert_entry(&state, &enc_key, &mac_key, tombstone("old-one", 1_000));

    let purged = run_trash_auto_purge(&state, 10_000_000).unwrap();
    assert_eq!(purged, 0);
    let db = state.database.lock().unwrap().clone().unwrap();
    assert!(database::load_entry(&db, &enc_key, "old-one", false)
        .unwrap()
        .is_some());
}

#[test]
fn expired_tombstones_are_purged_with_accurate_count() {
    let (state, _dir, enc_key, mac_key) = unlocked_state();
    set_purge_days(&state, &mac_key, 7);
    let now = 1_000_000;
    insert_entry(
        &state,
        &enc_key,
        &mac_key,
        tombstone("gone-a", now - 8 * DAY),
    );
    insert_entry(
        &state,
        &enc_key,
        &mac_key,
        tombstone("gone-b", now - 30 * DAY),
    );
    insert_entry(
        &state,
        &enc_key,
        &mac_key,
        tombstone("gone-c", now - 90 * DAY),
    );
    insert_entry(
        &state,
        &enc_key,
        &mac_key,
        tombstone("fresh", now - 6 * DAY),
    );
    insert_entry(&state, &enc_key, &mac_key, live_entry("alive"));

    let purged = run_trash_auto_purge(&state, now).unwrap();
    assert_eq!(purged, 3);

    let remaining: Vec<String> = list_deleted_entries(&state)
        .unwrap()
        .into_iter()
        .map(|summary| summary.id)
        .collect();
    assert_eq!(remaining, vec!["fresh".to_string()]);
    // Live entries are untouched by definition (list_all_entries, not trash).
    let db = state.database.lock().unwrap().clone().unwrap();
    assert!(database::load_entry(&db, &enc_key, "alive", false)
        .unwrap()
        .is_some());
}

#[test]
fn boundary_exactly_at_cutoff_counts_as_expired() {
    let (state, _dir, enc_key, mac_key) = unlocked_state();
    set_purge_days(&state, &mac_key, 1);
    let now = 50 * DAY;
    insert_entry(
        &state,
        &enc_key,
        &mac_key,
        tombstone("at-cutoff", now - DAY),
    );
    insert_entry(
        &state,
        &enc_key,
        &mac_key,
        tombstone("inside", now - DAY + 1),
    );

    assert_eq!(run_trash_auto_purge(&state, now).unwrap(), 1);
    assert!(purged_ids(&state).contains("at-cutoff"));
    let remaining: Vec<String> = list_deleted_entries(&state)
        .unwrap()
        .into_iter()
        .map(|summary| summary.id)
        .collect();
    assert_eq!(remaining, vec!["inside".to_string()]);
}

#[test]
fn ledger_record_shares_the_transaction_remote_replay_stays_dead() {
    let (state, _dir, enc_key, mac_key) = unlocked_state();
    set_purge_days(&state, &mac_key, 7);
    let now = 1_000_000;
    insert_entry(
        &state,
        &enc_key,
        &mac_key,
        tombstone("replayed", now - 30 * DAY),
    );

    assert_eq!(run_trash_auto_purge(&state, now).unwrap(), 1);
    // The delete and the ledger record committed together: a crash between
    // them is impossible, and a sync that re-inserts the same tombstone is
    // suppressed by the ledger (never reappears in the trash).
    assert!(purged_ids(&state).contains("replayed"));

    // Simulate the remote replay: same id, tombstoned, "newer" timestamp.
    insert_entry(&state, &enc_key, &mac_key, tombstone("replayed", now + DAY));
    let visible: Vec<String> = list_deleted_entries(&state)
        .unwrap()
        .into_iter()
        .map(|summary| summary.id)
        .collect();
    assert!(
        visible.is_empty(),
        "replayed row must stay ledger-suppressed"
    );
}

#[test]
fn ledger_suppressed_rows_are_swept_like_empty_trash() {
    let (state, _dir, enc_key, mac_key) = unlocked_state();
    set_purge_days(&state, &mac_key, 7);
    let now = 1_000_000;
    // A tombstone whose id is ALREADY in the ledger (a sync refill of a
    // previously purged entry): expired ones go too, else refills linger.
    insert_entry(
        &state,
        &enc_key,
        &mac_key,
        tombstone("refill", now - 30 * DAY),
    );
    {
        let db = state.database.lock().unwrap().clone().unwrap();
        database::vault_store::VaultStore::new(&db)
            .write(&mac_key, |txn| {
                vault_store::record_purged_entries_in_txn(
                    txn,
                    ["refill".to_string()].as_slice(),
                    now - DAY,
                )?;
                Ok(())
            })
            .unwrap();
    }

    assert_eq!(run_trash_auto_purge(&state, now).unwrap(), 1);
    let db = state.database.lock().unwrap().clone().unwrap();
    assert!(database::load_entry(&db, &enc_key, "refill", false)
        .unwrap()
        .is_none());
}

#[test]
fn live_entries_never_enter_the_scan() {
    let (state, _dir, enc_key, mac_key) = unlocked_state();
    set_purge_days(&state, &mac_key, 7);
    let now = 1_000_000;
    // Ancient live rows: wrong predicate (e.g. filtering on updated_at or
    // dropping the deleted_at guard) would destroy user data here.
    insert_entry(&state, &enc_key, &mac_key, live_entry("ancient-live"));

    assert_eq!(run_trash_auto_purge(&state, now).unwrap(), 0);
    let db = state.database.lock().unwrap().clone().unwrap();
    assert!(database::load_entry(&db, &enc_key, "ancient-live", false)
        .unwrap()
        .is_some());
    assert!(purged_ids(&state).is_empty());
}

#[test]
fn locked_vault_is_rejected_when_enabled() {
    let (state, _dir, _enc_key, mac_key) = locked_state();
    set_purge_days(&state, &mac_key, 30);
    assert!(run_trash_auto_purge(&state, 1_000_000).is_err());
}

#[test]
fn batch_cap_purges_at_most_500_per_call() {
    let (state, _dir, enc_key, mac_key) = unlocked_state();
    set_purge_days(&state, &mac_key, 7);
    let now = 1_000_000;
    for i in 0..(MAX_TRASH_SWEEP_BATCH + 5) {
        insert_entry(
            &state,
            &enc_key,
            &mac_key,
            tombstone(&format!("bulk-{i:04}"), now - 30 * DAY),
        );
    }

    assert_eq!(
        run_trash_auto_purge(&state, now).unwrap(),
        MAX_TRASH_SWEEP_BATCH,
        "one unlock deletes at most one bounded batch"
    );
    let remaining = list_deleted_entries(&state).unwrap().len();
    assert_eq!(remaining, 5, "the balance waits for the next unlock");

    // The backlog drains batch-by-batch on subsequent calls.
    assert_eq!(run_trash_auto_purge(&state, now).unwrap(), 5);
    assert!(list_deleted_entries(&state).unwrap().is_empty());
}
