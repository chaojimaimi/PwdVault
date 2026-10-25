use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use crate::service::vault::get_db;
use crate::{
    validation, AppState, CreateEntryRequest, EntrySecretResponse, EntrySummary,
    UpdateEntryRequest, VaultError,
};
use pwdvault_domain::constants::LAST_USED_BUMP_THROTTLE_SECS;
use pwdvault_infrastructure::crypto::{
    bc_deserialize, bc_serialize, decrypt, encrypt, EncryptedData,
};
use pwdvault_infrastructure::database;
use pwdvault_infrastructure::database::{
    list_all_entries_bulk, load_entry, vault_store, PasswordEntry,
};

pub fn create_entry(
    state: &Arc<AppState>,
    request: CreateEntryRequest,
) -> Result<EntrySummary, VaultError> {
    let mut request = request;
    request.url = validation::normalize_url(request.url);
    let lease = state.lease()?;
    validation::entry(&request)?;

    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;
    if let Some(group_id) = &request.group_id {
        if database::load_group(&db, key, group_id, false)?.is_none() {
            return Err(VaultError::InvalidInput {
                code: "UNKNOWN_GROUP".into(),
                message: "Group does not exist".into(),
            });
        }
    }

    // Encrypt password and notes BEFORE opening the write transaction,
    // so crypto failures roll back cleanly without holding the write lock.
    let encrypted_password = encrypt(key, request.password.as_bytes())?;
    let encrypted_password_bytes = bc_serialize(&encrypted_password)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

    let encrypted_notes = if let Some(notes) = &request.notes {
        let encrypted = encrypt(key, notes.as_bytes())?;
        let bytes =
            bc_serialize(&encrypted).map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        Some(bytes)
    } else {
        None
    };

    let mut entry = PasswordEntry::new(request.title, request.url, request.username);
    entry.encrypted_password = encrypted_password_bytes;
    entry.encrypted_notes = encrypted_notes;
    entry.tags = request.tags;
    entry.group_id = request.group_id;

    // Single transaction: business write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_entry_in_txn(txn, key, &entry)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(entry.into())
}

pub fn get_entry_meta(state: &Arc<AppState>, id: String) -> Result<EntrySummary, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let entry = load_entry(&db, key, &id, false)?.ok_or(VaultError::EntryNotFound)?;
    // Soft delete (P2.2): a tombstoned entry is invisible to callers.
    if entry.deleted_at.is_some() {
        return Err(VaultError::EntryNotFound);
    }

    lease.touch_remote_activity();

    Ok(entry.into())
}

pub fn get_entry_secret(
    state: &Arc<AppState>,
    id: String,
) -> Result<EntrySecretResponse, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mut entry = load_entry(&db, key, &id, false)?.ok_or(VaultError::EntryNotFound)?;
    // Soft delete (P2.2): a tombstoned entry must not give up its secrets —
    // same filter as get_entry_meta (this is the extension's secret-fetch
    // path; the row survives for merge/reseal, but reads must 404).
    if entry.deleted_at.is_some() {
        return Err(VaultError::EntryNotFound);
    }

    // Decrypt password. Try bincode format first (v1.0.5+ and v1.0.4 both use
    // bc_serialize(EncryptedData)), then fall back to raw bytes
    // (nonce||ciphertext) just in case an older build used to_bytes().
    let encrypted_password: EncryptedData =
        bc_deserialize(&entry.encrypted_password).or_else(|e| {
            EncryptedData::from_bytes(&entry.encrypted_password)
                .map_err(|e2| VaultError::DecryptionFailed(format!("bincode: {} / raw: {}", e, e2)))
        })?;
    let mut password_bytes = decrypt(key, &encrypted_password)?;
    let password = Zeroizing::new(
        String::from_utf8(password_bytes.clone())
            .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?,
    );

    // Decrypt notes if present
    let notes = if let Some(encrypted_notes_bytes) = &entry.encrypted_notes {
        let encrypted: EncryptedData = bc_deserialize(encrypted_notes_bytes).or_else(|e| {
            EncryptedData::from_bytes(encrypted_notes_bytes)
                .map_err(|e2| VaultError::DecryptionFailed(format!("bincode: {} / raw: {}", e, e2)))
        })?;
        let mut notes_bytes = decrypt(key, &encrypted)?;
        let notes_str = Zeroizing::new(
            String::from_utf8(notes_bytes.clone())
                .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?,
        );
        notes_bytes.zeroize();
        Some(notes_str)
    } else {
        None
    };

    // Zeroize intermediate password bytes
    password_bytes.zeroize();

    // v1.4.0: restored the last_used_at persistence that §5.1.2 removed,
    // behind a 60-second write throttle. §5.1.2's complaint was write
    // amplification (every fetch = entry re-seal + full digest refresh); the
    // throttle reduces that to at most one write per entry per minute, gated
    // by the CURRENT stored value alone (no extra state).
    // SYNC SEMANTICS (deliberate, review-verified): the bump explicitly does
    // NOT touch updated_at. last_used_at is device-local metadata —
    // `SyncEntry` has no such field (sync/mod.rs), so a pure bump never
    // changes the sync payload, never triggers a push, and never moves the
    // LWW fingerprint. When a merge DOES rewrite a row, the winner's payload
    // carries last_used_at=None and the local value resets — accepted
    // best-effort behavior for a device-local field. Pinned by tests:
    // `get_entry_secret_throttles_last_used_at_writes` (service) and the NM
    // contract test.
    let now = chrono::Utc::now().timestamp();
    if entry
        .last_used_at
        .is_none_or(|last| now - last > LAST_USED_BUMP_THROTTLE_SECS)
    {
        entry.last_used_at = Some(now);
        let mac_key = lease.mac_key()?;
        // Single transaction: bump + digest refresh (§5.1.2 pattern).
        vault_store::VaultStore::new(&db).write(mac_key, |txn| {
            vault_store::save_entry_in_txn(txn, key, &entry)?;
            Ok(())
        })?;
    }

    lease.touch_remote_activity();

    Ok(EntrySecretResponse {
        password,
        notes,
        last_used_at: entry.last_used_at,
    })
}

pub fn list_all_entries(state: &Arc<AppState>) -> Result<Vec<EntrySummary>, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;

    // §5.6.2: single read transaction bulk scan instead of 1+N.
    // Soft delete (P2.2): the infra bulk scan is raw (reseal_vault depends on
    // it); the service layer filters tombstones out here. The filter is
    // tombstone-only and deliberately ignores the purge ledger — a LIVE row
    // is served no matter what the ledger says.
    let entries = list_all_entries_bulk(&db, key, None)?
        .into_iter()
        .filter(|entry| entry.deleted_at.is_none())
        .collect::<Vec<_>>();

    // Purge-ledger reconciliation (v1.4.0): a LIVE row whose id is recorded
    // proves a merge revival / import resurrected the entry after a purge.
    // The row was served above (no live-row filtering); here the stale
    // ledger records are dropped so a LATER tombstone shows up in the trash
    // again — otherwise every sync would re-suppress it (= silent data
    // loss). Best-effort: a failed reconciliation only delays the cleanup to
    // the next successful list.
    reconcile_purged_ledger(&db, &lease, &entries)?;

    let summaries: Vec<EntrySummary> = entries.into_iter().map(Into::into).collect();

    lease.touch_remote_activity();

    Ok(summaries)
}

/// Drop ledger records for ids that now exist as LIVE rows (see
/// [`list_all_entries`]). Errors are logged and swallowed: the ledger is
/// local bookkeeping, the caller's read result stays valid either way.
fn reconcile_purged_ledger(
    db: &Arc<redb::Database>,
    lease: &crate::session::SessionLease<'_>,
    live_entries: &[PasswordEntry],
) -> Result<(), VaultError> {
    let purged = vault_store::purged_entry_ids(db)?;
    let stale_ids: Vec<String> = live_entries
        .iter()
        .filter(|entry| purged.contains(&entry.id))
        .map(|entry| entry.id.clone())
        .collect();
    if stale_ids.is_empty() {
        return Ok(());
    }
    let mac_key = lease.mac_key()?;
    let outcome = vault_store::VaultStore::new(db).write(mac_key, |txn| {
        for id in &stale_ids {
            vault_store::remove_purged_entry_in_txn(txn, id)?;
        }
        Ok(())
    });
    if let Err(error) = outcome {
        tracing::warn!("purge-ledger reconciliation failed: {error}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Trash (v1.4.0): soft-deleted entries. Tauri IPC only — the browser
// extension never sees the trash (D6, touch_activity precedent).
// ---------------------------------------------------------------------------

/// Tombstoned entries still visible in the trash: `deleted_at` set AND the id
/// not recorded in the purge ledger (ledger entries are rows a sync cycle
/// re-inserted after a physical delete — invisible by design).
pub fn list_deleted_entries(state: &Arc<AppState>) -> Result<Vec<EntrySummary>, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;

    let purged = vault_store::purged_entry_ids(&db)?;
    let entries = list_all_entries_bulk(&db, key, None)?
        .into_iter()
        .filter(|entry| entry.deleted_at.is_some())
        .filter(|entry| !purged.contains(&entry.id))
        .collect::<Vec<_>>();
    let summaries: Vec<EntrySummary> = entries.into_iter().map(Into::into).collect();

    lease.touch_remote_activity();

    Ok(summaries)
}

/// Restore a tombstoned entry. The `updated_at` bump is REQUIRED, not
/// cosmetic: LWW arbitration (merge.rs `merge_entry_pair`) lets a tombstone
/// win only when `deleted_at >= loser.updated_at` — the restore must present
/// itself as the newest change so a remote tombstone loses and the revival
/// sticks through the next sync.
pub fn restore_entry(state: &Arc<AppState>, id: String) -> Result<EntrySummary, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    let mut entry = load_entry(&db, key, &id, false)?.ok_or(VaultError::EntryNotFound)?;
    // Restoring a live entry is a caller bug, not a no-op.
    if entry.deleted_at.is_none() {
        return Err(VaultError::InvalidInput {
            code: "ENTRY_NOT_DELETED".into(),
            message: "Entry is not in the trash".into(),
        });
    }

    entry.deleted_at = None;
    entry.updated_at = chrono::Utc::now().timestamp();

    // Single transaction: revival + digest refresh + ledger cleanup (the row
    // is live again, so any stale purge record must go with it).
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_entry_in_txn(txn, key, &entry)?;
        vault_store::remove_purged_entry_in_txn(txn, &entry.id)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(entry.into())
}

/// Physically delete one tombstoned row and record the id in the purge
/// ledger (same transaction — a crash must never leave a deleted row without
/// its ledger record, or the next sync refills the trash). Purging a LIVE
/// entry is refused: the trash flow only ever offers tombstones.
pub fn purge_entry(state: &Arc<AppState>, id: String) -> Result<bool, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    let entry = load_entry(&db, key, &id, false)?;
    match entry {
        None => {
            // Row already gone: idempotent success only if this exact id was
            // purged before; a never-seen id is a caller bug.
            if vault_store::purged_entry_ids(&db)?.contains(&id) {
                Ok(false)
            } else {
                Err(VaultError::EntryNotFound)
            }
        }
        Some(entry) => {
            if entry.deleted_at.is_none() {
                return Err(VaultError::InvalidInput {
                    code: "ENTRY_NOT_DELETED".into(),
                    message: "Only deleted entries can be purged".into(),
                });
            }
            let now = chrono::Utc::now().timestamp();
            let entry_id = entry.id.clone();
            let store = vault_store::VaultStore::new(&db);
            store.write(mac_key, |txn| {
                vault_store::remove_entry_in_txn(txn, &entry_id)?;
                vault_store::record_purged_entries_in_txn(
                    txn,
                    std::slice::from_ref(&entry_id),
                    now,
                )?;
                Ok(())
            })?;
            lease.touch_remote_activity();
            Ok(true)
        }
    }
}

/// Physically delete EVERY tombstoned row (including ledger-suppressed ones
/// — their rows are sync refills that would otherwise linger forever) and
/// record all ids. Returns the number of rows removed.
pub fn empty_trash(state: &Arc<AppState>) -> Result<usize, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    let tombstone_ids: Vec<String> = list_all_entries_bulk(&db, key, None)?
        .into_iter()
        .filter(|entry| entry.deleted_at.is_some())
        .map(|entry| entry.id)
        .collect();
    if tombstone_ids.is_empty() {
        return Ok(0);
    }

    let now = chrono::Utc::now().timestamp();
    let count = tombstone_ids.len();
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        for id in &tombstone_ids {
            vault_store::remove_entry_in_txn(txn, id)?;
        }
        vault_store::record_purged_entries_in_txn(txn, &tombstone_ids, now)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(count)
}

pub fn update_entry<R: Into<UpdateEntryRequest>>(
    state: &Arc<AppState>,
    id: String,
    request: R,
) -> Result<EntrySummary, VaultError> {
    let mut request = request.into();
    request.url = validation::normalize_url(request.url);
    let lease = state.lease()?;
    validation::id(&id)?;
    validation::entry_update(&request)?;

    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;
    if let Some(group_id) = &request.group_id {
        if database::load_group(&db, key, group_id, false)?.is_none() {
            return Err(VaultError::InvalidInput {
                code: "UNKNOWN_GROUP".into(),
                message: "Group does not exist".into(),
            });
        }
    }

    let mut entry = load_entry(&db, key, &id, false)?.ok_or(VaultError::EntryNotFound)?;
    // Soft delete (P2.2): editing a tombstoned entry must not resurrect it.
    if entry.deleted_at.is_some() {
        return Err(VaultError::EntryNotFound);
    }

    // Update fields
    entry.title = request.title;
    entry.url = request.url;
    entry.username = request.username;
    entry.tags = request.tags;
    entry.group_id = request.group_id;
    entry.updated_at = chrono::Utc::now().timestamp();

    // Only replace sensitive fields explicitly included in the patch.
    if let Some(password) = &request.password {
        let encrypted_password = encrypt(key, password.as_bytes())?;
        entry.encrypted_password = bc_serialize(&encrypted_password)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
    }

    // Encrypt and update notes
    if request.update_notes {
        entry.encrypted_notes = if let Some(notes) = &request.notes {
            let encrypted = encrypt(key, notes.as_bytes())?;
            Some(
                bc_serialize(&encrypted)
                    .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?,
            )
        } else {
            None
        };
    }

    // TOTP tri-state (P2.4): None = leave unchanged, Some("") = clear,
    // Some(x) = encrypt and set (plain base32 or a whole otpauth:// URI —
    // the code generator parses either at read time).
    if let Some(totp_secret) = &request.totp_secret {
        entry.encrypted_totp_secret = if totp_secret.is_empty() {
            None
        } else {
            let encrypted = encrypt(key, totp_secret.as_bytes())?;
            Some(
                bc_serialize(&encrypted)
                    .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?,
            )
        };
    }

    // Single transaction: business write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_entry_in_txn(txn, key, &entry)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(entry.into())
}

pub fn remove_entry(state: &Arc<AppState>, id: String) -> Result<bool, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    // Soft delete (P2.2): stamp a tombstone and keep the row. The row must
    // survive so multi-device merge (P3.1) can arbitrate the deletion against
    // concurrent edits, and reseal_vault keeps seeing a consistent table.
    let mut entry = match load_entry(&db, key, &id, false)? {
        Some(entry) => entry,
        None => return Ok(false),
    };
    let now = chrono::Utc::now().timestamp();
    entry.deleted_at = Some(now);
    // Bump updated_at so LWW merge arbitration sees the delete as the newest
    // change ("deleted_at >= remote.updated_at → delete wins").
    entry.updated_at = now;

    // Single transaction: tombstone write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_entry_in_txn(txn, key, &entry)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(true)
}

pub fn get_entry_count(state: &Arc<AppState>) -> Result<usize, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;

    // Soft delete (P2.2): count live entries only, decrypting each row (the
    // raw table length would report tombstones the user can no longer see —
    // review P2 fix for the extension count).
    let count = list_all_entries_bulk(&db, key, None)?
        .iter()
        .filter(|entry| entry.deleted_at.is_none())
        .count();

    lease.touch_remote_activity();

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{change_password, create_entry, totp_code};
    use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
    use pwdvault_infrastructure::database::Settings;
    use pwdvault_infrastructure::totp::{self, TotpAlgorithm};
    use tempfile::TempDir;

    const TEST_PASSWORD: &str = "entry-test-password";
    const SAMPLE_TOTP: &str = "JBSWY3DPEHPK3PXP";

    /// Same shape as the backup.rs fixture: unlocked in-memory AppState.
    fn unlocked_state() -> (Arc<AppState>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(database::init_database(dir.path().join("entries.db")).unwrap());
        let salt = [0x71; 16];
        let params = AdaptiveParams {
            m_cost: 16384,
            t_cost: 1,
            p_cost: 1,
        };
        let (master_key, _) = pwdvault_infrastructure::crypto::kdf::derive_key_with_params(
            TEST_PASSWORD,
            &salt,
            &params,
        )
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
                    &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
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
        (state, dir)
    }

    fn create_test_entry(state: &Arc<AppState>, title: &str) -> EntrySummary {
        create_entry(
            state,
            CreateEntryRequest {
                title: title.to_string(),
                url: None,
                username: "user".to_string(),
                password: Zeroizing::new("secret".to_string()),
                notes: None,
                tags: vec![],
                group_id: None,
            },
        )
        .unwrap()
    }

    fn patch(totp_secret: Option<String>) -> UpdateEntryRequest {
        UpdateEntryRequest {
            title: "Patched".to_string(),
            url: None,
            username: "user".to_string(),
            password: None,
            notes: None,
            update_notes: false,
            tags: vec![],
            group_id: None,
            totp_secret,
        }
    }

    /// P3.6 item 1: after a soft delete the service layer hides the entry
    /// (list / get 404 / count / update 404) while the infra layer keeps the
    /// tombstone row raw for reseal and future merge.
    #[test]
    fn soft_deleted_entry_hidden_from_service_and_raw_in_infra() {
        let (state, _dir) = unlocked_state();
        let keep = create_test_entry(&state, "Keep");
        let gone = create_test_entry(&state, "Delete me");

        assert!(remove_entry(&state, gone.id.clone()).unwrap());

        // List filters the tombstone.
        let summaries = list_all_entries(&state).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].id, keep.id);

        // get_entry_meta 404s.
        assert!(matches!(
            get_entry_meta(&state, gone.id.clone()),
            Err(VaultError::EntryNotFound)
        ));

        // get_entry_secret 404s too — the tombstone must not give up its
        // decrypted secrets (P2-1: the NM secret-fetch path).
        assert!(matches!(
            get_entry_secret(&state, gone.id.clone()),
            Err(VaultError::EntryNotFound)
        ));

        // update on a deleted entry 404s (no resurrection).
        assert!(matches!(
            update_entry(&state, gone.id.clone(), patch(None)),
            Err(VaultError::EntryNotFound)
        ));

        // Live-only count.
        assert_eq!(get_entry_count(&state).unwrap(), 1);

        // Infra stays raw: the tombstone row survives and decrypts.
        let db = get_db(&state).unwrap();
        let raw = list_all_entries_bulk(&db, &state.session.get_enc_key().unwrap(), None).unwrap();
        assert_eq!(raw.len(), 2);
        let tombstone = raw.iter().find(|entry| entry.id == gone.id).unwrap();
        assert!(tombstone.deleted_at.is_some());
        assert_eq!(tombstone.title, "Delete me");

        // Re-removing an already-deleted entry still reports success.
        assert!(remove_entry(&state, gone.id.clone()).unwrap());
    }

    /// P2-1: the extension's secret-fetch path refuses a soft-deleted entry
    /// (404 like the meta path) — the tombstone row stays on disk for
    /// merge/reseal but never hands out decrypted secrets.
    #[test]
    fn get_entry_secret_hidden_after_soft_delete() {
        let (state, _dir) = unlocked_state();
        let entry = create_test_entry(&state, "Secret after delete");

        // Sanity: the secret is readable while the entry is live.
        let secret = get_entry_secret(&state, entry.id.clone()).unwrap();
        assert_eq!(*secret.password, "secret");

        assert!(remove_entry(&state, entry.id.clone()).unwrap());
        assert!(matches!(
            get_entry_secret(&state, entry.id.clone()),
            Err(VaultError::EntryNotFound)
        ));
    }

    /// P3.6 item 1: update_entry's totp set / leave-untouched / clear paths.
    #[test]
    fn update_entry_sets_clears_and_keeps_totp_secret() {
        let (state, _dir) = unlocked_state();
        let entry = create_test_entry(&state, "TOTP");

        // Set (None before → the tri-state must install the secret).
        update_entry(
            &state,
            entry.id.clone(),
            patch(Some(SAMPLE_TOTP.to_string())),
        )
        .unwrap();
        let response = totp_code(&state, entry.id.clone()).unwrap();
        assert_eq!(response.code.len(), 6);
        assert!(response.code.chars().all(|c| c.is_ascii_digit()));
        assert!((1..=30).contains(&response.seconds_remaining));
        // Deterministic value: matches a local code for the current or next
        // second (tolerates one tick between the two calls).
        let secret_bytes = totp::base32_decode(SAMPLE_TOTP).unwrap();
        let now = chrono::Utc::now().timestamp();
        let expected = [
            totp::totp_code(&secret_bytes, TotpAlgorithm::Sha1, 6, 30, now),
            totp::totp_code(&secret_bytes, TotpAlgorithm::Sha1, 6, 30, now + 1),
        ];
        assert!(expected.contains(&response.code));

        // None = leave unchanged (secret survives a metadata-only patch).
        update_entry(&state, entry.id.clone(), patch(None)).unwrap();
        assert!(totp_code(&state, entry.id.clone()).is_ok());

        // Some("") = clear.
        update_entry(&state, entry.id.clone(), patch(Some(String::new()))).unwrap();
        assert!(matches!(
            totp_code(&state, entry.id.clone()),
            Err(VaultError::InvalidInput { .. })
        ));
    }

    /// totp_code fails closed for unknown, unconfigured, and deleted entries.
    #[test]
    fn totp_code_rejects_missing_unconfigured_and_deleted() {
        let (state, _dir) = unlocked_state();
        let entry = create_test_entry(&state, "No TOTP");

        assert!(matches!(
            totp_code(&state, "missing-id".to_string()),
            Err(VaultError::EntryNotFound)
        ));
        assert!(matches!(
            totp_code(&state, entry.id.clone()),
            Err(VaultError::InvalidInput { .. })
        ));

        update_entry(
            &state,
            entry.id.clone(),
            patch(Some(SAMPLE_TOTP.to_string())),
        )
        .unwrap();
        assert!(remove_entry(&state, entry.id.clone()).unwrap());
        assert!(matches!(
            totp_code(&state, entry.id.clone()),
            Err(VaultError::EntryNotFound)
        ));
    }

    /// Over-length totp_secret is rejected by the domain validation policy.
    #[test]
    fn totp_secret_over_length_rejected() {
        let (state, _dir) = unlocked_state();
        let entry = create_test_entry(&state, "Long TOTP");
        let long = "A".repeat(pwdvault_domain::MAX_TOTP_SECRET_LENGTH + 1);
        assert!(matches!(
            update_entry(&state, entry.id.clone(), patch(Some(long))),
            Err(VaultError::InvalidInput { .. })
        ));
    }

    /// P3.6 item 7 (reseal inheritance): change_password re-encrypts the
    /// inner totp blob, so codes keep working under the new keys.
    #[test]
    fn change_password_reseals_totp_secret() {
        let (state, _dir) = unlocked_state();
        let entry = create_test_entry(&state, "Reseal");
        update_entry(
            &state,
            entry.id.clone(),
            patch(Some(SAMPLE_TOTP.to_string())),
        )
        .unwrap();

        change_password(
            &state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Zeroizing::new("brand-new-password".to_string()),
            None,
        )
        .unwrap();

        let response = totp_code(&state, entry.id.clone()).unwrap();
        assert_eq!(response.code.len(), 6);
    }

    // -------------------------------------------------------------------
    // v1.4.0: last_used_at restore + 60s throttle
    // -------------------------------------------------------------------

    fn raw_row(state: &Arc<AppState>, id: &str) -> PasswordEntry {
        let db = get_db(state).unwrap();
        load_entry(&db, &state.session.get_enc_key().unwrap(), id, false)
            .unwrap()
            .expect("row exists")
    }

    /// The restored persistence: a fetch stamps last_used_at on disk WITHOUT
    /// touching updated_at (device-local metadata, never a sync-relevant
    /// edit), and a second fetch inside the 60s throttle window does not
    /// write again.
    #[test]
    fn get_entry_secret_throttles_last_used_at_writes() {
        let (state, _dir) = unlocked_state();
        let entry = create_test_entry(&state, "Throttled");
        let updated_at_before = raw_row(&state, &entry.id).updated_at;

        let first = get_entry_secret(&state, entry.id.clone()).unwrap();
        let stamped = first.last_used_at.expect("first fetch stamps a value");
        let row = raw_row(&state, &entry.id);
        assert_eq!(row.last_used_at, Some(stamped), "bump persisted");
        assert_eq!(
            row.updated_at, updated_at_before,
            "the bump must not move updated_at (sync-invisible)"
        );

        // Cross a full second: a second-granularity re-bump would be
        // observable as stamped+1.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let second = get_entry_secret(&state, entry.id.clone()).unwrap();
        assert_eq!(
            second.last_used_at,
            Some(stamped),
            "fetch within the 60s throttle window must not re-bump"
        );
        assert_eq!(raw_row(&state, &entry.id).last_used_at, Some(stamped));
    }

    // -------------------------------------------------------------------
    // v1.4.0: trash (list / restore / purge / empty) + purge ledger
    // -------------------------------------------------------------------

    /// Re-insert a row directly through the infra layer — the stand-in for
    /// "the sync cycle wrote back a remote copy" (write_merged_back upserts
    /// rows verbatim, so a raw save is an exact simulation).
    fn reinsert_row(state: &Arc<AppState>, entry: &PasswordEntry) {
        let db = get_db(state).unwrap();
        let key = state.session.get_enc_key().unwrap();
        let mac_key = state.session.get_mac_key().unwrap();
        vault_store::VaultStore::new(&db)
            .write(&mac_key, |txn| {
                vault_store::save_entry_in_txn(txn, &key, entry)?;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn deleted_entries_are_listed_in_trash_only() {
        let (state, _dir) = unlocked_state();
        let keep = create_test_entry(&state, "Keep");
        let gone = create_test_entry(&state, "Gone");
        remove_entry(&state, gone.id.clone()).unwrap();

        let trash = list_deleted_entries(&state).unwrap();
        assert_eq!(trash.len(), 1);
        assert_eq!(trash[0].id, gone.id);
        assert!(trash[0].deleted_at.is_some(), "trash rows carry deleted_at");

        let live = list_all_entries(&state).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, keep.id);
        assert!(live[0].deleted_at.is_none());
    }

    #[test]
    fn restore_entry_revives_with_updated_at_bump() {
        let (state, _dir) = unlocked_state();
        let entry = create_test_entry(&state, "Restore me");
        remove_entry(&state, entry.id.clone()).unwrap();
        let tombstoned_updated_at = raw_row(&state, &entry.id).updated_at;

        std::thread::sleep(std::time::Duration::from_millis(1100));
        let restored = restore_entry(&state, entry.id.clone()).unwrap();
        assert!(restored.deleted_at.is_none());
        // REQUIRED for LWW survival: the restore must present itself as the
        // newest change, otherwise a remote tombstone with
        // deleted_at >= restored.updated_at would delete it again at the
        // next sync.
        assert!(
            restored.updated_at > tombstoned_updated_at,
            "restore bumps updated_at: {} -> {}",
            tombstoned_updated_at,
            restored.updated_at
        );
        // The restored entry is the vault's only entry — and it is live again.
        assert_eq!(list_all_entries(&state).unwrap().len(), 1);
        assert!(list_deleted_entries(&state).unwrap().is_empty());

        // Restoring a live entry is a caller error, not a no-op.
        assert!(matches!(
            restore_entry(&state, entry.id.clone()),
            Err(VaultError::InvalidInput { .. })
        ));
    }

    /// THE purge-reflow test: a physically deleted row whose tombstone comes
    /// back from the remote container must stay invisible (trash AND live
    /// list), while the ledger record suppresses exactly that tombstone.
    #[test]
    fn purged_entry_stays_hidden_when_remote_tombstone_reflows() {
        let (state, _dir) = unlocked_state();
        let entry = create_test_entry(&state, "Purge + reflow");
        remove_entry(&state, entry.id.clone()).unwrap();
        let tombstone = raw_row(&state, &entry.id);
        assert!(tombstone.deleted_at.is_some());

        assert!(purge_entry(&state, entry.id.clone()).unwrap());
        // Row is physically gone; the id is on the ledger.
        assert!(load_entry(
            &get_db(&state).unwrap(),
            &state.session.get_enc_key().unwrap(),
            &entry.id,
            false
        )
        .unwrap()
        .is_none());

        // Remote tombstone reflows on the next sync (merge rule 1: single
        // side present → adopted as-is; write_merged_back upserts it).
        reinsert_row(&state, &tombstone);

        assert!(list_all_entries(&state).unwrap().is_empty());
        assert!(
            list_deleted_entries(&state).unwrap().is_empty(),
            "reflowed tombstone must not refill the trash"
        );
    }

    /// The other direction: a purged id that comes back LIVE (merge revival
    /// / import) must be served AND its ledger record dropped — otherwise
    /// every later tombstone would be silently swallowed forever.
    #[test]
    fn purged_id_returning_as_live_row_is_served_and_cleared_from_ledger() {
        let (state, _dir) = unlocked_state();
        let entry = create_test_entry(&state, "Purge + revive");
        remove_entry(&state, entry.id.clone()).unwrap();
        let tombstone = raw_row(&state, &entry.id);
        assert!(purge_entry(&state, entry.id.clone()).unwrap());

        // Remote-side edit beats the old tombstone (merge revival rule):
        // the revived row comes back live with a bumped updated_at.
        let mut revived = tombstone.clone();
        revived.deleted_at = None;
        revived.updated_at = tombstone.updated_at + 3_600;
        reinsert_row(&state, &revived);

        // list_all_entries both serves the row and reconciles the ledger.
        let live = list_all_entries(&state).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].id, entry.id);

        let db = get_db(&state).unwrap();
        assert!(
            !vault_store::purged_entry_ids(&db)
                .unwrap()
                .contains(&entry.id),
            "the ledger record for the revived id must be dropped"
        );

        // And a LATER tombstone of the same id shows up in the trash again.
        remove_entry(&state, entry.id.clone()).unwrap();
        let trash = list_deleted_entries(&state).unwrap();
        assert_eq!(trash.len(), 1);
        assert_eq!(trash[0].id, entry.id);
    }

    #[test]
    fn purge_is_idempotent_and_refuses_live_rows() {
        let (state, _dir) = unlocked_state();
        let entry = create_test_entry(&state, "Idempotent purge");

        // A LIVE entry cannot be purged through the trash path.
        assert!(matches!(
            purge_entry(&state, entry.id.clone()),
            Err(VaultError::InvalidInput { .. })
        ));

        remove_entry(&state, entry.id.clone()).unwrap();
        assert!(purge_entry(&state, entry.id.clone()).unwrap());
        // Already purged → idempotent success-shaped no-op.
        assert!(!purge_entry(&state, entry.id.clone()).unwrap());
        // A never-seen id is a caller bug.
        assert!(matches!(
            purge_entry(&state, "missing-entry-id".to_string()),
            Err(VaultError::EntryNotFound)
        ));
    }

    #[test]
    fn empty_trash_removes_all_tombstones_including_ledger_suppressed() {
        let (state, _dir) = unlocked_state();
        let a = create_test_entry(&state, "Trash A");
        let b = create_test_entry(&state, "Trash B");
        let live = create_test_entry(&state, "Live");
        remove_entry(&state, a.id.clone()).unwrap();
        remove_entry(&state, b.id.clone()).unwrap();
        // A reflowed tombstone whose id is already ledgered: empty_trash
        // must still remove the ROW (otherwise it lingers forever) and keep
        // the ledger record.
        remove_entry(&state, a.id.clone()).unwrap(); // no-op tombstone refresh
        let a_row = raw_row(&state, &a.id);
        assert!(purge_entry(&state, a.id.clone()).unwrap());
        reinsert_row(&state, &a_row); // sync refill of the purged tombstone
                                      // The refilled 'a' stays hidden (ledgered); 'b' remains visible.
        let trash_before = list_deleted_entries(&state).unwrap();
        assert_eq!(trash_before.len(), 1);
        assert_eq!(trash_before[0].id, b.id);

        let removed = empty_trash(&state).unwrap();
        assert_eq!(removed, 2, "both tombstone rows are removed");

        assert!(list_all_entries(&state).unwrap().len() == 1);
        assert_eq!(list_all_entries(&state).unwrap()[0].id, live.id);
        assert!(list_deleted_entries(&state).unwrap().is_empty());

        // Ledger still holds both ids (refilled tombstones stay hidden).
        let db = get_db(&state).unwrap();
        let ledger = vault_store::purged_entry_ids(&db);
        assert!(ledger.as_ref().unwrap().contains(&a.id));
        assert!(ledger.as_ref().unwrap().contains(&b.id));

        // Emptying an already-empty trash is a 0.
        assert_eq!(empty_trash(&state).unwrap(), 0);
    }
}
