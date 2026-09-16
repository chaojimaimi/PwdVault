use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use crate::service::vault::get_db;
use crate::{
    validation, AppState, CreateEntryRequest, EntrySecretResponse, EntrySummary,
    UpdateEntryRequest, VaultError,
};
use pwdvault_infrastructure::crypto::{decrypt, encrypt, EncryptedData};
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
    let encrypted_password_bytes = bincode::serialize(&encrypted_password)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

    let encrypted_notes = if let Some(notes) = &request.notes {
        let encrypted = encrypt(key, notes.as_bytes())?;
        let bytes = bincode::serialize(&encrypted)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
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

    lease.touch_activity();

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

    lease.touch_activity();

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
    let entry = load_entry(&db, key, &id, false)?.ok_or(VaultError::EntryNotFound)?;

    // Decrypt password. Try bincode format first (v1.0.5+ and v1.0.4 both use
    // bincode::serialize(EncryptedData)), then fall back to raw bytes
    // (nonce||ciphertext) just in case an older build used to_bytes().
    let encrypted_password: EncryptedData = bincode::deserialize(&entry.encrypted_password)
        .or_else(|e| {
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
        let encrypted: EncryptedData =
            bincode::deserialize(encrypted_notes_bytes).or_else(|e| {
                EncryptedData::from_bytes(encrypted_notes_bytes).map_err(|e2| {
                    VaultError::DecryptionFailed(format!("bincode: {} / raw: {}", e, e2))
                })
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

    // §5.1.2: Removed last_used_at persistence side-effect.
    // The frontend does not use this field, and persisting it caused
    // write amplification (entry re-seal + full digest refresh) on every
    // secret read. last_used_at is now only returned from the in-memory
    // entry without being written back.

    lease.touch_activity();

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
    // it); the service layer filters tombstones out here.
    let entries = list_all_entries_bulk(&db, key, None)?
        .into_iter()
        .filter(|entry| entry.deleted_at.is_none())
        .collect::<Vec<_>>();
    let summaries: Vec<EntrySummary> = entries.into_iter().map(Into::into).collect();

    lease.touch_activity();

    Ok(summaries)
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
        entry.encrypted_password = bincode::serialize(&encrypted_password)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
    }

    // Encrypt and update notes
    if request.update_notes {
        entry.encrypted_notes = if let Some(notes) = &request.notes {
            let encrypted = encrypt(key, notes.as_bytes())?;
            Some(
                bincode::serialize(&encrypted)
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
                bincode::serialize(&encrypted)
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

    lease.touch_activity();

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

    lease.touch_activity();

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

    lease.touch_activity();

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
        let db = Arc::new(
            database::init_database(dir.path().join("entries.db")).unwrap(),
        );
        let salt = [0x71; 16];
        let params = AdaptiveParams {
            m_cost: 16384,
            t_cost: 1,
            p_cost: 1,
        };
        let (master_key, _) =
            pwdvault_infrastructure::crypto::kdf::derive_key_with_params(
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

        // update on a deleted entry 404s (no resurrection).
        assert!(matches!(
            update_entry(&state, gone.id.clone(), patch(None)),
            Err(VaultError::EntryNotFound)
        ));

        // Live-only count.
        assert_eq!(get_entry_count(&state).unwrap(), 1);

        // Infra stays raw: the tombstone row survives and decrypts.
        let db = get_db(&state).unwrap();
        let raw =
        list_all_entries_bulk(&db, &state.session.get_enc_key().unwrap(), None).unwrap();
        assert_eq!(raw.len(), 2);
        let tombstone = raw.iter().find(|entry| entry.id == gone.id).unwrap();
        assert!(tombstone.deleted_at.is_some());
        assert_eq!(tombstone.title, "Delete me");

        // Re-removing an already-deleted entry still reports success.
        assert!(remove_entry(&state, gone.id.clone()).unwrap());
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
}
