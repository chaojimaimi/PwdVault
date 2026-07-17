use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use pwdvault_infrastructure::crypto::{decrypt, encrypt, EncryptedData};
use pwdvault_infrastructure::database;
use pwdvault_infrastructure::database::{count_entries, list_all_entries_bulk, load_entry, vault_store, PasswordEntry};
use crate::service::vault::get_db;
use crate::{
    validation, AppState, CreateEntryRequest, EntrySecretResponse, EntrySummary,
    UpdateEntryRequest, VaultError,
};

pub fn create_entry(
    state: &Arc<AppState>,
    request: CreateEntryRequest,
) -> Result<EntrySummary, VaultError> {
    let lease = state.lease()?;
    validation::entry(&request)?;

    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;
    if let Some(group_id) = &request.group_id {
        if database::load_group(&db, key, group_id)?.is_none() {
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
    let entry = load_entry(&db, key, &id)?.ok_or(VaultError::EntryNotFound)?;

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
    let entry = load_entry(&db, key, &id)?.ok_or(VaultError::EntryNotFound)?;

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
    let entries = list_all_entries_bulk(&db, key, None)?;
    let summaries: Vec<EntrySummary> = entries.into_iter().map(Into::into).collect();

    lease.touch_activity();

    Ok(summaries)
}

pub fn update_entry<R: Into<UpdateEntryRequest>>(
    state: &Arc<AppState>,
    id: String,
    request: R,
) -> Result<EntrySummary, VaultError> {
    let request = request.into();
    let lease = state.lease()?;
    validation::id(&id)?;
    validation::entry_update(&request)?;

    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;
    if let Some(group_id) = &request.group_id {
        if database::load_group(&db, key, group_id)?.is_none() {
            return Err(VaultError::InvalidInput {
                code: "UNKNOWN_GROUP".into(),
                message: "Group does not exist".into(),
            });
        }
    }

    let mut entry = load_entry(&db, key, &id)?.ok_or(VaultError::EntryNotFound)?;

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
    let mac_key = lease.mac_key()?;

    // Single transaction: delete + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    let existed = store.write(mac_key, |txn| {
        let existed = vault_store::delete_entry_in_txn(txn, &id)?;
        Ok(existed)
    })?;

    lease.touch_activity();

    Ok(existed)
}

pub fn get_entry_count(state: &Arc<AppState>) -> Result<usize, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let count = count_entries(&db)?;

    lease.touch_activity();

    Ok(count)
}
