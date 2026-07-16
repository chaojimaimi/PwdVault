use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{decrypt, encrypt, EncryptedData};
use crate::database::{count_entries, list_entries, load_entry, vault_store, PasswordEntry};
use crate::service::vault::{get_db, get_mac_key};
use crate::{
    constants, AppState, CreateEntryRequest, EntrySecretResponse, EntrySummary, VaultError,
};

fn validate_entry_request(req: &CreateEntryRequest) -> Result<(), VaultError> {
    if req.title.is_empty() || req.title.len() > constants::MAX_FIELD_LENGTH {
        return Err(VaultError::InternalError(
            "Invalid title length".to_string(),
        ));
    }
    if req.username.is_empty() || req.username.len() > constants::MAX_FIELD_LENGTH {
        return Err(VaultError::InternalError(
            "Invalid username length".to_string(),
        ));
    }
    if req.password.len() > constants::MAX_PASSWORD_LENGTH {
        return Err(VaultError::InternalError(
            "Invalid password length".to_string(),
        ));
    }
    if req
        .notes
        .as_ref()
        .map_or(false, |n| n.len() > constants::MAX_NOTES_LENGTH)
    {
        return Err(VaultError::InternalError("Notes too long".to_string()));
    }
    if req
        .url
        .as_ref()
        .map_or(false, |u| u.len() > constants::MAX_FIELD_LENGTH)
    {
        return Err(VaultError::InternalError("Invalid URL length".to_string()));
    }
    Ok(())
}

pub fn create_entry(
    state: &Arc<AppState>,
    request: CreateEntryRequest,
) -> Result<EntrySummary, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    validate_entry_request(&request)?;

    let db = get_db(state)?;
    let key = state.session.get_enc_key()?;
    let mac_key = get_mac_key(state)?;

    // Encrypt password and notes BEFORE opening the write transaction,
    // so crypto failures roll back cleanly without holding the write lock.
    let encrypted_password = encrypt(&key, request.password.as_bytes())?;
    let encrypted_password_bytes = bincode::serialize(&encrypted_password)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

    let encrypted_notes = if let Some(notes) = &request.notes {
        let encrypted = encrypt(&key, notes.as_bytes())?;
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
    store.write(&mac_key, |txn| {
        vault_store::save_entry_in_txn(txn, &key, &entry)?;
        Ok(())
    })?;

    state.touch_activity();

    Ok(entry.into())
}

pub fn get_entry_meta(state: &Arc<AppState>, id: String) -> Result<EntrySummary, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.session.get_enc_key()?;
    let entry = load_entry(&db, &key, &id)?.ok_or(VaultError::EntryNotFound)?;

    state.touch_activity();

    Ok(entry.into())
}

pub fn get_entry_secret(
    state: &Arc<AppState>,
    id: String,
) -> Result<EntrySecretResponse, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.session.get_enc_key()?;
    let entry = load_entry(&db, &key, &id)?.ok_or(VaultError::EntryNotFound)?;

    // Decrypt password. Try bincode format first (v1.0.5+ and v1.0.4 both use
    // bincode::serialize(EncryptedData)), then fall back to raw bytes
    // (nonce||ciphertext) just in case an older build used to_bytes().
    let encrypted_password: EncryptedData = bincode::deserialize(&entry.encrypted_password)
        .or_else(|e| {
            EncryptedData::from_bytes(&entry.encrypted_password)
                .map_err(|e2| VaultError::DecryptionFailed(format!("bincode: {} / raw: {}", e, e2)))
        })?;
    let mut password_bytes = decrypt(&key, &encrypted_password)?;
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
        let mut notes_bytes = decrypt(&key, &encrypted)?;
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

    state.touch_activity();

    Ok(EntrySecretResponse {
        password,
        notes,
        last_used_at: entry.last_used_at,
    })
}

pub fn list_all_entries(state: &Arc<AppState>) -> Result<Vec<EntrySummary>, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.session.get_enc_key()?;
    let ids = list_entries(&db)?;
    let mut summaries = Vec::new();

    for id in ids {
        if let Some(entry) = load_entry(&db, &key, &id)? {
            summaries.push(entry.into());
        }
    }

    state.touch_activity();

    Ok(summaries)
}

pub fn update_entry(
    state: &Arc<AppState>,
    id: String,
    request: CreateEntryRequest,
) -> Result<EntrySummary, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    validate_entry_request(&request)?;

    let db = get_db(state)?;
    let key = state.session.get_enc_key()?;
    let mac_key = get_mac_key(state)?;

    let mut entry = load_entry(&db, &key, &id)?.ok_or(VaultError::EntryNotFound)?;

    // Update fields
    entry.title = request.title;
    entry.url = request.url;
    entry.username = request.username;
    entry.tags = request.tags;
    entry.group_id = request.group_id;
    entry.updated_at = chrono::Utc::now().timestamp();

    // Encrypt and update password
    let encrypted_password = encrypt(&key, request.password.as_bytes())?;
    entry.encrypted_password = bincode::serialize(&encrypted_password)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

    // Encrypt and update notes
    entry.encrypted_notes = if let Some(notes) = &request.notes {
        let encrypted = encrypt(&key, notes.as_bytes())?;
        Some(
            bincode::serialize(&encrypted)
                .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?,
        )
    } else {
        None
    };

    // Single transaction: business write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(&mac_key, |txn| {
        vault_store::save_entry_in_txn(txn, &key, &entry)?;
        Ok(())
    })?;

    state.touch_activity();

    Ok(entry.into())
}

pub fn remove_entry(state: &Arc<AppState>, id: String) -> Result<bool, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let mac_key = get_mac_key(state)?;

    // Single transaction: delete + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    let existed = store.write(&mac_key, |txn| {
        let existed = vault_store::delete_entry_in_txn(txn, &id)?;
        Ok(existed)
    })?;

    state.touch_activity();

    Ok(existed)
}

pub fn get_entry_count(state: &Arc<AppState>) -> Result<usize, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let count = count_entries(&db)?;

    state.touch_activity();

    Ok(count)
}
