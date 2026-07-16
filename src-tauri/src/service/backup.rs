use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use base64::Engine;

use crate::crypto::{self, decrypt, encrypt, EncryptedData};
use crate::database::{
    self, list_entries, list_groups, load_entry, load_group, load_settings, Group, PasswordEntry,
};
use crate::service::vault::{get_db, get_mac_key};
use crate::{AppState, BackupPayload, ExportEntry, ImportResult, VaultBackup, VaultError};

pub fn export_vault(
    state: &Arc<AppState>,
    export_password: Zeroizing<String>,
) -> Result<VaultBackup, VaultError> {
    if !state.keystore.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.keystore.get_key()?;

    // Load all entries and decrypt passwords/notes
    let entry_ids = list_entries(&db)?;
    let mut export_entries = Vec::new();
    for id in entry_ids {
        if let Some(entry) = load_entry(&db, &key, &id)? {
            // Decrypt password
            let enc_pwd: EncryptedData = bincode::deserialize(&entry.encrypted_password)
                .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
            let pwd_bytes = decrypt(&key, &enc_pwd)?;
            let password = String::from_utf8(pwd_bytes)
                .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;

            // Decrypt notes
            let notes = if let Some(ref enc_notes_bytes) = entry.encrypted_notes {
                let enc: EncryptedData = bincode::deserialize(enc_notes_bytes)
                    .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
                let notes_bytes = decrypt(&key, &enc)?;
                Some(
                    String::from_utf8(notes_bytes)
                        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?,
                )
            } else {
                None
            };

            export_entries.push(ExportEntry {
                id: entry.id,
                title: entry.title,
                url: entry.url,
                username: entry.username,
                password: Zeroizing::new(password),
                notes: notes.map(Zeroizing::new),
                tags: entry.tags,
                group_id: entry.group_id,
                created_at: entry.created_at,
                updated_at: entry.updated_at,
            });
        }
    }

    // Load groups
    let group_ids = list_groups(&db)?;
    let mut groups = Vec::new();
    for id in group_ids {
        if let Some(g) = load_group(&db, &key, &id)? {
            groups.push(g);
        }
    }

    // Load settings
    let settings = load_settings(&db)?;

    // Build plaintext payload
    let payload = BackupPayload {
        entries: export_entries,
        groups,
        settings,
    };

    let mut payload_json =
        serde_json::to_vec(&payload).map_err(|e| VaultError::InternalError(e.to_string()))?;

    // Derive export key from export password using Argon2id
    let salt = crypto::kdf::generate_salt();
    let (mut export_key, params) = crypto::kdf::derive_key(export_password.as_str(), &salt)?;

    // `export_password` is Zeroizing<String>; wiped on drop here.

    // Encrypt payload with export key
    let encrypted = encrypt(&export_key, &payload_json)?;

    // Zeroize the export key and plaintext payload now that encryption is done.
    export_key.zeroize();
    // ExportEntry uses Zeroizing<String> so sensitive strings are cleared
    // automatically when the Vec is dropped.
    payload_json.zeroize();

    let b64 = base64::engine::general_purpose::STANDARD;

    Ok(VaultBackup {
        version: 1,
        created_at: chrono::Utc::now().timestamp(),
        salt: b64.encode(&salt),
        kdf_memory: params.m_cost,
        kdf_iterations: params.t_cost,
        kdf_parallelism: params.p_cost,
        nonce: b64.encode(&encrypted.nonce),
        data: b64.encode(&encrypted.ciphertext),
    })
}

pub fn import_vault(
    state: &Arc<AppState>,
    backup: VaultBackup,
    import_password: Zeroizing<String>,
) -> Result<ImportResult, VaultError> {
    if !state.keystore.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    if backup.version != 1 {
        return Err(VaultError::InvalidBackup(
            "Unsupported backup version".to_string(),
        ));
    }

    // Decode salt and nonce from base64
    let b64 = base64::engine::general_purpose::STANDARD;

    let salt = b64
        .decode(&backup.salt)
        .map_err(|e| VaultError::InvalidBackup(format!("Invalid salt: {}", e)))?;
    let nonce_bytes = b64
        .decode(&backup.nonce)
        .map_err(|e| VaultError::InvalidBackup(format!("Invalid nonce: {}", e)))?;
    let ciphertext = b64
        .decode(&backup.data)
        .map_err(|e| VaultError::InvalidBackup(format!("Invalid data: {}", e)))?;

    if salt.len() != 16 {
        return Err(VaultError::InvalidBackup("Invalid salt length".to_string()));
    }

    // Derive key from import password with stored KDF params
    let salt_array: [u8; 16] = salt
        .try_into()
        .map_err(|_| VaultError::InvalidBackup("Invalid salt".to_string()))?;
    let (mut import_key, _params) = crypto::kdf::derive_key_with_params(
        import_password.as_str(),
        &salt_array,
        &crypto::kdf::AdaptiveParams {
            m_cost: backup.kdf_memory,
            t_cost: backup.kdf_iterations,
            p_cost: backup.kdf_parallelism,
        },
    )?;

    // `import_password` is Zeroizing<String>; wiped on drop here.

    // Decrypt payload
    let encrypted_data = EncryptedData {
        nonce: nonce_bytes,
        ciphertext,
    };
    let mut payload_bytes =
        decrypt(&import_key, &encrypted_data).map_err(|_| VaultError::InvalidPassword)?;

    // Zeroize the import key now that decryption is done.
    import_key.zeroize();

    // Parse payload — validate before any destructive operations
    let payload: BackupPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VaultError::InvalidBackup(format!("Invalid payload: {}", e)))?;

    // Zeroize decrypted payload bytes
    payload_bytes.zeroize();

    let db = get_db(state)?;
    let key = state.keystore.get_key()?;

    // Pre-validate and prepare groups (generate new IDs to avoid conflicts)
    let mut group_id_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut new_groups = Vec::new();
    for g in &payload.groups {
        let new_group = Group::new(g.name.clone());
        group_id_map.insert(g.id.clone(), new_group.id.clone());
        new_groups.push(new_group);
    }

    // Pre-validate and encrypt all entries before any destructive operations
    let mut new_entries = Vec::new();
    for export_entry in &payload.entries {
        let mut entry = PasswordEntry::new(
            export_entry.title.clone(),
            export_entry.url.clone(),
            export_entry.username.clone(),
        );

        // Encrypt password with current master key
        let enc_pwd = encrypt(&key, export_entry.password.as_bytes())?;
        entry.encrypted_password = bincode::serialize(&enc_pwd)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        // Encrypt notes
        entry.encrypted_notes = if let Some(ref notes) = export_entry.notes {
            let enc = encrypt(&key, notes.as_bytes())?;
            Some(
                bincode::serialize(&enc)
                    .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?,
            )
        } else {
            None
        };

        entry.tags = export_entry.tags.clone();
        // Map old group_id to new group_id
        entry.group_id = export_entry
            .group_id
            .as_ref()
            .and_then(|gid| group_id_map.get(gid).cloned());
        entry.created_at = export_entry.created_at;
        entry.updated_at = export_entry.updated_at;

        new_entries.push(entry);
    }

    // All validation and encryption succeeded — now perform database mutations
    // atomically. Pre-seal (encrypt) all records BEFORE opening the write
    // transaction so that a seal failure rolls back cleanly without leaving
    // the database half-cleared. The entire clear+insert cycle runs in ONE
    // redb write transaction: if any operation fails, the transaction is
    // aborted and the vault remains untouched.
    let mut sealed_groups: Vec<(String, Vec<u8>)> = Vec::with_capacity(new_groups.len());
    for g in &new_groups {
        let blob = database::group_codec::seal_group(g, &key)?;
        sealed_groups.push((g.id.clone(), blob));
    }
    let mut sealed_entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(new_entries.len());
    for entry in &new_entries {
        let blob = database::entry_codec::seal_entry(entry, &key)?;
        sealed_entries.push((entry.id.clone(), blob));
    }
    let settings_bytes = serde_json::to_vec(&payload.settings)
        .map_err(|e| VaultError::InternalError(e.to_string()))?;

    // Collect existing IDs via a read transaction before the write.
    let existing_entry_ids = list_entries(&db)?;
    let existing_group_ids = list_groups(&db)?;

    // Apply all mutations in a single write transaction. Wrapped in an
    // inner closure returning DatabaseError so the redb error types
    // (TableError, StorageError, CommitError) convert via the existing
    // From impls on DatabaseError; the outer ? then lifts DatabaseError
    // into VaultError.
    let apply_txn = || -> Result<(), database::DatabaseError> {
        let txn = db.begin_write()?;
        {
            let mut t = txn.open_table(database::ENTRIES_TABLE)?;
            for id in &existing_entry_ids {
                t.remove(id.as_str())?;
            }
            for (id, blob) in &sealed_entries {
                t.insert(id.as_str(), blob.as_slice())?;
            }
        }
        {
            let mut t = txn.open_table(database::GROUPS_TABLE)?;
            for id in &existing_group_ids {
                t.remove(id.as_str())?;
            }
            for (id, blob) in &sealed_groups {
                t.insert(id.as_str(), blob.as_slice())?;
            }
        }
        {
            let mut t = txn.open_table(database::SETTINGS_TABLE)?;
            t.insert("current", settings_bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    };
    apply_txn()?;

    *state.auto_lock_secs.lock().expect("timeout lock poisoned") = payload.settings.auto_lock_secs;

    let mac_key = get_mac_key(state)?;
    database::integrity::refresh_digest(&db, &mac_key)?;

    let entries_count = payload.entries.len();
    let groups_count = payload.groups.len();

    state.touch_activity();
    Ok(ImportResult {
        entries_imported: entries_count,
        groups_imported: groups_count,
    })
}
