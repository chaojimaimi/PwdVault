use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use base64::Engine;

use crate::service::vault::get_db;
use crate::{AppState, BackupPayload, ExportEntry, ImportResult, VaultBackup, VaultError};
use pwdvault_infrastructure::crypto::{
    self, decrypt, decrypt_with_aad, encrypt, encrypt_with_aad, EncryptedData,
};
use pwdvault_infrastructure::database::{self, load_settings, Group, PasswordEntry};

const BACKUP_VERSION_V1: u32 = 1;
const BACKUP_VERSION_V2: u32 = 2;
const BACKUP_MAGIC: &str = "PWDVAULT";
const BACKUP_KDF: &str = "argon2id";
const BACKUP_CIPHER: &str = "aes-256-gcm";

#[derive(serde::Serialize)]
struct BackupV2Aad<'a> {
    magic: &'a str,
    version: u32,
    created_at: i64,
    kdf_name: &'a str,
    cipher_name: &'a str,
    salt: &'a str,
    kdf_memory: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
}

fn backup_v2_aad(backup: &VaultBackup) -> Result<Vec<u8>, VaultError> {
    serde_json::to_vec(&BackupV2Aad {
        magic: backup.magic.as_deref().unwrap_or(""),
        version: backup.version,
        created_at: backup.created_at,
        kdf_name: backup.kdf_name.as_deref().unwrap_or(""),
        cipher_name: backup.cipher_name.as_deref().unwrap_or(""),
        salt: &backup.salt,
        kdf_memory: backup.kdf_memory,
        kdf_iterations: backup.kdf_iterations,
        kdf_parallelism: backup.kdf_parallelism,
    })
    .map_err(|error| VaultError::InvalidBackup(error.to_string()))
}

pub fn export_vault(
    state: &Arc<AppState>,
    export_password: Zeroizing<String>,
) -> Result<VaultBackup, VaultError> {
    pwdvault_domain::validation::export_password(export_password.as_str())?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;

    // Load all entries and decrypt passwords/notes.
    // Uses list_all_entries_bulk (single read txn, §5.6.2) instead of the
    // old list_entries + N×load_entry pattern.
    let entries = database::list_all_entries_bulk(&db, key, None)?;
    let mut export_entries = Vec::new();
    for entry in entries {
        // Decrypt the inner password field. Use the same resilient path as
        // get_entry_secret: try bincode(EncryptedData) first, then raw bytes,
        // to handle entries written by different historical versions.
        let password = if entry.encrypted_password.is_empty() {
            String::new()
        } else {
            let enc_pwd: EncryptedData = bincode::deserialize(&entry.encrypted_password)
                .or_else(|_| EncryptedData::from_bytes(&entry.encrypted_password))
                .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
            let mut pwd_bytes = decrypt(key, &enc_pwd)?;
            let result = String::from_utf8(pwd_bytes.clone())
                .map_err(|e| VaultError::DecryptionFailed(e.to_string()));
            pwd_bytes.zeroize();
            result?
        };

        // Decrypt notes if present.
        let notes = if let Some(ref enc_notes_bytes) = entry.encrypted_notes {
            if enc_notes_bytes.is_empty() {
                None
            } else {
                let enc: EncryptedData = bincode::deserialize(enc_notes_bytes)
                    .or_else(|_| EncryptedData::from_bytes(enc_notes_bytes))
                    .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
                let mut notes_bytes = decrypt(key, &enc)?;
                let result = String::from_utf8(notes_bytes.clone())
                    .map_err(|e| VaultError::DecryptionFailed(e.to_string()));
                notes_bytes.zeroize();
                Some(Zeroizing::new(result?))
            }
        } else {
            None
        };

        export_entries.push(ExportEntry {
            id: entry.id,
            title: entry.title,
            url: entry.url,
            username: entry.username,
            password: Zeroizing::new(password),
            notes,
            tags: entry.tags,
            group_id: entry.group_id,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        });
    }

    // Load groups via bulk scan (§5.6.2).
    let groups = database::list_all_groups_bulk(&db, key)?;

    // Load settings
    let settings = load_settings(&db)?;

    // Build plaintext payload
    let payload = BackupPayload {
        entries: export_entries,
        groups,
        settings,
    };
    pwdvault_domain::validation::backup_payload(&payload)?;

    let mut payload_json =
        serde_json::to_vec(&payload).map_err(|e| VaultError::InternalError(e.to_string()))?;
    if payload_json.len() > pwdvault_domain::validation::MAX_BACKUP_DECODED_BYTES {
        payload_json.zeroize();
        return Err(VaultError::InvalidInput {
            code: "BACKUP_TOO_LARGE".into(),
            message: "Backup exceeds the maximum supported size".into(),
        });
    }

    // Derive export key from export password using Argon2id
    let salt = crypto::kdf::generate_salt();
    let (mut export_key, params) = crypto::kdf::derive_key(export_password.as_str(), &salt)?;

    // `export_password` is Zeroizing<String>; wiped on drop here.

    // Encrypt payload with export key
    let created_at = chrono::Utc::now().timestamp();
    let b64 = base64::engine::general_purpose::STANDARD;
    let salt_b64 = b64.encode(salt);
    let mut backup = VaultBackup {
        version: BACKUP_VERSION_V2,
        created_at,
        magic: Some(BACKUP_MAGIC.to_string()),
        kdf_name: Some(BACKUP_KDF.to_string()),
        cipher_name: Some(BACKUP_CIPHER.to_string()),
        salt: salt_b64,
        kdf_memory: params.m_cost,
        kdf_iterations: params.t_cost,
        kdf_parallelism: params.p_cost,
        nonce: String::new(),
        data: String::new(),
    };
    let aad = backup_v2_aad(&backup)?;
    let encrypted = encrypt_with_aad(&export_key, &payload_json, &aad)?;

    // Zeroize the export key and plaintext payload now that encryption is done.
    export_key.zeroize();
    // ExportEntry uses Zeroizing<String> so sensitive strings are cleared
    // automatically when the Vec is dropped.
    payload_json.zeroize();

    backup.nonce = b64.encode(&encrypted.nonce);
    backup.data = b64.encode(&encrypted.ciphertext);
    Ok(backup)
}

pub fn import_vault(
    state: &Arc<AppState>,
    backup: VaultBackup,
    import_password: Zeroizing<String>,
) -> Result<ImportResult, VaultError> {
    pwdvault_domain::validation::import_password(import_password.as_str())?;
    let lease = state.lease()?;

    if !matches!(backup.version, BACKUP_VERSION_V1 | BACKUP_VERSION_V2) {
        return Err(VaultError::InvalidBackup(
            "Unsupported backup version".to_string(),
        ));
    }
    if backup.version == BACKUP_VERSION_V2
        && (backup.magic.as_deref() != Some(BACKUP_MAGIC)
            || backup.kdf_name.as_deref() != Some(BACKUP_KDF)
            || backup.cipher_name.as_deref() != Some(BACKUP_CIPHER))
    {
        return Err(VaultError::InvalidBackup(
            "Invalid backup envelope".to_string(),
        ));
    }
    let max_b64_len = pwdvault_domain::validation::MAX_BACKUP_DECODED_BYTES
        .saturating_mul(4)
        .div_ceil(3)
        .saturating_add(4);
    if backup.data.len() > max_b64_len || backup.salt.len() > 128 || backup.nonce.len() > 128 {
        return Err(VaultError::InvalidBackup(
            "Backup exceeds resource limits".to_string(),
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

    if salt.len() != 16 || nonce_bytes.len() != crypto::NONCE_SIZE {
        return Err(VaultError::InvalidBackup("Invalid salt length".to_string()));
    }
    if ciphertext.len() < 16
        || ciphertext.len() > pwdvault_domain::validation::MAX_BACKUP_DECODED_BYTES
    {
        return Err(VaultError::InvalidBackup(
            "Invalid ciphertext length".to_string(),
        ));
    }

    // Derive key from import password with stored KDF params
    let salt_array: [u8; 16] = salt
        .try_into()
        .map_err(|_| VaultError::InvalidBackup("Invalid salt".to_string()))?;
    let params = crypto::kdf::AdaptiveParams {
        m_cost: backup.kdf_memory,
        t_cost: backup.kdf_iterations,
        p_cost: backup.kdf_parallelism,
    };
    crypto::kdf::KdfPolicy::validate(&params)
        .map_err(|_| VaultError::InvalidBackup("Invalid KDF parameters".to_string()))?;
    let (mut import_key, _params) =
        crypto::kdf::derive_key_with_params(import_password.as_str(), &salt_array, &params)?;

    // `import_password` is Zeroizing<String>; wiped on drop here.

    // Decrypt payload
    let encrypted_data = EncryptedData {
        nonce: nonce_bytes,
        ciphertext,
    };
    let mut payload_bytes = if backup.version == BACKUP_VERSION_V2 {
        let aad = backup_v2_aad(&backup)?;
        decrypt_with_aad(&import_key, &encrypted_data, &aad)
    } else {
        decrypt(&import_key, &encrypted_data)
    }
    .map_err(|_| VaultError::InvalidPassword)?;

    // Zeroize the import key now that decryption is done.
    import_key.zeroize();

    // Parse payload — validate before any destructive operations
    let payload: BackupPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VaultError::InvalidBackup(format!("Invalid payload: {}", e)))?;

    // Zeroize decrypted payload bytes
    payload_bytes.zeroize();
    pwdvault_domain::validation::backup_payload(&payload)?;

    let db = get_db(state)?;
    let key = lease.enc_key()?;

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
        let enc_pwd = encrypt(key, export_entry.password.as_bytes())?;
        entry.encrypted_password = bincode::serialize(&enc_pwd)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        // Encrypt notes
        entry.encrypted_notes = if let Some(ref notes) = export_entry.notes {
            let enc = encrypt(key, notes.as_bytes())?;
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
        let blob = database::group_codec::seal_group(g, key)?;
        sealed_groups.push((g.id.clone(), blob));
    }
    let mut sealed_entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(new_entries.len());
    for entry in &new_entries {
        let blob = database::entry_codec::seal_entry(entry, key)?;
        sealed_entries.push((entry.id.clone(), blob));
    }
    let settings_bytes = serde_json::to_vec(&payload.settings)
        .map_err(|e| VaultError::InternalError(e.to_string()))?;

    // Collect existing IDs via a read transaction before the write.
    let existing_entry_ids = database::list_entries(&db)?;
    let existing_group_ids = database::list_groups(&db)?;

    // Apply all mutations AND digest refresh in a single write transaction
    // (§5.1.2). Wrapped in an inner closure returning DatabaseError so the
    // redb error types convert via the existing From impls on DatabaseError.
    let mac_key = lease.mac_key()?;
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
        // Refresh digest within the SAME transaction (§5.1.2)
        database::integrity::refresh_digest_in_txn(&txn, mac_key)?;
        txn.commit()?;
        Ok(())
    };
    apply_txn()?;

    *state.auto_lock_secs.lock().expect("timeout lock poisoned") = payload.settings.auto_lock_secs;

    let entries_count = payload.entries.len();
    let groups_count = payload.groups.len();

    lease.touch_activity();
    Ok(ImportResult {
        entries_imported: entries_count,
        groups_imported: groups_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
    use pwdvault_infrastructure::database::Settings;
    use tempfile::TempDir;

    const TEST_PASSWORD: &str = "backup-test-password";

    fn unlocked_state_with_entries<F>(build_entries: F) -> (Arc<AppState>, TempDir, Vec<String>)
    where
        F: FnOnce(&[u8; 32]) -> Vec<PasswordEntry>,
    {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(database::init_database(dir.path().join("backup.db")).unwrap());
        let salt = [0x41; 16];
        let params = AdaptiveParams {
            m_cost: 16384,
            t_cost: 1,
            p_cost: 1,
        };
        let (master_key, _) =
            crypto::kdf::derive_key_with_params(TEST_PASSWORD, &salt, &params).unwrap();
        let verification = crypto::create_verification_header(&master_key, salt, params).unwrap();
        let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);
        let entries = build_entries(&enc_key);
        let entry_ids = entries.iter().map(|entry| entry.id.clone()).collect();

        database::vault_store::VaultStore::new(&db)
            .write(&mac_key, |txn| {
                database::vault_store::save_verification_data_in_txn(txn, &verification)?;
                pwdvault_infrastructure::vault_header::save_header_in_txn(
                    txn,
                    &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
                    &enc_key,
                )?;
                database::vault_store::save_settings_in_txn(txn, &Settings::default())?;
                for entry in &entries {
                    database::vault_store::save_entry_in_txn(txn, &enc_key, entry)?;
                }
                Ok(())
            })
            .unwrap();

        let state = Arc::new(AppState::default());
        *state.database.lock().unwrap() = Some(db);
        *state.verification_data.lock().unwrap() = Some(verification);
        state.session.unlock(enc_key, mac_key);
        (state, dir, entry_ids)
    }

    fn unlocked_state() -> (Arc<AppState>, TempDir) {
        let (state, dir, _) = unlocked_state_with_entries(|enc_key| {
            let mut entry = PasswordEntry::new("Backup entry".into(), None, "backup-user".into());
            let encrypted_password = crypto::encrypt(enc_key, b"backup-secret").unwrap();
            entry.encrypted_password = bincode::serialize(&encrypted_password).unwrap();
            vec![entry]
        });
        (state, dir)
    }

    #[test]
    fn v2_export_import_round_trip() {
        let (state, _dir) = unlocked_state();
        let backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
        assert_eq!(backup.version, BACKUP_VERSION_V2);
        assert_eq!(backup.magic.as_deref(), Some(BACKUP_MAGIC));
        let result =
            import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
        assert_eq!(result.entries_imported, 1);
    }

    #[test]
    fn export_supports_raw_historical_secrets_and_empty_passwords() {
        let (state, _dir, _) = unlocked_state_with_entries(|enc_key| {
            let mut raw =
                PasswordEntry::new("Historical raw entry".into(), None, "legacy-user".into());
            raw.encrypted_password = crypto::encrypt(enc_key, b"legacy-secret")
                .unwrap()
                .to_bytes();
            raw.encrypted_notes = Some(
                crypto::encrypt(enc_key, b"legacy-notes")
                    .unwrap()
                    .to_bytes(),
            );

            let mut empty =
                PasswordEntry::new("Historical empty entry".into(), None, "empty-user".into());
            empty.encrypted_password = Vec::new();
            empty.encrypted_notes = Some(Vec::new());
            vec![raw, empty]
        });

        let backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
        let result =
            import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
        assert_eq!(result.entries_imported, 2);

        let entries = crate::service::list_all_entries(&state).unwrap();
        let raw_id = entries
            .iter()
            .find(|entry| entry.title == "Historical raw entry")
            .unwrap()
            .id
            .clone();
        let empty_id = entries
            .iter()
            .find(|entry| entry.title == "Historical empty entry")
            .unwrap()
            .id
            .clone();

        let raw = crate::service::get_entry_secret(&state, raw_id).unwrap();
        assert_eq!(raw.password.as_str(), "legacy-secret");
        assert_eq!(
            raw.notes.as_deref().map(String::as_str),
            Some("legacy-notes")
        );

        let empty = crate::service::get_entry_secret(&state, empty_id).unwrap();
        assert_eq!(empty.password.as_str(), "");
        assert!(empty.notes.is_none());
    }

    #[test]
    fn v1_fixture_remains_importable() {
        let (state, _dir) = unlocked_state();
        let (json, password) = crate::fixtures::create_backup_v1(2);
        let backup: VaultBackup = serde_json::from_str(&json).unwrap();
        let result = import_vault(&state, backup, Zeroizing::new(password.to_string())).unwrap();
        assert_eq!(result.entries_imported, 2);
    }

    #[test]
    fn v2_header_nonce_and_ciphertext_tampering_fail() {
        let (state, _dir) = unlocked_state();
        let backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();

        let mut header = backup.clone();
        header.created_at += 1;
        assert!(import_vault(&state, header, Zeroizing::new(TEST_PASSWORD.to_string())).is_err());

        let mut nonce = backup.clone();
        nonce.nonce.replace_range(
            ..1,
            if nonce.nonce.starts_with('A') {
                "B"
            } else {
                "A"
            },
        );
        assert!(import_vault(&state, nonce, Zeroizing::new(TEST_PASSWORD.to_string())).is_err());

        let mut ciphertext = backup;
        ciphertext.data.replace_range(
            ..1,
            if ciphertext.data.starts_with('A') {
                "B"
            } else {
                "A"
            },
        );
        assert!(import_vault(
            &state,
            ciphertext,
            Zeroizing::new(TEST_PASSWORD.to_string())
        )
        .is_err());
    }

    #[test]
    fn invalid_kdf_and_oversized_backup_rejected_before_work() {
        let (state, _dir) = unlocked_state();
        let mut backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
        backup.kdf_memory = u32::MAX;
        let start = std::time::Instant::now();
        assert!(import_vault(
            &state,
            backup.clone(),
            Zeroizing::new(TEST_PASSWORD.to_string())
        )
        .is_err());
        assert!(start.elapsed().as_millis() < 50);

        backup.data = "A".repeat(
            pwdvault_domain::validation::MAX_BACKUP_DECODED_BYTES
                .saturating_mul(4)
                .div_ceil(3)
                .saturating_add(5),
        );
        assert!(import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).is_err());
    }
}
