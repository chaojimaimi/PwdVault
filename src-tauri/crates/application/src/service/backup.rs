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
    // Soft delete (P2.2): tombstoned rows are excluded — a restore must not
    // resurrect entries the user deleted (note: restoring an older backup
    // can still re-add a deleted entry under its old ID; documented).
    let all_entries = database::list_all_entries_bulk(&db, key, None)?;
    let live_group_ids: std::collections::HashSet<String> =
        database::list_all_groups_bulk(&db, key)?
            .into_iter()
            .filter(|group| group.deleted_at.is_none())
            .map(|group| group.id)
            .collect();
    let mut export_entries = Vec::new();
    for entry in all_entries {
        if entry.deleted_at.is_some() {
            continue;
        }
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

        // Dangling group references (removed group without a cascade, P2.2)
        // normalize to "ungrouped" so backup_payload's referential check
        // stays valid.
        let group_id = entry.group_id.filter(|gid| live_group_ids.contains(gid));

        export_entries.push(ExportEntry {
            id: entry.id,
            title: entry.title,
            url: pwdvault_domain::validation::normalize_url(entry.url),
            username: entry.username,
            password: Zeroizing::new(password),
            notes,
            tags: entry.tags,
            group_id,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        });
    }

    // Load groups via bulk scan (§5.6.2), excluding tombstones.
    let groups = database::list_all_groups_bulk(&db, key)?
        .into_iter()
        .filter(|group| group.deleted_at.is_none())
        .collect::<Vec<_>>();

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

/// Maximum .pvault file size accepted by [`parse_backup_file_bytes`] —
/// mirrors the frontend constant `MAX_BACKUP_FILE_BYTES`
/// (src/screens/ImportExportScreen.tsx).
pub const MAX_BACKUP_FILE_BYTES: usize = 14 * 1024 * 1024;

/// Parse and pre-validate a raw .pvault file (SEC-M2: the webview no longer
/// reads backup files itself — the `read_backup_file` IPC command feeds the
/// bytes here). Enforces the file-size cap, the JSON shape, and the envelope
/// version/magic rules; the full cryptographic validation still happens in
/// [`import_vault`] at restore time.
pub fn parse_backup_file_bytes(bytes: &[u8]) -> Result<VaultBackup, VaultError> {
    if bytes.len() > MAX_BACKUP_FILE_BYTES {
        return Err(VaultError::InvalidInput {
            code: "BACKUP_TOO_LARGE".into(),
            message: "Backup file is too large".into(),
        });
    }
    let backup: VaultBackup = serde_json::from_slice(bytes)
        .map_err(|e| VaultError::InvalidBackup(format!("Invalid backup file: {}", e)))?;
    validate_backup_envelope(&backup)?;
    Ok(backup)
}

/// Stage 1 of the import pipeline (and the pre-flight check behind
/// `parse_backup_file_bytes`): version support, v2 header names, and
/// resource limits — no decoding and no KDF work.
fn validate_backup_envelope(backup: &VaultBackup) -> Result<(), VaultError> {
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
    Ok(())
}

/// Stage 2 output: the decoded envelope fields, ready for key derivation.
struct DecodedBackup {
    salt: [u8; 16],
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    params: crypto::kdf::AdaptiveParams,
}

/// Stage 2: decode the base64 envelope fields and enforce the KDF policy
/// (structural `validate` + the X6 import floor) BEFORE any key derivation.
fn decode_and_check_kdf(backup: &VaultBackup) -> Result<DecodedBackup, VaultError> {
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
    // X6: import-side product floor — backups whose embedded KDF params fall
    // below the OWASP baseline (19 MiB / t=2) are rejected before derivation.
    // Deliberately stricter than the structural `validate` above and applied
    // ONLY here: the unlock path (`verification.rs`) keeps accepting every
    // historical parameter set so existing vaults keep unlocking.
    if !crypto::kdf::KdfPolicy::meets_import_floor(&params) {
        return Err(VaultError::WeakKdfParams);
    }
    Ok(DecodedBackup {
        salt: salt_array,
        nonce: nonce_bytes,
        ciphertext,
        params,
    })
}

/// Stage 3: derive the import key from the stored KDF params. Consumes
/// `import_password` (moved through the pipeline): the Zeroizing buffer
/// stays alive until derivation completes and is wiped on drop at the end of
/// this function — it never escapes it.
fn derive_import_key(
    import_password: Zeroizing<String>,
    salt: [u8; 16],
    params: &crypto::kdf::AdaptiveParams,
) -> Result<[u8; 32], VaultError> {
    let (import_key, _params) =
        crypto::kdf::derive_key_with_params(import_password.as_str(), &salt, params)?;

    // `import_password` is Zeroizing<String>; wiped on drop here.
    Ok(import_key)
}

/// Stage 4: decrypt the payload (v2 binds the envelope as AAD; v1 is plain
/// AEAD). An authentication failure reports as `InvalidPassword`.
fn decrypt_backup_payload(
    backup: &VaultBackup,
    import_key: &[u8; 32],
    nonce_bytes: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, VaultError> {
    let encrypted_data = EncryptedData {
        nonce: nonce_bytes,
        ciphertext,
    };
    if backup.version == BACKUP_VERSION_V2 {
        let aad = backup_v2_aad(backup)?;
        decrypt_with_aad(import_key, &encrypted_data, &aad)
    } else {
        decrypt(import_key, &encrypted_data)
    }
    .map_err(|_| VaultError::InvalidPassword)
}

/// Stage 5a: re-ID the payload groups (new IDs avoid conflicts with the
/// live vault) and return the old→new group-id map for the entry remap.
fn remap_import_groups(
    payload: &BackupPayload,
) -> (Vec<Group>, std::collections::HashMap<String, String>) {
    let mut group_id_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut new_groups = Vec::new();
    for g in &payload.groups {
        let new_group = Group::new(g.name.clone());
        group_id_map.insert(g.id.clone(), new_group.id.clone());
        new_groups.push(new_group);
    }
    (new_groups, group_id_map)
}

/// Stage 5b: re-encrypt every entry under the current master key, mapping
/// group references through the old→new ID map.
fn encrypt_import_entries(
    payload: &BackupPayload,
    group_id_map: &std::collections::HashMap<String, String>,
    key: &[u8; 32],
) -> Result<Vec<PasswordEntry>, VaultError> {
    let mut new_entries = Vec::new();
    for export_entry in &payload.entries {
        let mut entry = PasswordEntry::new(
            export_entry.title.clone(),
            pwdvault_domain::validation::normalize_url(export_entry.url.clone()),
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
    Ok(new_entries)
}

/// Stage 5: pre-validate and pre-encrypt every row BEFORE any destructive
/// operations — a validation or encryption failure must leave the database
/// untouched. Returns the re-IDed groups and the entries re-encrypted under
/// the current master key.
fn prepare_import_rows(
    payload: &BackupPayload,
    key: &[u8; 32],
) -> Result<(Vec<Group>, Vec<PasswordEntry>), VaultError> {
    let (new_groups, group_id_map) = remap_import_groups(payload);
    let new_entries = encrypt_import_entries(payload, &group_id_map, key)?;
    Ok((new_groups, new_entries))
}

pub fn import_vault(
    state: &Arc<AppState>,
    backup: VaultBackup,
    import_password: Zeroizing<String>,
) -> Result<ImportResult, VaultError> {
    pwdvault_domain::validation::import_password(import_password.as_str())?;
    let lease = state.lease()?;

    // Stages 1-2: hostile-input fast path — envelope and KDF policy checks
    // run before any key derivation or database access (X6).
    validate_backup_envelope(&backup)?;
    let decoded = decode_and_check_kdf(&backup)?;

    // Stage 3: derive the import key.
    let mut import_key = derive_import_key(import_password, decoded.salt, &decoded.params)?;

    // Stage 4: decrypt the payload.
    let mut payload_bytes =
        decrypt_backup_payload(&backup, &import_key, decoded.nonce, decoded.ciphertext)?;

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

    // Stage 5: pre-validate and pre-encrypt all rows before any destructive
    // operations.
    let (new_groups, new_entries) = prepare_import_rows(&payload, key)?;

    // Stage 6 — all validation and encryption succeeded — now perform
    // database mutations atomically. Pre-seal (encrypt) all records BEFORE
    // opening the write transaction so that a seal failure rolls back cleanly
    // without leaving the database half-cleared. The entire clear+insert
    // cycle runs in ONE redb write transaction: if any operation fails, the
    // transaction is aborted and the vault remains untouched.
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

    lease.touch_remote_activity();
    Ok(ImportResult {
        entries_imported: entries_count,
        groups_imported: groups_count,
    })
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod tests;
