use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, create_verification_header, unlock_with_password};
use crate::database::{self, load_settings, Settings};
use crate::paths;
use crate::{constants, AppState, VaultError};

/// Check if the rate limiter is currently blocking unlock attempts.
pub fn check_rate_limit(state: &AppState) -> Result<(), VaultError> {
    let lockout = state.lockout_until.lock().expect("lockout lock poisoned");
    if let Some(until) = *lockout {
        let now = Instant::now();
        if now < until {
            let remaining = (until - now).as_secs();
            return Err(VaultError::RateLimited {
                retry_after_secs: remaining,
            });
        }
    }
    Ok(())
}

/// Record a failed unlock attempt. After MAX_FAILED_ATTEMPTS, starts lockout.
pub fn record_failed_attempt(state: &AppState) {
    let mut attempts = state
        .failed_unlock_attempts
        .lock()
        .expect("attempts lock poisoned");
    *attempts += 1;
    if *attempts >= constants::MAX_FAILED_ATTEMPTS {
        let mut lockout = state.lockout_until.lock().expect("lockout lock poisoned");
        *lockout = Some(Instant::now() + Duration::from_secs(constants::LOCKOUT_DURATION_SECS));
        *attempts = 0;
    }
}

/// Reset rate limit state (called on successful unlock).
pub fn reset_rate_limit(state: &AppState) {
    *state
        .failed_unlock_attempts
        .lock()
        .expect("attempts lock poisoned") = 0;
    *state.lockout_until.lock().expect("lockout lock poisoned") = None;
}

/// Get the database from state.
pub fn get_db(state: &Arc<AppState>) -> Result<Arc<redb::Database>, VaultError> {
    let guard = state.database.lock().expect("db lock poisoned");
    guard
        .clone()
        .ok_or_else(|| VaultError::InternalError("Database not initialized".to_string()))
}

/// Get the MAC key from the vault session.
pub fn get_mac_key(state: &Arc<AppState>) -> Result<[u8; 32], VaultError> {
    state.session.get_mac_key()
}

/// Get the encryption key from the vault session.
pub fn get_enc_key(state: &Arc<AppState>) -> Result<[u8; 32], VaultError> {
    state.session.get_enc_key()
}

fn ensure_db_dir() -> Result<std::path::PathBuf, VaultError> {
    paths::ensure_db_dir().map_err(|e| VaultError::InternalError(e.to_string()))
}

pub fn is_initialized(state: &Arc<AppState>) -> bool {
    state
        .verification_data
        .lock()
        .expect("verification lock poisoned")
        .is_some()
}

pub fn is_unlocked(state: &Arc<AppState>) -> bool {
    state.session.is_unlocked()
}

pub fn init_vault(state: &Arc<AppState>, password: Zeroizing<String>) -> Result<(), VaultError> {
    if state
        .verification_data
        .lock()
        .expect("verification lock poisoned")
        .is_some()
    {
        // `password` is Zeroizing<String>; it is wiped on drop at return.
        return Err(VaultError::VaultAlreadyExists);
    }

    let db_path = ensure_db_dir()?;
    let db = Arc::new(database::init_database(&db_path)?);
    *state.database.lock().expect("db lock poisoned") = Some(db.clone());

    let salt = crypto::kdf::generate_salt();
    let (master_key, params) = crypto::kdf::derive_key(password.as_str(), &salt)?;

    // `password` zeroizes on drop here.

    let verification_data = create_verification_header(&master_key, salt, params)?;

    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &verification_data.salt);

    // Single transaction: verification data + header + settings + digest (§5.1.2, §5.1.4)
    let default_settings = Settings::default();
    let header = crate::vault_header::VaultHeader::new_initial();
    {
        let store = database::vault_store::VaultStore::new(&db);
        store.write(&mac_key, |txn| {
            database::vault_store::save_verification_data_in_txn(txn, &verification_data)?;
            crate::vault_header::save_header_in_txn(txn, &header, &enc_key)?;
            database::vault_store::save_settings_in_txn(txn, &default_settings)?;
            Ok(())
        })?;
    }

    *state
        .verification_data
        .lock()
        .expect("verification lock poisoned") = Some(verification_data);
    state.session.unlock(enc_key, mac_key);

    state.touch_activity();
    state.update_lock_menu("Lock Vault");

    Ok(())
}

pub fn unlock_vault(
    state: &Arc<AppState>,
    password: Zeroizing<String>,
) -> Result<bool, VaultError> {
    // §5.1.3: Two-phase unlock — keys are NOT published until ALL
    // verification completes. Any error before step 8 leaves the vault
    // in the Locked state.

    // Step 1: Check rate limit
    check_rate_limit(state)?;

    let verification_data = state
        .verification_data
        .lock()
        .expect("verification lock poisoned")
        .as_ref()
        .ok_or(VaultError::VaultLocked)?
        .clone();

    // Step 2: Verify password and derive keys in local variables.
    // The keys stay in local scope — they are NOT published to the session yet.
    let keys = unlock_with_password(password.as_str(), &verification_data)?;

    // `password` zeroizes on drop here.

    let (enc_key, mac_key) = match keys {
        Some(k) => k,
        None => {
            record_failed_attempt(state);
            return Ok(false);
        }
    };

    // Step 3: Acquire database handle
    let db = get_db(state)?;

    // Step 4: Read and verify the AEAD-authenticated vault header (§5.1.4).
    // The header determines whether this is a legacy DB that needs migration,
    // or a modern DB that must fail-closed on integrity issues.
    let header = crate::vault_header::load_header(&db, &enc_key)?;
    let integrity_required = crate::vault_header::is_integrity_required(header.as_ref());

    // Step 5-6: Verify integrity and migrate if needed.
    if integrity_required {
        // Modern database with integrity_required=true.
        // §5.1.4: Missing or unknown digest → REJECT (no auto-migration).
        if !database::integrity::has_digest(&db)? {
            tracing::error!("integrity_required but digest missing — possible tampering");
            return Err(VaultError::InvalidBackup(
                "Database integrity check failed".to_string(),
            ));
        }
        if database::integrity::needs_digest_rebuild(&db)? {
            // Unknown digest version → REJECT (not auto-rebuild)
            tracing::error!("integrity_required but digest version unknown — possible downgrade");
            return Err(VaultError::InvalidBackup(
                "Database integrity check failed".to_string(),
            ));
        }
        if !database::integrity::verify_integrity(&db, &mac_key)? {
            // Digest mismatch → tampering detected → REJECT
            return Err(VaultError::InvalidBackup(
                "Database integrity check failed".to_string(),
            ));
        }
    } else {
        // Legacy database (no header, or header with integrity_required=false).
        // Migration is triggered by the explicit absence of integrity protection.
        tracing::info!("migrating database from legacy format");
        let (mut master_key, _) = crypto::kdf::derive_key_with_params(
            password.as_str(),
            &verification_data.salt,
            &verification_data.params,
        )?;
        let migrate_result = migrate_database(&db, &master_key, &enc_key, &mac_key);
        master_key.zeroize();
        migrate_result?; // Error = stay Locked
    }

    // Step 7: Load and validate settings
    let settings = load_settings(&db)?;

    // Step 8: Atomically publish UnlockedSession — THE LAST STEP.
    // Only now are the keys exposed to other threads.
    state.session.unlock(enc_key, mac_key);

    // Step 9: Reset rate limit and start activity timer
    reset_rate_limit(state);
    *state.auto_lock_secs.lock().expect("timeout lock poisoned") = settings.auto_lock_secs;
    state.touch_activity();
    state.update_lock_menu("Lock Vault");

    Ok(true)
}

pub fn lock_vault(state: &Arc<AppState>) {
    state.lock_vault();
}

/// One-time migration for databases created before the current format.
///
/// Performs:
/// 1. **Pre-migration backup**: copies the original DB file to
///    `vault.db.{timestamp}.bak` (non-overwriting) before any modification (§5.1.4).
/// 2. **Inner field re-encryption**: `encrypted_password`/`encrypted_notes`
///    encrypted with `master_key` in v1.0.4 are re-encrypted with `enc_key`.
/// 3. **Outer blob re-seal with AAD**: all entries/groups are re-sealed
///    using record format v2 (AAD-bound) (§5.1.4).
/// 4. **Vault header**: writes an AEAD-authenticated header with
///    `integrity_required = true` so future unlock cannot be downgraded.
/// 5. **Digest baseline**: establishes the v4 integrity digest.
///
/// All writes (steps 2-5) happen in a single VaultStore transaction (§5.1.2).
fn migrate_database(
    db: &Arc<redb::Database>,
    master_key: &[u8; 32],
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<(), VaultError> {
    use crate::crypto::{decrypt, encrypt, EncryptedData};

    // §5.1.4: Create non-overwriting backup before migration.
    let db_path = paths::get_db_path();
    if db_path.exists() {
        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let backup_path = db_path.with_extension(format!("db.{}.bak", timestamp));
        if !backup_path.exists() {
            if let Err(e) = std::fs::copy(&db_path, &backup_path) {
                tracing::warn!("failed to create pre-migration backup: {}", e);
            } else {
                tracing::info!("pre-migration backup created");
            }
        }
    }

    // Pre-process entries: decrypt inner fields and re-seal with AAD.
    let entry_ids = database::list_entries(db)?;
    let entry_count = entry_ids.len();
    let mut sealed_entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(entry_count);
    for id in &entry_ids {
        if let Some(mut entry) = database::load_entry(db, enc_key, id)? {
            // Re-encrypt encrypted_password: master_key → enc_key
            if !entry.encrypted_password.is_empty() {
                let old_enc: EncryptedData = bincode::deserialize(&entry.encrypted_password)
                    .or_else(|_| EncryptedData::from_bytes(&entry.encrypted_password))?;
                if let Ok(plain) = decrypt(master_key, &old_enc) {
                    let new_enc = encrypt(enc_key, &plain)?;
                    entry.encrypted_password = bincode::serialize(&new_enc)
                        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
                }
                // If decrypt with master_key fails, the field is already
                // enc_key-encrypted; seal_entry will re-seal it with AAD.
            }

            // Re-encrypt encrypted_notes: master_key → enc_key
            if let Some(old_notes_bytes) = entry.encrypted_notes.take() {
                let old_enc: EncryptedData = bincode::deserialize(&old_notes_bytes)
                    .or_else(|_| EncryptedData::from_bytes(&old_notes_bytes))?;
                if let Ok(plain) = decrypt(master_key, &old_enc) {
                    let new_enc = encrypt(enc_key, &plain)?;
                    entry.encrypted_notes = Some(
                        bincode::serialize(&new_enc)
                            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?,
                    );
                } else {
                    entry.encrypted_notes = Some(old_notes_bytes);
                }
            }

            // Pre-seal with AAD (record format v2)
            let blob = database::entry_codec::seal_entry(&entry, enc_key)?;
            sealed_entries.push((entry.id.clone(), blob));
        }
    }

    // Pre-process groups
    let group_ids = database::list_groups(db)?;
    let group_count = group_ids.len();
    let mut sealed_groups: Vec<(String, Vec<u8>)> = Vec::with_capacity(group_count);
    for id in &group_ids {
        if let Some(group) = database::load_group(db, enc_key, id)? {
            let blob = database::group_codec::seal_group(&group, enc_key)?;
            sealed_groups.push((group.id.clone(), blob));
        }
    }

    // Single transaction: replace all records + write header + digest (§5.1.2, §5.1.4)
    let header = crate::vault_header::VaultHeader::new_migrated();
    let store = database::vault_store::VaultStore::new(db);
    store.write(mac_key, |txn| {
        // Replace entries
        {
            let mut t = txn.open_table(database::ENTRIES_TABLE)?;
            for id in &entry_ids {
                t.remove(id.as_str())?;
            }
            for (id, blob) in &sealed_entries {
                t.insert(id.as_str(), blob.as_slice())?;
            }
        }
        // Replace groups
        {
            let mut t = txn.open_table(database::GROUPS_TABLE)?;
            for id in &group_ids {
                t.remove(id.as_str())?;
            }
            for (id, blob) in &sealed_groups {
                t.insert(id.as_str(), blob.as_slice())?;
            }
        }
        // Write vault header (integrity_required = true)
        crate::vault_header::save_header_in_txn(txn, &header, enc_key)?;
        Ok(())
    })?;

    tracing::info!(
        entries = entry_count,
        groups = group_count,
        "database migration complete (AAD records + header + digest v4)"
    );

    Ok(())
}

pub fn setup_vault(state: &Arc<AppState>) -> Result<bool, VaultError> {
    // Check if database is already loaded in state
    {
        let db_guard = state.database.lock().expect("db lock poisoned");
        if db_guard.is_some()
            && state
                .verification_data
                .lock()
                .expect("verification lock poisoned")
                .is_some()
        {
            return Ok(true);
        }
    }

    let db_path = paths::get_db_path();

    if !db_path.exists() {
        return Ok(false);
    }

    let db = Arc::new(database::init_database(&db_path)?);
    *state.database.lock().expect("db lock poisoned") = Some(db.clone());

    let verification_data = database::load_verification_data(&db)?;

    if let Some(data) = verification_data {
        *state
            .verification_data
            .lock()
            .expect("verification lock poisoned") = Some(data);
        // Load auto-lock timeout from settings
        if let Ok(settings) = load_settings(&db) {
            *state.auto_lock_secs.lock().expect("timeout lock poisoned") = settings.auto_lock_secs;
        }
        return Ok(true);
    }

    Ok(false)
}
