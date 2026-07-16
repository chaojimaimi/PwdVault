use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, create_verification_header, unlock_with_password};
use crate::database::{self, load_settings, save_settings, Settings};
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

    database::save_verification_data(&db, &verification_data)?;

    *state
        .verification_data
        .lock()
        .expect("verification lock poisoned") = Some(verification_data);
    state.session.unlock(enc_key, mac_key);

    let default_settings = Settings::default();
    save_settings(&db, &default_settings)?;

    database::integrity::refresh_digest(&db, &mac_key)?;

    state.touch_activity();
    state.update_lock_menu("Lock Vault");

    Ok(())
}

pub fn unlock_vault(
    state: &Arc<AppState>,
    password: Zeroizing<String>,
) -> Result<bool, VaultError> {
    check_rate_limit(state)?;

    let verification_data = state
        .verification_data
        .lock()
        .expect("verification lock poisoned")
        .as_ref()
        .ok_or(VaultError::VaultLocked)?
        .clone();

    let keys = unlock_with_password(password.as_str(), &verification_data)?;

    // `password` zeroizes on drop here.

    if let Some((enc_key, mac_key)) = keys {
        // NOTE: This still publishes keys before integrity verification —
        // the full two-phase unlock fix is §5.1.3 (Step 3). For now we use
        // the session API to keep the code compiling.
        state.session.unlock(enc_key, mac_key);

        // Verify database integrity before exposing unlocked vault.
        // For databases created before v1.0.5 (no stored digest), run a
        // one-time migration: re-encrypt entries/groups with the new codecs
        // and establish the integrity digest baseline.
        //
        // If a digest exists but its computation version is stale (computed
        // by an earlier v1.0.5 build with a different digest algorithm or
        // before inner-field re-encryption), re-run migration to re-encrypt
        // the inner encrypted_password/encrypted_notes fields from the v1.0.4
        // master_key to the v1.0.5 enc_key.
        if let Ok(db) = get_db(state) {
            if database::integrity::has_digest(&db)? {
                if database::integrity::needs_digest_rebuild(&db)? {
                    tracing::info!("rebuilding integrity baseline (digest version mismatch)");
                    // Re-derive master_key to decrypt v1.0.4-era inner fields.
                    let (mut master_key, _) = crypto::kdf::derive_key_with_params(
                        password.as_str(),
                        &verification_data.salt,
                        &verification_data.params,
                    )?;
                    migrate_database(&db, &master_key, &enc_key, &mac_key)?;
                    master_key.zeroize();
                } else if !database::integrity::verify_integrity(&db, &mac_key)? {
                    state.lock_vault();
                    return Err(VaultError::InvalidBackup(
                        "Database integrity check failed".to_string(),
                    ));
                }
            } else {
                tracing::info!("migrating database from pre-v1.0.5 format");
                let (mut master_key, _) = crypto::kdf::derive_key_with_params(
                    password.as_str(),
                    &verification_data.salt,
                    &verification_data.params,
                )?;
                migrate_database(&db, &master_key, &enc_key, &mac_key)?;
                master_key.zeroize();
            }
        }

        reset_rate_limit(state);
        // Load settings (e.g. auto-lock timeout) from database
        if let Ok(db) = get_db(state) {
            if let Ok(settings) = load_settings(&db) {
                *state.auto_lock_secs.lock().expect("timeout lock poisoned") =
                    settings.auto_lock_secs;
            }
        }
        state.touch_activity();
        state.update_lock_menu("Lock Vault");
    } else {
        record_failed_attempt(state);
    }

    Ok(keys.is_some())
}

pub fn lock_vault(state: &Arc<AppState>) {
    state.lock_vault();
}

/// One-time migration for databases created before v1.0.5 (or with an
/// earlier v1.0.5 build that did not re-encrypt inner fields).
///
/// Performs two layers of re-encryption:
/// 1. **Inner fields**: `encrypted_password` and `encrypted_notes` were
///    encrypted with `master_key` in v1.0.4. Decrypt with `master_key`,
///    re-encrypt with `enc_key` (the HKDF-derived subkey used by v1.0.5).
/// 2. **Outer blob**: v1.0.4 stored plaintext `bincode::serialize(entry)`.
///    v1.0.5 wraps it via `seal_entry` (encrypt the serialized entry).
///    `open_entry` handles both formats on read, but we re-seal so future
///    reads don't rely on the fallback.
///
/// After migration, establishes the integrity digest baseline.
fn migrate_database(
    db: &Arc<redb::Database>,
    master_key: &[u8; 32],
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<(), VaultError> {
    use crate::crypto::{decrypt, encrypt, EncryptedData};

    let entry_ids = database::list_entries(db)?;
    let entry_count = entry_ids.len();
    for id in &entry_ids {
        if let Some(mut entry) = database::load_entry(db, enc_key, id)? {
            // Re-encrypt encrypted_password: master_key → enc_key
            if !entry.encrypted_password.is_empty() {
                let old_enc: EncryptedData = bincode::deserialize(&entry.encrypted_password)
                    .or_else(|_| EncryptedData::from_bytes(&entry.encrypted_password))?;
                if let Ok(plain) = decrypt(master_key, &old_enc) {
                    // Successfully decrypted with master_key → re-encrypt with enc_key
                    let new_enc = encrypt(enc_key, &plain)?;
                    entry.encrypted_password = bincode::serialize(&new_enc)
                        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
                } else {
                    // Already encrypted with enc_key (or format unknown) — leave as-is
                    tracing::warn!(entry_id = %id, "could not decrypt password with master_key, leaving as-is");
                }
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
                    // Already encrypted with enc_key — put it back
                    entry.encrypted_notes = Some(old_notes_bytes);
                    tracing::warn!(entry_id = %id, "could not decrypt notes with master_key, leaving as-is");
                }
            }

            // Re-seal the outer blob with enc_key (v1.0.5 format)
            database::save_entry(db, enc_key, &entry)?;
        }
    }

    // Migrate groups (outer blob only — no inner encrypted fields)
    let group_ids = database::list_groups(db)?;
    let group_count = group_ids.len();
    for id in &group_ids {
        if let Some(group) = database::load_group(db, enc_key, id)? {
            database::save_group(db, enc_key, &group)?;
        }
    }

    // Establish integrity digest baseline
    database::integrity::refresh_digest(db, mac_key)?;

    tracing::info!(
        entries = entry_count,
        groups = group_count,
        "database migration complete (inner fields re-encrypted)"
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
