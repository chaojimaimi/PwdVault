use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::{AppState, VaultError};
use pwdvault_domain::constants;
use pwdvault_infrastructure::crypto::{self, create_verification_header};
use pwdvault_infrastructure::database::{self, load_settings, Settings};
use pwdvault_infrastructure::paths;

use super::security::{complete_unlock, derive_master_for_unlock, verify_master_and_integrity};

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
#[cfg(test)]
pub fn get_mac_key(state: &Arc<AppState>) -> Result<[u8; 32], VaultError> {
    state.session.get_mac_key()
}

/// Get the encryption key from the vault session.
#[cfg(test)]
pub fn get_enc_key(state: &Arc<AppState>) -> Result<[u8; 32], VaultError> {
    state.session.get_enc_key()
}

/// Open the on-disk database and report whether a verification row exists (B2).
///
/// Returns `Ok(false)` when the file does not exist. A file that exists but
/// cannot be opened/read is an error: callers must not treat it as "no vault"
/// and proceed to overwrite it.
fn disk_has_verification(db_path: &std::path::Path) -> Result<bool, VaultError> {
    if !db_path.exists() {
        return Ok(false);
    }
    let db = database::init_database(db_path)?;
    database::load_verification_data(&db)
        .map(|data| data.is_some())
        .map_err(VaultError::from)
}

pub fn is_initialized(state: &Arc<AppState>) -> bool {
    if state
        .verification_data
        .lock()
        .expect("verification lock poisoned")
        .is_some()
    {
        return true;
    }
    // A database handle already open in state was opened by setup_vault from
    // the actual vault file — its (missing) verification row is authoritative.
    {
        let db_guard = state.database.lock().expect("db lock poisoned");
        if db_guard.is_some() {
            return false;
        }
    }
    // Disk fallback (B2): a vault left on disk by a previous run counts as
    // initialized during the boot window before setup_vault() has loaded it.
    match disk_has_verification(&paths::get_db_path()) {
        Ok(has_verification) => has_verification,
        Err(e) => {
            tracing::warn!("vault disk state check failed: {}", e);
            false
        }
    }
}

pub fn is_unlocked(state: &Arc<AppState>) -> bool {
    state.session.is_unlocked()
}

pub fn init_vault(state: &Arc<AppState>, password: Zeroizing<String>) -> Result<(), VaultError> {
    init_vault_at(&paths::get_db_path(), state, password)
}

/// Create a new vault at `db_path`. Split from [`init_vault`] so tests can
/// target a temporary path instead of the real user vault location.
fn init_vault_at(
    db_path: &std::path::Path,
    state: &Arc<AppState>,
    password: Zeroizing<String>,
) -> Result<(), VaultError> {
    pwdvault_domain::validation::master_password(password.as_str())?;
    if state
        .verification_data
        .lock()
        .expect("verification lock poisoned")
        .is_some()
    {
        // `password` is Zeroizing<String>; it is wiped on drop at return.
        return Err(VaultError::VaultAlreadyExists);
    }

    if let Some(parent) = db_path.parent() {
        paths::secure_dir(parent).map_err(|e| VaultError::InternalError(e.to_string()))?;
    }

    // Disk-level duplicate guard (B2): the in-memory check alone cannot see a
    // vault left on disk by a previous run. Never overwrite an existing
    // verification row; an unreadable existing file also fails closed.
    if disk_has_verification(db_path)? {
        // `password` is Zeroizing<String>; it is wiped on drop at return.
        return Err(VaultError::VaultAlreadyExists);
    }

    let db = Arc::new(database::init_database(db_path)?);
    *state.database.lock().expect("db lock poisoned") = Some(db.clone());

    let salt = crypto::kdf::generate_salt();
    let (master_key, params) = crypto::kdf::derive_key(password.as_str(), &salt)?;
    let master_key = Zeroizing::new(master_key);

    // `password` zeroizes on drop here.

    let verification_data = create_verification_header(&master_key, salt, params)?;

    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &verification_data.salt);
    let enc_key = crypto::SecretKey::new(enc_key);
    let mac_key = crypto::SecretKey::new(mac_key);

    // Single transaction: verification data + header + settings + digest (§5.1.2, §5.1.4)
    let default_settings = Settings::default();
    let header = pwdvault_infrastructure::vault_header::VaultHeader::new_initial();
    {
        let store = database::vault_store::VaultStore::new(&db);
        store.write(mac_key.as_ref(), |txn| {
            database::vault_store::save_verification_data_in_txn(txn, &verification_data)?;
            pwdvault_infrastructure::vault_header::save_header_in_txn(
                txn,
                &header,
                enc_key.as_ref(),
            )?;
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
    // verification completes. Any error before the publish step leaves the
    // vault in the Locked state.

    // Step 1: Check rate limit
    check_rate_limit(state)?;

    let verification_data = state
        .verification_data
        .lock()
        .expect("verification lock poisoned")
        .as_ref()
        .ok_or(VaultError::VaultLocked)?
        .clone();

    // Step 2: Verify password and derive the master key (single Argon2 pass,
    // same constant-time header check as `unlock_with_password` — the master
    // key is kept for the legacy-transparency migration branch).
    let master_key = match derive_master_for_unlock(password.as_str(), &verification_data)? {
        Some(master_key) => master_key,
        None => {
            record_failed_attempt(state);
            return Ok(false);
        }
    };

    // `password` zeroizes on drop here.

    // Steps 3-7: subkey derivation, header read/version check, integrity
    // verification (or legacy migration), settings validation. Nothing is
    // published yet.
    let (enc_key, mac_key) = verify_master_and_integrity(state, &master_key)?;

    // Steps 8-9: publish + side effects — THE LAST STEP.
    complete_unlock(state, enc_key, mac_key)?;

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
///
/// Unlock no longer triggers this automatically (B1 fail-closed); it is
/// reached through `verify_master_and_integrity` (password path) and kept
/// callable for tests and a future explicit migration tool.
pub(crate) fn migrate_database(
    db: &Arc<redb::Database>,
    master_key: &[u8; 32],
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<(), VaultError> {
    use pwdvault_infrastructure::crypto::{decrypt, encrypt, EncryptedData};

    // §5.1.4: Create non-overwriting backup before migration.
    backup_db_file("pre-migration");

    // Pre-process entries: decrypt inner fields and re-seal with AAD.
    let entry_ids = database::list_entries(db)?;
    let entry_count = entry_ids.len();
    let mut sealed_entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(entry_count);
    for id in &entry_ids {
        // Migration is the only path allowed to read pre-v1.0.5 plaintext
        // records (allow_plaintext = true).
        if let Some(mut entry) = database::load_entry(db, enc_key, id, true)? {
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
        // Migration is the only path allowed to read pre-v1.0.5 plaintext
        // records (allow_plaintext = true).
        if let Some(group) = database::load_group(db, enc_key, id, true)? {
            let blob = database::group_codec::seal_group(&group, enc_key)?;
            sealed_groups.push((group.id.clone(), blob));
        }
    }

    // Single transaction: replace all records + write header + digest (§5.1.2, §5.1.4)
    let header = pwdvault_infrastructure::vault_header::VaultHeader::new_migrated();
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
        pwdvault_infrastructure::vault_header::save_header_in_txn(txn, &header, enc_key)?;
        Ok(())
    })?;

    tracing::info!(
        entries = entry_count,
        groups = group_count,
        "database migration complete (AAD records + header + digest v4)"
    );

    Ok(())
}

/// Non-overwriting `.bak` copy of the vault file before a destructive
/// operation (§5.1.4 migration precedent; reused by Phase 1 password
/// change / recovery). Best-effort: a failed copy is logged, never fatal —
/// the caller's transaction remains the atomicity boundary.
pub(crate) fn backup_db_file(reason: &str) {
    let db_path = paths::get_db_path();
    if db_path.exists() {
        let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let backup_path = db_path.with_extension(format!("db.{reason}-{timestamp}.bak"));
        if !backup_path.exists() {
            if let Err(e) = std::fs::copy(&db_path, &backup_path) {
                tracing::warn!("failed to create {reason} backup: {}", e);
            } else {
                tracing::info!("{reason} backup created");
            }
        }
    }
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

#[cfg(test)]
#[path = "vault_tests.rs"]
mod tests;
