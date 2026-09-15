//! Shared helpers for the security operations: the unlock verification chain,
//! the D8 re-seal plumbing, and the credential wrap-blob row keys.

use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::{AppState, VaultError};
use pwdvault_infrastructure::crypto::{
    self, create_verification_header, recovery_wrap_key, unwrap_secret, wrap_secret, SecretKey,
    VerificationData, WRAP_AAD_BIO, WRAP_AAD_RECOVERY,
};
use pwdvault_infrastructure::database::{
    self, load_settings,
    vault_store::{self, VaultStore},
};
use pwdvault_infrastructure::keychain::{SecretStoreError, BIO_WRAP_ACCOUNT};

use super::super::vault::{get_db, reset_rate_limit};

/// VAULT_TABLE row holding the biometric wrap blob (D4).
pub const BIO_WRAP_BLOB_KEY: &str = "bio_wrap";

/// VAULT_TABLE row holding the recovery wrap blob (D4).
pub const RECOVERY_WRAP_BLOB_KEY: &str = "recovery_wrap";

/// Escape-hatch guidance shown when the credential store no longer holds the
/// wrap key for an enabled bio blob (e.g. keychain reset). No secret material.
const BIO_KEYCHAIN_MISSING_GUIDANCE: &str = "Touch ID credentials for this vault are out of sync. \
     Unlock with your master password, disable Touch ID in Settings, then enable it again and retry.";

// ---------------------------------------------------------------------------
// Shared unlock helpers (extracted from `unlock_vault`, behavior preserved)
// ---------------------------------------------------------------------------

/// Clone of the verification row from app state.
pub(super) fn current_verification(state: &Arc<AppState>) -> Result<VerificationData, VaultError> {
    Ok(state
        .verification_data
        .lock()
        .expect("verification lock poisoned")
        .as_ref()
        .ok_or(VaultError::VaultLocked)?
        .clone())
}

/// Derive the master key from a password and check it against the
/// verification header. `None` means wrong password.
///
/// This mirrors `crypto::unlock_with_password` (same single Argon2 pass, same
/// constant-time comparison) except that it KEEPS the master key:
/// `verify_master_and_integrity` needs it for the legacy-transparency
/// migration branch, and the Touch ID / recovery enable paths need it to
/// wrap. `unlock_with_password` deliberately zeroizes the master key, so it
/// cannot serve those callers.
pub fn derive_master_for_unlock(
    password: &str,
    verification: &VerificationData,
) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
    let (master_key, _) =
        crypto::kdf::derive_key_with_params(password, &verification.salt, &verification.params)?;
    let master_key = Zeroizing::new(master_key);

    // Same check unlock_with_password performs before discarding the master.
    let matches = match crypto::decrypt(&master_key, &verification.encrypted_header) {
        Ok(decrypted) => decrypted
            .as_slice()
            .ct_eq(pwdvault_infrastructure::crypto::VERIFICATION_HEADER)
            .into(),
        Err(_) => false,
    };
    // On the mismatch path the Zeroizing master key is dropped here (wiped).
    Ok(matches.then_some(master_key))
}

/// Verify the master key against the vault WITHOUT publishing any keys
/// (unlock steps 3-7, verification-only):
///
/// 1. derive enc/mac subkeys from the master key
/// 2. read + version-check the AEAD vault header
/// 3. verify the integrity digest (modern vaults) or run the one-time legacy
///    migration — the migration branch passes the GIVEN master key through
///    (the password path derives the same bytes; Touch ID / recovery
///    callers can never reach it because enable is rejected on legacy vaults)
/// 4. load settings to fail early on corruption
///
/// Returns the derived subkeys; callers publish them via [`complete_unlock`].
pub fn verify_master_and_integrity(
    state: &Arc<AppState>,
    master_key: &[u8; 32],
) -> Result<(SecretKey, SecretKey), VaultError> {
    let verification_data = current_verification(state)?;
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(master_key, &verification_data.salt);
    let enc_key = SecretKey::new(enc_key);
    let mac_key = SecretKey::new(mac_key);

    // Step 4: read and verify the AEAD-authenticated vault header (§5.1.4).
    let db = get_db(state)?;
    let header = pwdvault_infrastructure::vault_header::load_header(&db, enc_key.as_ref())?;
    if header
        .as_ref()
        .is_some_and(|value| !pwdvault_infrastructure::vault_header::is_supported(value))
    {
        return Err(VaultError::InvalidBackup(
            "Database format is newer than this application".to_string(),
        ));
    }

    // Steps 5-6: verify integrity / migrate legacy layouts.
    match header.as_ref() {
        Some(value) if value.integrity_required => {
            if !database::integrity::has_digest(&db)? {
                tracing::error!("integrity_required but digest missing — possible tampering");
                return Err(VaultError::InvalidBackup(
                    "Database integrity check failed".to_string(),
                ));
            }
            if database::integrity::needs_digest_rebuild(&db)? {
                tracing::error!(
                    "integrity_required but digest version unknown — possible downgrade"
                );
                return Err(VaultError::InvalidBackup(
                    "Database integrity check failed".to_string(),
                ));
            }
            if !database::integrity::verify_integrity(&db, mac_key.as_ref())? {
                return Err(VaultError::InvalidBackup(
                    "Database integrity check failed".to_string(),
                ));
            }
        }
        // One-time legacy migration. Only the password path can reach this:
        // enable_biometric/enable_recovery reject legacy vaults, so the
        // master key always corresponds to the password that the old code
        // would have re-derived here (transparent pass-through).
        Some(_) => {
            if database::integrity::has_digest(&db)?
                && !database::integrity::verify_integrity(&db, mac_key.as_ref())?
            {
                tracing::error!("legacy migration blocked: stored digest does not match contents");
                return Err(VaultError::InvalidBackup(
                    "Database integrity check failed".to_string(),
                ));
            }
            tracing::info!("migrating database from legacy format");
            let steps = database::migrations::plan(
                0,
                pwdvault_infrastructure::vault_header::VAULT_FORMAT_VERSION,
            )?;
            if steps != vec![database::migrations::MigrationStep::LegacyToV1] {
                return Err(VaultError::InvalidBackup(
                    "Unsupported database migration path".to_string(),
                ));
            }
            super::super::vault::migrate_database(
                &db,
                master_key,
                enc_key.as_ref(),
                mac_key.as_ref(),
            )?;
        }
        None => return Err(VaultError::LegacyVaultRequiresMigration),
    }

    // Step 7: settings must be loadable.
    load_settings(&db)?;

    Ok((enc_key, mac_key))
}

/// Publish verified keys and run the unlock side effects (steps 8-9):
/// session unlock, rate-limit reset, auto-lock timeout application, menu and
/// activity refresh. Must only be called after verification succeeded.
pub fn complete_unlock(
    state: &Arc<AppState>,
    enc_key: SecretKey,
    mac_key: SecretKey,
) -> Result<(), VaultError> {
    // Load settings BEFORE publishing so a failure leaves the vault Locked.
    let db = get_db(state)?;
    let settings = load_settings(&db)?;

    // Step 8: atomically publish — THE LAST STEP.
    state.session.unlock(enc_key, mac_key);

    // Step 9: side effects.
    reset_rate_limit(state);
    *state.auto_lock_secs.lock().expect("timeout lock poisoned") = settings.auto_lock_secs;
    state.touch_activity();
    state.update_lock_menu("Lock Vault");
    Ok(())
}

/// Reject vaults that predate the AEAD header or have integrity enforcement
/// disabled. Bio/recovery unlock would otherwise walk straight into the
/// legacy migration branch of the verification chain.
pub(super) fn require_modern_vault(
    db: &Arc<redb::Database>,
    enc_key: &SecretKey,
) -> Result<(), VaultError> {
    let header = pwdvault_infrastructure::vault_header::load_header(db, enc_key.as_ref())?;
    match header {
        Some(h) if h.integrity_required => Ok(()),
        Some(_) | None => Err(VaultError::LegacyVaultRequiresMigration),
    }
}

// ---------------------------------------------------------------------------
// D8 re-seal plumbing
// ---------------------------------------------------------------------------

/// A blob-row mutation to apply inside the re-seal transaction (D4: the
/// digest must cover wrap blobs, so they only change via `VaultStore::write`).
pub(crate) enum BlobRewrite {
    Write { key: &'static str, blob: Vec<u8> },
    Remove { key: &'static str },
}

/// Re-encrypt an entry's inner `encrypted_password` / `encrypted_notes`
/// fields from `old_enc` to `new_enc`. The inner fields are encrypted with
/// the enc subkey, which rotates with the master key — same step as
/// `migrate_database`'s inner-field pass, here without any legacy plaintext
/// channel (a field that fails to decrypt aborts the whole re-seal).
fn reencrypt_entry_inner(
    entry: &mut database::PasswordEntry,
    old_enc: &[u8; 32],
    new_enc: &[u8; 32],
) -> Result<(), VaultError> {
    use pwdvault_infrastructure::crypto::{decrypt, encrypt, EncryptedData};

    if !entry.encrypted_password.is_empty() {
        let sealed: EncryptedData = bincode::deserialize(&entry.encrypted_password)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        let mut plain = decrypt(old_enc, &sealed)?;
        let resealed = encrypt(new_enc, &plain)?;
        plain.zeroize();
        entry.encrypted_password = bincode::serialize(&resealed)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
    }

    if let Some(notes_bytes) = entry.encrypted_notes.take() {
        let sealed: EncryptedData = bincode::deserialize(&notes_bytes)
            .or_else(|_| EncryptedData::from_bytes(&notes_bytes))
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        let mut plain = decrypt(old_enc, &sealed)?;
        let resealed = encrypt(new_enc, &plain)?;
        plain.zeroize();
        entry.encrypted_notes = Some(
            bincode::serialize(&resealed)
                .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?,
        );
    }

    Ok(())
}

/// Full vault re-seal under a new master key ("read all → re-seal → one
/// transaction").
///
/// Reads every record with `old_enc` (fail-closed runtime channel — NO legacy
/// plaintext path, unlike `migrate_database`), re-encrypts inner secret
/// fields, then replaces entries, groups, the verification row, the header
/// (same version/integrity flags, re-sealed with `new_enc`) and applies
/// `rewraps` in a single `VaultStore::write` transaction so the digest is
/// refreshed atomically with the content.
pub(super) fn reseal_vault(
    db: &Arc<redb::Database>,
    old_enc: &SecretKey,
    new_enc: &SecretKey,
    new_mac: &SecretKey,
    new_verification: &VerificationData,
    rewraps: Vec<BlobRewrite>,
) -> Result<(), VaultError> {
    // --- Full read with the old-key copy. Leases are drained at this point,
    // so no other writer can make this snapshot stale. ---
    let entry_ids = database::list_entries(db)?;
    let mut entries = Vec::with_capacity(entry_ids.len());
    for id in &entry_ids {
        if let Some(mut entry) = database::load_entry(db, old_enc.as_ref(), id, false)? {
            reencrypt_entry_inner(&mut entry, old_enc.as_ref(), new_enc.as_ref())?;
            entries.push(entry);
        }
    }
    let group_ids = database::list_groups(db)?;
    let mut groups = Vec::with_capacity(group_ids.len());
    for id in &group_ids {
        if let Some(group) = database::load_group(db, old_enc.as_ref(), id, false)? {
            groups.push(group);
        }
    }

    // Header: keep version/integrity flags, re-seal under the new key.
    let header = pwdvault_infrastructure::vault_header::load_header(db, old_enc.as_ref())?
        .ok_or_else(|| {
            VaultError::InternalError("vault header vanished during re-seal".to_string())
        })?;

    // --- Single transaction: everything or nothing. ---
    let store = VaultStore::new(db);
    store.write(new_mac.as_ref(), |txn| {
        {
            let mut t = txn.open_table(database::ENTRIES_TABLE)?;
            for id in &entry_ids {
                t.remove(id.as_str())?;
            }
        }
        for entry in &entries {
            vault_store::save_entry_in_txn(txn, new_enc.as_ref(), entry)?;
        }
        {
            let mut t = txn.open_table(database::GROUPS_TABLE)?;
            for id in &group_ids {
                t.remove(id.as_str())?;
            }
        }
        for group in &groups {
            vault_store::save_group_in_txn(txn, new_enc.as_ref(), group)?;
        }
        vault_store::save_verification_data_in_txn(txn, new_verification)?;
        pwdvault_infrastructure::vault_header::save_header_in_txn(txn, &header, new_enc.as_ref())?;
        for rewrite in &rewraps {
            match rewrite {
                BlobRewrite::Write { key, blob } => {
                    vault_store::save_blob_in_txn(txn, key, blob)?;
                }
                BlobRewrite::Remove { key } => {
                    vault_store::remove_blob_in_txn(txn, key)?;
                }
            }
        }
        Ok(())
    })?;

    tracing::info!(
        entries = entries.len(),
        groups = groups.len(),
        blobs = rewraps.len(),
        "vault re-sealed under new master key"
    );
    Ok(())
}

/// Derive fresh KDF params + salt + master/subkeys for a new password.
/// `AdaptiveParams::adaptive` re-benchmarks the machine; its starting point
/// is clamped to the X6 import floor, so a password change is the natural
/// moment weak historical parameters get healed.
pub(super) struct NewKeys {
    pub(super) verification: VerificationData,
    pub(super) master: Zeroizing<[u8; 32]>,
    pub(super) enc: SecretKey,
    pub(super) mac: SecretKey,
}

pub(super) fn derive_new_keys(new_password: &str) -> Result<NewKeys, VaultError> {
    let params = crypto::kdf::AdaptiveParams::adaptive(500);
    let salt = crypto::kdf::generate_salt();
    let (master_key, _) = crypto::kdf::derive_key_with_params(new_password, &salt, &params)?;
    let master = Zeroizing::new(master_key);
    let verification = create_verification_header(&master, salt, params)?;
    let (enc, mac) = crypto::kdf::derive_subkeys(&master, &salt);
    Ok(NewKeys {
        verification,
        master,
        enc: SecretKey::new(enc),
        mac: SecretKey::new(mac),
    })
}

/// Collect the re-wrap mutations for any enabled bio/recovery credential and
/// verify each input against the stored blob BEFORE any DB write (D8 step 1).
///
/// - bio: prefer the session-cached wrap key (Touch ID unlock session); read
///   it from the credential store otherwise (may prompt once — the UI must
///   announce this, D5).
/// - recovery: the paste is mandatory and must unwrap the existing blob.
pub(super) fn collect_rewraps(
    state: &Arc<AppState>,
    db: &Arc<redb::Database>,
    new_master: &[u8; 32],
    recovery_key: Option<&str>,
) -> Result<Vec<BlobRewrite>, VaultError> {
    let mut rewraps = Vec::new();

    if let Some(blob) = vault_store::load_blob(db, BIO_WRAP_BLOB_KEY)? {
        let wrap_key: [u8; 32] = match state.session.cached_wrap_key() {
            Some(key) => key,
            None => match state.secret_store.get(BIO_WRAP_ACCOUNT) {
                Ok(bytes) => bytes.try_into().map_err(|_| VaultError::WrapBlobCorrupt)?,
                Err(SecretStoreError::NotFound) => {
                    return Err(VaultError::KeychainError(
                        BIO_KEYCHAIN_MISSING_GUIDANCE.to_string(),
                    ));
                }
                Err(SecretStoreError::UserCancelled) => return Err(VaultError::BiometricCancelled),
                Err(SecretStoreError::LockedOut) => return Err(VaultError::BiometricLockedOut),
                Err(SecretStoreError::Unavailable(e)) => return Err(VaultError::KeychainError(e)),
            },
        };
        // Prove the wrap key still matches the stored blob before replacing
        // it — a stale keychain item must abort the change, not strand an
        // undecryptable blob.
        unwrap_secret(&wrap_key, &blob, WRAP_AAD_BIO)?;
        rewraps.push(BlobRewrite::Write {
            key: BIO_WRAP_BLOB_KEY,
            blob: wrap_secret(&wrap_key, new_master, WRAP_AAD_BIO)?,
        });
    }

    if let Some(blob) = vault_store::load_blob(db, RECOVERY_WRAP_BLOB_KEY)? {
        let paste = recovery_key.ok_or(VaultError::InvalidInput {
            code: "RECOVERY_KEY_REQUIRED".to_string(),
            message:
                "Recovery key is required to change the master password while recovery is enabled"
                    .to_string(),
        })?;
        let wrap_key = recovery_wrap_key(paste)?;
        // Correctness proof: only the true recovery key opens the blob.
        unwrap_secret(&wrap_key, &blob, WRAP_AAD_RECOVERY)
            .map_err(|_| VaultError::RecoveryKeyInvalid)?;
        rewraps.push(BlobRewrite::Write {
            key: RECOVERY_WRAP_BLOB_KEY,
            blob: wrap_secret(&wrap_key, new_master, WRAP_AAD_RECOVERY)?,
        });
    }

    Ok(rewraps)
}
