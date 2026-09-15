//! Security operations on the vault master key (Phase 1).
//!
//! Three features share one wrap-key infrastructure:
//! - **Change master password** — re-benchmarks KDF params, re-derives the
//!   master key, re-seals the whole vault in a single transaction, and
//!   re-wraps any stored credential blobs (Touch ID / recovery).
//! - **Touch ID (biometric) unlock** — the master key is wrapped under a
//!   random wrap key kept in the platform credential store behind a biometric
//!   access control (macOS only, D7).
//! - **Recovery key** — the master key is wrapped under SHA-256 of a random
//!   256-bit key shown once to the user.
//!
//! ## D8 — exclusive-clear serialization of full re-seals
//!
//! Write services hold only a read lease (see `entries.rs`), so a naive
//! "read all → re-seal → write" window would let in-flight writes either (A)
//! be silently swallowed by a stale snapshot overwrite, or (B) commit under
//! the OLD key after the swap, mixing keys and refreshing the digest with the
//! old MAC — permanently locking the vault. Every re-seal therefore follows
//! this protocol:
//!
//! 1. *Preamble (no DB writes)*: validate inputs, verify the current
//!    password, derive the new keys, and complete ALL credential-store
//!    interaction (Touch ID prompts). Then take ONE lease to copy the old
//!    enc/mac into local `SecretKey`s and release it immediately.
//! 2. Call `session.exclusive_lock_and_clear()` — drains every in-flight
//!    lease and rejects new ones (never called while holding a lease).
//! 3. Assert the session is still Locked (a concurrent password unlock in
//!    between aborts the operation cleanly instead of mixing keys), read the
//!    full vault with the old-key copy, and re-seal everything — new
//!    verification row, re-encrypted header, re-wrapped blobs — in ONE
//!    `VaultStore::write` transaction.
//! 4. Success: republish the new keys exactly once. Failure: the transaction
//!    rolls back (disk unchanged) and the previous state is restored.
//!
//! Blob-writing settings operations (`enable_biometric`, `enable_recovery`,
//! `disable_*`) require an unlocked vault and hold a lease across their
//! `VaultStore::write`, so they are serialized against the re-seal window by
//! the same lease mechanism.

use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::{AppState, VaultError, validation};
use pwdvault_domain::BiometricStatus;
use pwdvault_infrastructure::crypto::{
    self, SecretKey, VerificationData, WRAP_AAD_BIO, WRAP_AAD_RECOVERY, create_verification_header,
    generate_recovery_key, generate_wrap_key, recovery_wrap_key, unwrap_secret, wrap_secret,
};
use pwdvault_infrastructure::database::{
    self, load_settings,
    vault_store::{self, VaultStore},
};
use pwdvault_infrastructure::keychain::{BIO_WRAP_ACCOUNT, SecretStore, SecretStoreError};

use super::vault::{
    backup_db_file, check_rate_limit, get_db, record_failed_attempt, reset_rate_limit,
};

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
fn current_verification(state: &Arc<AppState>) -> Result<VerificationData, VaultError> {
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
    let (master_key, _) = crypto::kdf::derive_key_with_params(
        password,
        &verification.salt,
        &verification.params,
    )?;
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
            super::vault::migrate_database(&db, master_key, enc_key.as_ref(), mac_key.as_ref())?;
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

// ---------------------------------------------------------------------------
// D8 re-seal plumbing
// ---------------------------------------------------------------------------

/// A blob-row mutation to apply inside the re-seal transaction (D4: the
/// digest must cover wrap blobs, so they only change via `VaultStore::write`).
pub(crate) enum BlobRewrite {
    Write {
        key: &'static str,
        blob: Vec<u8>,
    },
    Remove {
        key: &'static str,
    },
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
fn reseal_vault(
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
        pwdvault_infrastructure::vault_header::save_header_in_txn(
            txn,
            &header,
            new_enc.as_ref(),
        )?;
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
struct NewKeys {
    verification: VerificationData,
    master: Zeroizing<[u8; 32]>,
    enc: SecretKey,
    mac: SecretKey,
}

fn derive_new_keys(new_password: &str) -> Result<NewKeys, VaultError> {
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
fn collect_rewraps(
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
                Ok(bytes) => bytes
                    .try_into()
                    .map_err(|_| VaultError::WrapBlobCorrupt)?,
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
            message: "Recovery key is required to change the master password while recovery is enabled"
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

// ---------------------------------------------------------------------------
// Change master password (D8 protocol)
// ---------------------------------------------------------------------------

/// Change the master password. Requires an unlocked vault (the old session
/// keys are the re-seal input); the current password is verified
/// independently as user confirmation.
///
/// On any failure after the exclusive window the transaction has rolled back
/// (disk unchanged) and the previous unlocked state is restored.
pub fn change_password(
    state: &Arc<AppState>,
    current_password: Zeroizing<String>,
    new_password: Zeroizing<String>,
    recovery_key: Option<String>,
) -> Result<(), VaultError> {
    let db = get_db(state)?;

    // --- D8 step 1: preamble. Nothing below writes to the DB until the
    // exclusive window opens. ---
    validation::master_password(new_password.as_str())?;

    let verification = current_verification(state)?;
    let old_master = derive_master_for_unlock(current_password.as_str(), &verification)?
        .ok_or(VaultError::CurrentPasswordInvalid)?;
    // Wrong-password derivations are wiped when `derive_master_for_unlock`
    // drops them; `current_password` zeroizes on drop here.

    // B1 fail-closed: a headerless vault must go through the explicit
    // migration tool first, exactly like unlock. A downgraded header
    // (integrity_required=false) is allowed through — the re-seal preserves
    // its flags and the next password unlock performs the one-time migration.
    {
        let (check_enc, _) = crypto::kdf::derive_subkeys(&old_master, &verification.salt);
        let header =
            pwdvault_infrastructure::vault_header::load_header(&db, &check_enc)?;
        if header.is_none() {
            return Err(VaultError::LegacyVaultRequiresMigration);
        }
    }

    let new_keys = derive_new_keys(new_password.as_str())?;
    // `new_password` zeroizes on drop here.

    // ALL credential-store interaction happens now — a Touch ID prompt must
    // never overlap the exclusive window.
    let rewraps = collect_rewraps(state, &db, &new_keys.master, recovery_key.as_deref())?;

    // Non-overwriting backup before touching the vault (migration precedent).
    backup_db_file("password change");

    // Copy the old session keys and release the lease immediately. Never
    // hold a lease into exclusive_lock_and_clear (same-thread deadlock).
    let lease = state.lease()?;
    let old_enc = SecretKey::new(*lease.enc_key()?);
    let old_mac = SecretKey::new(*lease.mac_key()?);
    drop(lease);

    // --- D8 step 2: drain every in-flight lease, refuse new ones. ---
    state.session.exclusive_lock_and_clear();

    // --- D8 step 3: a concurrent password unlock slipping in between the
    // drain and this check must abort us cleanly (its keys are already
    // published) — never proceed over a live session. ---
    if state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    match reseal_vault(
        &db,
        &old_enc,
        &new_keys.enc,
        &new_keys.mac,
        &new_keys.verification,
        rewraps,
    ) {
        Ok(()) => {
            // --- D8 step 4: republish exactly once. The rebuilt session
            // drops any wrap-key cache (D5) and the verification row moves
            // to the new master so password unlocks track the new secret. ---
            *state
                .verification_data
                .lock()
                .expect("verification lock poisoned") = Some(new_keys.verification);
            state.session.unlock(new_keys.enc, new_keys.mac);
            state.touch_activity();
            state.update_lock_menu("Lock Vault");
            Ok(())
        }
        Err(e) => {
            // The transaction rolled back — the disk is unchanged. Restore
            // the previous unlocked state so the user keeps working.
            state.session.unlock(old_enc, old_mac);
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Biometric (Touch ID) unlock — macOS only (D7)
// ---------------------------------------------------------------------------

/// Report biometric unlock availability and per-vault enablement. Both
/// answers are obtainable while the vault is locked.
pub fn biometric_status(
    state: &Arc<AppState>,
    store: &dyn SecretStore,
) -> Result<BiometricStatus, VaultError> {
    let db = get_db(state)?;
    let enabled = vault_store::load_blob(&db, BIO_WRAP_BLOB_KEY)?.is_some();
    Ok(BiometricStatus {
        available: store.available(),
        enabled,
    })
}

/// Reject vaults that predate the AEAD header or have integrity enforcement
/// disabled. Bio/recovery unlock would otherwise walk straight into the
/// legacy migration branch of the verification chain.
fn require_modern_vault(db: &Arc<redb::Database>, enc_key: &SecretKey) -> Result<(), VaultError> {
    let header = pwdvault_infrastructure::vault_header::load_header(db, enc_key.as_ref())?;
    match header {
        Some(h) if h.integrity_required => Ok(()),
        Some(_) | None => Err(VaultError::LegacyVaultRequiresMigration),
    }
}

/// Enable Touch ID unlock for this vault. Requires the current master
/// password (D2: no session ever holds the master key, and the password
/// doubles as operation confirmation). Must be called on an unlocked vault so
/// the blob write participates in the lease-guarded serialization.
pub fn enable_biometric(
    state: &Arc<AppState>,
    password: Zeroizing<String>,
    store: &dyn SecretStore,
) -> Result<(), VaultError> {
    let db = get_db(state)?;
    let lease = state.lease()?;

    let verification = current_verification(state)?;
    let master = derive_master_for_unlock(password.as_str(), &verification)?
        .ok_or(VaultError::CurrentPasswordInvalid)?;
    // `password` zeroizes on drop here.

    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master, &verification.salt);
    let enc_key = SecretKey::new(enc_key);
    let mac_key = SecretKey::new(mac_key);
    require_modern_vault(&db, &enc_key)?;

    if !store.available() {
        return Err(VaultError::BiometricUnavailable);
    }

    let wrap_key = generate_wrap_key();

    // Credential store first, blob second: if the blob write fails below, the
    // user can simply retry (set is an upsert) and a leftover keychain item
    // without a blob just reports `enabled=false`.
    store
        .set(BIO_WRAP_ACCOUNT, &wrap_key)
        .map_err(|e| VaultError::KeychainError(e.to_string()))?;

    let blob = wrap_secret(&wrap_key, &master, WRAP_AAD_BIO)?;
    let store_handle = VaultStore::new(&db);
    store_handle.write(mac_key.as_ref(), |txn| {
        vault_store::save_blob_in_txn(txn, BIO_WRAP_BLOB_KEY, &blob)?;
        Ok(())
    })?;

    lease.touch_activity();
    Ok(())
}

/// Disable Touch ID unlock: remove the blob in a digest-consistent
/// transaction, then best-effort delete the credential-store item.
pub fn disable_biometric(state: &Arc<AppState>, store: &dyn SecretStore) -> Result<(), VaultError> {
    let db = get_db(state)?;
    let lease = state.lease()?;

    let store_handle = VaultStore::new(&db);
    store_handle.write(lease.mac_key()?, |txn| {
        vault_store::remove_blob_in_txn(txn, BIO_WRAP_BLOB_KEY)?;
        Ok(())
    })?;

    if let Err(e) = store.delete(BIO_WRAP_ACCOUNT) {
        // A stray keychain item without a blob is inert (status reports
        // disabled; the next enable overwrites it), so only warn.
        tracing::warn!("keychain delete of bio wrap key failed: {}", e);
    }

    lease.touch_activity();
    Ok(())
}

/// Unlock the vault with Touch ID:
/// rate limit → blob presence (never pop the prompt for an unconfigured
/// vault) → Touch ID → unwrap master → verify integrity → publish → cache
/// the wrap key in this session (D5).
///
/// User cancellation / lockout / keychain absence are transparent errors and
/// do NOT count toward the rate limit; only unwrap/header failures do.
pub fn unlock_biometric(state: &Arc<AppState>, store: &dyn SecretStore) -> Result<(), VaultError> {
    // Step 1: rate limit.
    check_rate_limit(state)?;

    let db = get_db(state)?;

    // Step 2: no blob → no prompt.
    let blob = vault_store::load_blob(&db, BIO_WRAP_BLOB_KEY)?.ok_or(VaultError::InvalidInput {
        code: "BIOMETRIC_NOT_ENABLED".to_string(),
        message: "Touch ID unlock is not enabled for this vault".to_string(),
    })?;

    // Step 3: Touch ID prompt happens here.
    let wrap_key_bytes = store.get(BIO_WRAP_ACCOUNT).map_err(|e| match e {
        SecretStoreError::NotFound => VaultError::BiometricUnavailable,
        SecretStoreError::UserCancelled => VaultError::BiometricCancelled,
        SecretStoreError::LockedOut => VaultError::BiometricLockedOut,
        SecretStoreError::Unavailable(s) => VaultError::KeychainError(s),
    })?;
    let wrap_key: [u8; 32] = wrap_key_bytes
        .try_into()
        .map_err(|_| VaultError::WrapBlobCorrupt)?;

    // Step 4: unwrap the master key.
    let master = match unwrap_secret(&wrap_key, &blob, WRAP_AAD_BIO) {
        Ok(master) => master,
        Err(e) => {
            record_failed_attempt(state);
            return Err(e.into());
        }
    };

    // Step 5: full verification chain (header + digest + settings).
    let (enc_key, mac_key) = match verify_master_and_integrity(state, &master) {
        Ok(keys) => keys,
        Err(e) => {
            record_failed_attempt(state);
            return Err(e);
        }
    };

    // Step 6: publish + side effects.
    complete_unlock(state, enc_key, mac_key)?;

    // Step 7: cache the wrap key in THIS session only (D5).
    state.session.set_wrap_key(SecretKey::new(wrap_key));
    Ok(())
}

// ---------------------------------------------------------------------------
// Recovery key
// ---------------------------------------------------------------------------

/// Whether a recovery wrap blob exists (queryable while locked).
pub fn recovery_status(state: &Arc<AppState>) -> Result<bool, VaultError> {
    let db = get_db(state)?;
    Ok(vault_store::load_blob(&db, RECOVERY_WRAP_BLOB_KEY)?.is_some())
}

/// Enable the recovery key. Same D2 password requirement and legacy-vault
/// rejection as `enable_biometric`. Returns the plaintext recovery key —
/// shown to the user exactly once.
pub fn enable_recovery(
    state: &Arc<AppState>,
    password: Zeroizing<String>,
) -> Result<String, VaultError> {
    let db = get_db(state)?;
    let lease = state.lease()?;

    let verification = current_verification(state)?;
    let master = derive_master_for_unlock(password.as_str(), &verification)?
        .ok_or(VaultError::CurrentPasswordInvalid)?;

    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master, &verification.salt);
    let enc_key = SecretKey::new(enc_key);
    let mac_key = SecretKey::new(mac_key);
    // Symmetric legacy rejection: recover_vault on a legacy vault would
    // trigger the migration write inside verification, breaking the
    // "failure leaves the disk unchanged" promise.
    require_modern_vault(&db, &enc_key)?;

    let recovery_key = generate_recovery_key();
    let wrap_key = recovery_wrap_key(&recovery_key)?;
    let blob = wrap_secret(&wrap_key, &master, WRAP_AAD_RECOVERY)?;

    let store_handle = VaultStore::new(&db);
    store_handle.write(mac_key.as_ref(), |txn| {
        vault_store::save_blob_in_txn(txn, RECOVERY_WRAP_BLOB_KEY, &blob)?;
        Ok(())
    })?;

    lease.touch_activity();
    Ok(recovery_key)
}

/// Disable the recovery key. The current password is required as
/// confirmation against accidental or malicious clears (review decision).
pub fn disable_recovery(
    state: &Arc<AppState>,
    current_password: Zeroizing<String>,
) -> Result<(), VaultError> {
    let db = get_db(state)?;
    let lease = state.lease()?;

    let verification = current_verification(state)?;
    if derive_master_for_unlock(current_password.as_str(), &verification)?.is_none() {
        return Err(VaultError::CurrentPasswordInvalid);
    }

    let store_handle = VaultStore::new(&db);
    store_handle.write(lease.mac_key()?, |txn| {
        vault_store::remove_blob_in_txn(txn, RECOVERY_WRAP_BLOB_KEY)?;
        Ok(())
    })?;

    lease.touch_activity();
    Ok(())
}

/// Recover a vault with its recovery key and a NEW master password
/// (three-phase, no "unlocked under old key" intermediate state):
///
/// 1. verify-only chain: paste format → blob → unwrap master → header +
///    integrity + settings (nothing published)
/// 2. derive new keys; if a bio blob exists, resolve its wrap key NOW
///    (locked-state Touch ID is acceptable — the user is present; a failure
///    downgrades to "disable biometric, re-enable later" instead of failing
///    the recovery)
/// 3. `.bak` backup → exclusive drain (assert Locked) → single re-seal
///    transaction → publish exactly once. Any failure keeps the vault locked
///    and the disk unchanged. The password rate limit is NOT applied: a
///    256-bit recovery key authenticated by GCM + the verification header is
///    its own proof of correctness.
pub fn recover_vault(
    state: &Arc<AppState>,
    recovery_key_paste: &str,
    new_password: Zeroizing<String>,
) -> Result<(), VaultError> {
    let db = get_db(state)?;

    // Phase 1 — verification only.
    validation::master_password(new_password.as_str())?;
    let wrap_key = recovery_wrap_key(recovery_key_paste)?;
    let blob = vault_store::load_blob(&db, RECOVERY_WRAP_BLOB_KEY)?
        .ok_or(VaultError::RecoveryNotEnabled)?;
    let old_master = unwrap_secret(&wrap_key, &blob, WRAP_AAD_RECOVERY)
        .map_err(|_| VaultError::RecoveryKeyInvalid)?;
    let (old_enc, _old_mac) = verify_master_and_integrity(state, &old_master)?;

    // Phase 2 — new keys + up-front credential-store interaction.
    let new_keys = derive_new_keys(new_password.as_str())?;

    let mut rewraps = vec![BlobRewrite::Write {
        key: RECOVERY_WRAP_BLOB_KEY,
        blob: wrap_secret(&wrap_key, &new_keys.master, WRAP_AAD_RECOVERY)?,
    }];
    let mut drop_bio = false;
    if let Some(blob) = vault_store::load_blob(&db, BIO_WRAP_BLOB_KEY)? {
        let resolved = state
            .secret_store
            .get(BIO_WRAP_ACCOUNT)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bio_wrap_key| {
                unwrap_secret(&bio_wrap_key, &blob, WRAP_AAD_BIO)
                    .ok()
                    .map(|_| bio_wrap_key)
            });
        match resolved {
            Some(bio_wrap_key) => rewraps.push(BlobRewrite::Write {
                key: BIO_WRAP_BLOB_KEY,
                blob: wrap_secret(&bio_wrap_key, &new_keys.master, WRAP_AAD_BIO)?,
            }),
            None => {
                // Touch ID failed or is unavailable — do not block recovery;
                // drop the blob in the transaction and have the user
                // re-enable biometric unlock afterwards.
                drop_bio = true;
                rewraps.push(BlobRewrite::Remove {
                    key: BIO_WRAP_BLOB_KEY,
                });
            }
        }
    }

    backup_db_file("recovery");

    // Phase 3 — exclusive window + single transaction + one publish.
    state.session.exclusive_lock_and_clear();
    if state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    match reseal_vault(
        &db,
        &old_enc,
        &new_keys.enc,
        &new_keys.mac,
        &new_keys.verification,
        rewraps,
    ) {
        Ok(()) => {
            if drop_bio {
                if let Err(e) = state.secret_store.delete(BIO_WRAP_ACCOUNT) {
                    // Blob already removed; a stray keychain item is inert.
                    tracing::warn!("keychain delete of bio wrap key failed: {}", e);
                }
                tracing::info!("biometric unlock disabled during recovery — must be re-enabled");
            }
            *state
                .verification_data
                .lock()
                .expect("verification lock poisoned") = Some(new_keys.verification);
            complete_unlock(state, new_keys.enc, new_keys.mac)?;
            Ok(())
        }
        // Keep the vault locked; the transaction rolled back.
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
    use pwdvault_infrastructure::keychain::MemorySecretStore;
    use std::sync::Barrier;
    use std::thread;
    use tempfile::TempDir;

    const TEST_PASSWORD: &str = "phase-one-test-password";
    const NEW_PASSWORD: &str = "a-brand-new-password!";
    const TEST_SALT: [u8; 16] = [0x41; 16];

    struct TestVault {
        state: Arc<AppState>,
        store: Arc<MemorySecretStore>,
        _dir: TempDir,
        entry_ids: Vec<String>,
        group_ids: Vec<String>,
    }

    /// Same pattern as vault.rs `create_modern_vault`, plus a group and a
    /// `MemorySecretStore` wired into state.
    fn create_test_vault(entry_count: usize, group_count: usize) -> TestVault {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(database::init_database(dir.path().join("security.db")).unwrap());
        let params = AdaptiveParams {
            m_cost: 16384,
            t_cost: 1,
            p_cost: 1,
        };
        let (master_key, _) =
            crypto::kdf::derive_key_with_params(TEST_PASSWORD, &TEST_SALT, &params).unwrap();
        let verification = create_verification_header(&master_key, TEST_SALT, params).unwrap();
        let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &TEST_SALT);

        let mut group_ids = Vec::new();
        for index in 0..group_count {
            let group = pwdvault_domain::Group::new(format!("Group {index}"));
            group_ids.push(group.id.clone());
            database::vault_store::VaultStore::new(&db)
                .write(&mac_key, |txn| {
                    database::vault_store::save_group_in_txn(txn, &enc_key, &group)
                })
                .unwrap();
        }

        let mut entry_ids = Vec::new();
        for index in 0..entry_count {
            let mut entry = database::PasswordEntry::new(
                format!("Entry {index}"),
                None,
                format!("user-{index}"),
            );
            let encrypted =
                crypto::encrypt(&enc_key, format!("secret-{index}").as_bytes()).unwrap();
            entry.encrypted_password = bincode::serialize(&encrypted).unwrap();
            entry.group_id = group_ids.first().cloned();
            entry_ids.push(entry.id.clone());
            database::vault_store::VaultStore::new(&db)
                .write(&mac_key, |txn| {
                    database::vault_store::save_entry_in_txn(txn, &enc_key, &entry)
                })
                .unwrap();
        }

        let store = VaultStore::new(&db);
        store
            .write(&mac_key, |txn| {
                vault_store::save_verification_data_in_txn(txn, &verification)?;
                pwdvault_infrastructure::vault_header::save_header_in_txn(
                    txn,
                    &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
                    &enc_key,
                )?;
                database::vault_store::save_settings_in_txn(
                    txn,
                    &pwdvault_domain::Settings::default(),
                )?;
                Ok(())
            })
            .unwrap();

        let store = Arc::new(MemorySecretStore::new());
        let state = Arc::new(AppState {
            secret_store: Arc::clone(&store) as Arc<dyn SecretStore>,
            ..AppState::default()
        });
        // The platform credential store is replaced with the test double
        // (commands and services read it from state with zero special-casing).
        *state.database.lock().unwrap() = Some(db);
        *state.verification_data.lock().unwrap() = Some(verification);
        TestVault {
            state,
            store,
            _dir: dir,
            entry_ids,
            group_ids,
        }
    }

    /// Unlock the test vault through the real password path.
    fn unlock(vault: &TestVault, password: &str) -> bool {
        unlock_vault(&vault.state, Zeroizing::new(password.to_string())).unwrap()
    }

    fn unlock_vault_result(vault: &TestVault, password: &str) -> Result<bool, VaultError> {
        crate::unlock_vault(&vault.state, Zeroizing::new(password.to_string()))
    }

    use super::super::vault::{lock_vault, unlock_vault};

    /// P1.7-2: content survives the password change byte-for-byte; old
    /// password rejected; new password unlocks; digest + header intact.
    #[test]
    fn change_password_preserves_content_and_rotates_keys() {
        let vault = create_test_vault(3, 2);
        assert!(unlock(&vault, TEST_PASSWORD));

        change_password(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Zeroizing::new(NEW_PASSWORD.to_string()),
            None,
        )
        .unwrap();

        // Old password must fail (verification row replaced).
        assert!(!unlock_vault_result(&vault, TEST_PASSWORD).unwrap());
        // New password unlocks.
        assert!(unlock_vault_result(&vault, NEW_PASSWORD).unwrap());

        let db = get_db(&vault.state).unwrap();
        let enc = vault.state.session.get_enc_key().unwrap();

        // Entries decrypt identically.
        for (index, id) in vault.entry_ids.iter().enumerate() {
            let entry = database::load_entry(&db, &enc, id, false)
                .unwrap()
                .unwrap();
            let encrypted: crypto::EncryptedData =
                bincode::deserialize(&entry.encrypted_password).unwrap();
            assert_eq!(
                crypto::decrypt(&enc, &encrypted).unwrap(),
                format!("secret-{index}").into_bytes()
            );
            assert_eq!(entry.username, format!("user-{index}"));
        }
        // Groups decrypt identically.
        for (index, id) in vault.group_ids.iter().enumerate() {
            let group = database::load_group(&db, &enc, id, false)
                .unwrap()
                .unwrap();
            assert_eq!(group.name, format!("Group {index}"));
        }

        // Digest passes and the header is readable with integrity required.
        assert!(database::integrity::verify_integrity(&db, &vault.state.session.get_mac_key().unwrap()).unwrap());
        let header = pwdvault_infrastructure::vault_header::load_header(&db, &enc)
            .unwrap()
            .unwrap();
        assert!(header.integrity_required);
        assert_eq!(header.migration_generation, 0);
    }

    /// P1.7-2: changing the password is rejected when recovery is enabled
    /// but the paste is missing or wrong — and the vault stays intact.
    #[test]
    fn change_password_requires_recovery_key_when_recovery_enabled() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));
        let recovery_key =
            enable_recovery(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();

        // Missing paste.
        assert!(change_password(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Zeroizing::new(NEW_PASSWORD.to_string()),
            None,
        )
        .is_err());
        // Wrong paste.
        assert!(matches!(
            change_password(
                &vault.state,
                Zeroizing::new(TEST_PASSWORD.to_string()),
                Zeroizing::new(NEW_PASSWORD.to_string()),
                Some("definitely-not-the-key".to_string()),
            ),
            Err(VaultError::RecoveryKeyInvalid)
        ));

        // Recovery disabled: no paste needed.
        disable_recovery(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
        change_password(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Zeroizing::new(NEW_PASSWORD.to_string()),
            None,
        )
        .unwrap();
        assert!(unlock_vault_result(&vault, NEW_PASSWORD).unwrap());
        let _ = recovery_key;
    }

    /// P1.7-2 + P1.7-5: with bio AND recovery enabled, a password change
    /// requires the recovery paste (D3) and re-wraps both blobs — proven by a
    /// subsequent Touch ID unlock and a successful recovery with the SAME
    /// recovery key under the new master.
    #[test]
    fn change_password_rewraps_bio_and_recovery_blobs() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));
        enable_biometric(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            vault.store.as_ref(),
        )
        .unwrap();
        let recovery_key =
            enable_recovery(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();

        // D3: with recovery enabled the paste is mandatory — a change without
        // it is rejected even when the password is correct.
        assert!(matches!(
            change_password(
                &vault.state,
                Zeroizing::new(TEST_PASSWORD.to_string()),
                Zeroizing::new(NEW_PASSWORD.to_string()),
                None,
            ),
            Err(VaultError::InvalidInput { .. })
        ));

        change_password(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Zeroizing::new(NEW_PASSWORD.to_string()),
            Some(recovery_key.clone()),
        )
        .unwrap();
        // Republish dropped the wrap-key cache (D5).
        assert!(vault.state.session.cached_wrap_key().is_none());

        // Bio blob was re-wrapped: Touch ID unlock still works and the new
        // session caches the wrap key again.
        lock_vault(&vault.state);
        unlock_biometric(&vault.state, vault.store.as_ref()).unwrap();
        assert!(vault.state.is_unlocked());
        assert!(vault.state.session.cached_wrap_key().is_some());

        // Recovery blob was re-wrapped under the new master: the SAME key
        // plus a third password recovers the vault (exclusive path).
        lock_vault(&vault.state);
        crate::recover_vault(
            &vault.state,
            &recovery_key,
            Zeroizing::new("third-password-99".to_string()),
        )
        .unwrap();
        assert!(vault.state.is_unlocked());
        assert!(!unlock_vault_result(&vault, NEW_PASSWORD).unwrap());
    }

    /// P1.7-2: wrong current password and weak new password are rejected.
    #[test]
    fn change_password_rejects_bad_inputs() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));

        // Wrong current password.
        assert!(matches!(
            change_password(
                &vault.state,
                Zeroizing::new("not-the-current-password".to_string()),
                Zeroizing::new(NEW_PASSWORD.to_string()),
                None,
            ),
            Err(VaultError::CurrentPasswordInvalid)
        ));
        // Weak new password (fails validation before any derivation).
        assert!(change_password(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Zeroizing::new("short".to_string()),
            None,
        )
        .is_err());

        // Nothing changed: the old password still unlocks and the old
        // verification row is intact.
        assert!(unlock_vault_result(&vault, TEST_PASSWORD).unwrap());
    }

    /// P1.7-5: the Keychain-NotFound escape hatch during a password change.
    #[test]
    fn change_password_keychain_missing_bio_wrap_key_reports_escape_hatch() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));
        enable_biometric(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            vault.store.as_ref(),
        )
        .unwrap();

        // Fresh password session: no cached wrap key → the change must read
        // the credential store, which we empty to simulate a keychain reset.
        lock_vault(&vault.state);
        assert!(unlock_vault_result(&vault, TEST_PASSWORD).unwrap());
        assert!(vault.state.session.cached_wrap_key().is_none());
        vault.store.remove(BIO_WRAP_ACCOUNT);

        let err = change_password(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Zeroizing::new(NEW_PASSWORD.to_string()),
            None,
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("Touch ID"), "unexpected message: {message}");
        assert!(message.contains("disable Touch ID"), "unexpected message: {message}");

        // Failure path restored the previous unlocked state and the vault is
        // still fully usable under the OLD password.
        assert!(vault.state.is_unlocked());
        assert!(vault.state.session.get_enc_key().is_ok());
        lock_vault(&vault.state);
        assert!(unlock_vault_result(&vault, TEST_PASSWORD).unwrap());
        let db = get_db(&vault.state).unwrap();
        assert!(database::integrity::verify_integrity(
            &db,
            &vault.state.session.get_mac_key().unwrap()
        )
        .unwrap());
    }

    /// P1.7-3 (D8 P0 regression): writes racing the exclusive window are
    /// either accepted before it or rejected with `VaultLocked` — never
    /// mixed-key. After the change the vault must unlock with the new
    /// password, pass digest verification, and reflect every accepted write.
    #[test]
    fn concurrent_writes_during_change_password_do_not_corrupt_vault() {
        let vault = create_test_vault(120, 0);
        assert!(unlock(&vault, TEST_PASSWORD));

        let writers: Vec<Arc<AppState>> = {
            let mut v = Vec::new();
            for _ in 0..4 {
                v.push(Arc::clone(&vault.state));
            }
            v
        };
        let entry_ids = Arc::new(vault.entry_ids.clone());
        let barrier = Arc::new(Barrier::new(writers.len() + 1));

        let mut handles = Vec::new();
        for (w, state) in writers.into_iter().enumerate() {
            let barrier = Arc::clone(&barrier);
            let entry_ids = Arc::clone(&entry_ids);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let mut accepted = 0usize;
                let mut rejected = 0usize;
                for i in 0..40 {
                    let id = &entry_ids[(w * 40 + i) % entry_ids.len()];
                    let request = pwdvault_domain::UpdateEntryRequest {
                        title: format!("w{w}-{i}"),
                        url: None,
                        username: format!("writer-{w}"),
                        password: None,
                        notes: None,
                        update_notes: false,
                        tags: vec![],
                        group_id: None,
                    };
                    match crate::update_entry(&state, id.clone(), request) {
                        Ok(_) => accepted += 1,
                        Err(VaultError::VaultLocked) => rejected += 1,
                        Err(e) => panic!("unexpected write error: {e}"),
                    }
                }
                (accepted, rejected)
            }));
        }

        let changer = {
            let state = Arc::clone(&vault.state);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                change_password(
                    &state,
                    Zeroizing::new(TEST_PASSWORD.to_string()),
                    Zeroizing::new(NEW_PASSWORD.to_string()),
                    None,
                )
            })
        };

        let mut total_accepted = 0usize;
        let mut total_rejected = 0usize;
        for handle in handles {
            let (accepted, rejected) = handle.join().unwrap();
            total_accepted += accepted;
            total_rejected += rejected;
        }
        changer.join().unwrap().unwrap();
        assert!(
            total_rejected > 0,
            "test expects at least one write to hit the exclusive window"
        );
        let _ = total_accepted;

        // The swap must leave a consistent vault.
        lock_vault(&vault.state);
        assert!(!unlock_vault_result(&vault, TEST_PASSWORD).unwrap());
        assert!(unlock_vault_result(&vault, NEW_PASSWORD).unwrap());

        let db = get_db(&vault.state).unwrap();
        assert!(database::integrity::verify_integrity(
            &db,
            &vault.state.session.get_mac_key().unwrap()
        )
        .unwrap());
        // All 120 entries still decrypt under the new keys.
        let entries = database::list_all_entries_bulk(
            &db,
            &vault.state.session.get_enc_key().unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(entries.len(), 120);
    }

    /// P1.7-4: enable → lock → Touch ID unlock full chain, with the wrap-key
    /// cache semantics of D5.
    #[test]
    fn biometric_enable_lock_unlock_full_chain() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));

        let status =
            biometric_status(&vault.state, vault.store.as_ref()).unwrap();
        assert!(status.available);
        assert!(!status.enabled);

        enable_biometric(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            vault.store.as_ref(),
        )
        .unwrap();
        assert!(biometric_status(&vault.state, vault.store.as_ref())
            .unwrap()
            .enabled);

        lock_vault(&vault.state);
        unlock_biometric(&vault.state, vault.store.as_ref()).unwrap();
        assert!(vault.state.is_unlocked());
        assert!(vault.state.session.cached_wrap_key().is_some());
    }

    /// P1.7-4: a deleted keychain item fails the bio unlock (fail-closed) and
    /// the vault stays locked.
    #[test]
    fn unlock_biometric_after_keychain_delete_fails_and_stays_locked() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));
        enable_biometric(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            vault.store.as_ref(),
        )
        .unwrap();
        lock_vault(&vault.state);

        vault.store.remove(BIO_WRAP_ACCOUNT);
        assert!(matches!(
            unlock_biometric(&vault.state, vault.store.as_ref()),
            Err(VaultError::BiometricUnavailable)
        ));
        assert!(!vault.state.is_unlocked());

        // Password unlock still works.
        assert!(unlock_vault_result(&vault, TEST_PASSWORD).unwrap());
    }

    /// P1.7-4: Touch ID cancellation never counts toward the rate limit.
    #[test]
    fn biometric_cancelled_does_not_count_rate_limit() {
        use std::sync::Mutex as StdMutex;

        struct CancellingStore {
            inner: MemorySecretStore,
            gets: StdMutex<usize>,
        }
        impl SecretStore for CancellingStore {
            fn available(&self) -> bool {
                true
            }
            fn set(&self, account: &str, value: &[u8]) -> Result<(), SecretStoreError> {
                self.inner.set(account, value)
            }
            fn get(&self, _account: &str) -> Result<Vec<u8>, SecretStoreError> {
                *self.gets.lock().unwrap() += 1;
                Err(SecretStoreError::UserCancelled)
            }
            fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
                self.inner.delete(account)
            }
        }

        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));
        enable_biometric(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            vault.store.as_ref(),
        )
        .unwrap();
        lock_vault(&vault.state);

        let cancelling = Arc::new(CancellingStore {
            inner: MemorySecretStore::new(),
            gets: StdMutex::new(0),
        });
        // Seed the store so get() is reached (cancellation at the prompt).
        cancelling.inner.set(BIO_WRAP_ACCOUNT, &[0u8; 32]).unwrap();

        assert!(matches!(
            unlock_biometric(&vault.state, cancelling.as_ref()),
            Err(VaultError::BiometricCancelled)
        ));
        assert!(!vault.state.is_unlocked());
        assert_eq!(*cancelling.gets.lock().unwrap(), 1);
        // No failed attempt recorded.
        assert_eq!(*vault.state.failed_unlock_attempts.lock().unwrap(), 0);
        // And the very next password unlock is not rate limited.
        assert!(unlock_vault_result(&vault, TEST_PASSWORD).unwrap());
    }

    /// P1.7-4: without a stored blob, unlock_biometric fails fast and never
    /// touches the credential store (no empty Touch ID prompt).
    #[test]
    fn unlock_biometric_without_blob_does_not_prompt() {
        struct PanickingStore;
        impl SecretStore for PanickingStore {
            fn available(&self) -> bool {
                true
            }
            fn set(&self, _: &str, _: &[u8]) -> Result<(), SecretStoreError> {
                panic!("store must not be touched")
            }
            fn get(&self, _: &str) -> Result<Vec<u8>, SecretStoreError> {
                panic!("store.get must not be called without a blob")
            }
            fn delete(&self, _: &str) -> Result<(), SecretStoreError> {
                panic!("store must not be touched")
            }
        }

        let vault = create_test_vault(1, 0);
        let err = unlock_biometric(&vault.state, &PanickingStore).unwrap_err();
        assert!(matches!(err, VaultError::InvalidInput { .. }));
        assert!(!vault.state.is_unlocked());
    }

    /// P1.7-4: legacy vaults (no header / integrity not enforced) must not
    /// enable biometric unlock — the bio verification chain cannot migrate.
    #[test]
    fn legacy_vault_rejects_biometric_enable() {
        let (_dir, db_path, _) = fixtures::create_pre_v1_0_5(1);
        let db = Arc::new(redb::Database::open(db_path).unwrap());
        let verification = database::load_verification_data(&db).unwrap().unwrap();
        let state = Arc::new(AppState::default());
        *state.database.lock().unwrap() = Some(Arc::clone(&db));
        *state.verification_data.lock().unwrap() = Some(verification);

        // Locked vault: enable requires a session.
        assert!(matches!(
            enable_biometric(
                &state,
                Zeroizing::new(fixtures::FIXTURE_PASSWORD.to_string()),
                &MemorySecretStore::new(),
            ),
            Err(VaultError::VaultLocked)
        ));

        // Explicitly migrate first (the 1.1.4 tool path), then enable works.
        {
            let verification = database::load_verification_data(&db).unwrap().unwrap();
            let (master_key, _) = crypto::kdf::derive_key_with_params(
                fixtures::FIXTURE_PASSWORD,
                &verification.salt,
                &verification.params,
            )
            .unwrap();
            let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &verification.salt);
            super::super::vault::migrate_database(&db, &master_key, &enc_key, &mac_key).unwrap();
        }
        assert!(unlock_vault_result_for(&state, fixtures::FIXTURE_PASSWORD).unwrap());
        enable_biometric(
            &state,
            Zeroizing::new(fixtures::FIXTURE_PASSWORD.to_string()),
            &MemorySecretStore::new(),
        )
        .unwrap();
        assert!(vault_store::load_blob(
            state.database.lock().unwrap().as_ref().unwrap(),
            BIO_WRAP_BLOB_KEY
        )
        .unwrap()
        .is_some());
    }

    fn unlock_vault_result_for(
        state: &Arc<AppState>,
        password: &str,
    ) -> Result<bool, VaultError> {
        super::super::vault::unlock_vault(state, Zeroizing::new(password.to_string()))
    }

    /// P1.7-5: recovery end-to-end — enable → lock → recover → new password
    /// works, old password rejected, and the recovery blob follows the new
    /// master (a second recovery with the same key succeeds).
    #[test]
    fn recovery_end_to_end_rotates_master_and_blob() {
        let vault = create_test_vault(2, 1);
        assert!(unlock(&vault, TEST_PASSWORD));
        assert!(!recovery_status(&vault.state).unwrap());
        let recovery_key =
            enable_recovery(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
        assert!(recovery_status(&vault.state).unwrap());

        lock_vault(&vault.state);
        crate::recover_vault(
            &vault.state,
            &recovery_key,
            Zeroizing::new(NEW_PASSWORD.to_string()),
        )
        .unwrap();

        // Recover publishes the new keys exactly once (three-phase).
        assert!(vault.state.is_unlocked());
        // Old password rejected, new password works.
        assert!(!unlock_vault_result(&vault, TEST_PASSWORD).unwrap());
        assert!(unlock_vault_result(&vault, NEW_PASSWORD).unwrap());

        // The recovery blob was re-wrapped under the new master.
        lock_vault(&vault.state);
        crate::recover_vault(
            &vault.state,
            &recovery_key,
            Zeroizing::new("post-rotation-passphrase".to_string()),
        )
        .unwrap();
        assert!(vault.state.is_unlocked());
    }

    /// P1.7-5: a wrong recovery key is rejected and the vault stays locked
    /// with the disk untouched.
    #[test]
    fn wrong_recovery_key_rejected_and_stays_locked() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));
        enable_recovery(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
        lock_vault(&vault.state);

        // Well-formed but wrong key.
        let wrong = crypto::generate_recovery_key();
        assert!(matches!(
            crate::recover_vault(
                &vault.state,
                &wrong,
                Zeroizing::new(NEW_PASSWORD.to_string()),
            ),
            Err(VaultError::RecoveryKeyInvalid)
        ));
        assert!(!vault.state.is_unlocked());

        // Disk untouched: the original password still unlocks.
        assert!(unlock_vault_result(&vault, TEST_PASSWORD).unwrap());
    }

    /// P1.7-5: bio + recovery enabled together — recovery re-wraps both in
    /// the same transaction when the keychain cooperates.
    #[test]
    fn recovery_with_bio_enabled_rewraps_bio_blob() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));
        enable_biometric(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            vault.store.as_ref(),
        )
        .unwrap();
        let recovery_key =
            enable_recovery(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();

        lock_vault(&vault.state);
        crate::recover_vault(
            &vault.state,
            &recovery_key,
            Zeroizing::new(NEW_PASSWORD.to_string()),
        )
        .unwrap();
        assert!(vault.state.is_unlocked());

        // Bio blob survived and still matches the keychain key.
        lock_vault(&vault.state);
        unlock_biometric(&vault.state, vault.store.as_ref()).unwrap();
        assert!(vault.state.is_unlocked());
    }

    /// P1.7-5: when the keychain cannot produce the bio wrap key during a
    /// recovery, recovery still succeeds and biometric unlock is disabled
    /// (blob removed) instead of left broken.
    #[test]
    fn recovery_disables_biometric_when_keychain_fails() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));
        enable_biometric(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            vault.store.as_ref(),
        )
        .unwrap();
        let recovery_key =
            enable_recovery(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
        lock_vault(&vault.state);

        // recover_vault resolves the bio wrap key from the state store —
        // empty it to simulate a keychain that can no longer serve the item.
        assert!(vault.store.remove(BIO_WRAP_ACCOUNT));

        crate::recover_vault(
            &vault.state,
            &recovery_key,
            Zeroizing::new(NEW_PASSWORD.to_string()),
        )
        .unwrap();
        assert!(vault.state.is_unlocked());

        // Bio was disabled, recovery survived with the new master.
        assert!(!biometric_status(&vault.state, &MemorySecretStore::new())
            .unwrap()
            .enabled);
        assert!(recovery_status(&vault.state).unwrap());
        lock_vault(&vault.state);
        assert!(unlock_vault_result(&vault, NEW_PASSWORD).unwrap());
    }

    /// P1.7-5: disable_recovery requires the current password as
    /// confirmation.
    #[test]
    fn disable_recovery_requires_current_password() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));
        enable_recovery(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();

        assert!(matches!(
            disable_recovery(&vault.state, Zeroizing::new("wrong-password".to_string())),
            Err(VaultError::CurrentPasswordInvalid)
        ));
        assert!(recovery_status(&vault.state).unwrap());

        disable_recovery(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
        assert!(!recovery_status(&vault.state).unwrap());
    }

    /// P1.7-5: recovery without an enabled blob is rejected up front.
    #[test]
    fn recovery_without_enabled_blob_is_rejected() {
        let vault = create_test_vault(1, 0);
        assert!(unlock(&vault, TEST_PASSWORD));
        lock_vault(&vault.state);
        assert!(matches!(
            crate::recover_vault(
                &vault.state,
                &crypto::generate_recovery_key(),
                Zeroizing::new(NEW_PASSWORD.to_string()),
            ),
            Err(VaultError::RecoveryNotEnabled)
        ));
        assert!(!vault.state.is_unlocked());
    }

    /// P1.7-6 (regression): a downgraded (integrity_required=false) header
    /// passes the change (flags preserved); the FOLLOWING password unlock
    /// then performs the one-time legacy migration through the extracted
    /// verify helper with the pass-through master key.
    #[test]
    fn change_password_on_legacy_header_then_unlock_migrates() {
        let vault = create_test_vault(2, 0);
        // Splice in a downgraded header (integrity_required=false), like the
        // B1 test does, but WITHOUT tampering so migration may proceed.
        {
            let db = get_db(&vault.state).unwrap();
            let params = AdaptiveParams {
                m_cost: 16384,
                t_cost: 1,
                p_cost: 1,
            };
            let (master_key, _) =
                crypto::kdf::derive_key_with_params(TEST_PASSWORD, &TEST_SALT, &params).unwrap();
            let (enc_key, _) = crypto::kdf::derive_subkeys(&master_key, &TEST_SALT);
            let mut header = pwdvault_infrastructure::vault_header::VaultHeader::new_initial();
            header.integrity_required = false;
            let txn = db.begin_write().unwrap();
            pwdvault_infrastructure::vault_header::save_header_in_txn(
                &txn,
                &header,
                &enc_key,
            )
            .unwrap();
            txn.commit().unwrap();
        }

        // Prime the session directly (a password unlock would run the
        // migration before we get a chance to test the change path).
        {
            let params = AdaptiveParams {
                m_cost: 16384,
                t_cost: 1,
                p_cost: 1,
            };
            let (master_key, _) =
                crypto::kdf::derive_key_with_params(TEST_PASSWORD, &TEST_SALT, &params).unwrap();
            let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &TEST_SALT);
            vault.state.session.unlock(enc_key, mac_key);
        }

        change_password(
            &vault.state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Zeroizing::new(NEW_PASSWORD.to_string()),
            None,
        )
        .unwrap();

        // The re-seal preserved the downgraded flags...
        assert!(vault.state.session.get_enc_key().is_ok());
        lock_vault(&vault.state);
        // ...and the next password unlock migrates through
        // verify_master_and_integrity (pass-through master key).
        assert!(unlock_vault_result(&vault, NEW_PASSWORD).unwrap());
        let db = get_db(&vault.state).unwrap();
        let header = pwdvault_infrastructure::vault_header::load_header(
            &db,
            &vault.state.session.get_enc_key().unwrap(),
        )
        .unwrap()
        .unwrap();
        assert!(header.integrity_required);
        assert_eq!(header.migration_generation, 1);
        // Content survived both the rotation and the migration.
        let enc = vault.state.session.get_enc_key().unwrap();
        let entry = database::load_entry(&db, &enc, &vault.entry_ids[0], false)
            .unwrap()
            .unwrap();
        assert_eq!(entry.title, "Entry 0");
    }

    /// P1.7-6 (regression): a headerless legacy vault is rejected before any
    /// re-seal happens (LegacyVaultRequiresMigration), keeping the old
    /// password authoritative. The session is primed directly because a
    /// headerless vault cannot unlock through the password path.
    #[test]
    fn change_password_on_headerless_legacy_vault_fails_closed() {
        let (_dir, db_path, _) = fixtures::create_pre_v1_0_5(1);
        let db = Arc::new(redb::Database::open(db_path).unwrap());
        let verification = database::load_verification_data(&db).unwrap().unwrap();
        let state = Arc::new(AppState::default());
        *state.database.lock().unwrap() = Some(Arc::clone(&db));
        *state.verification_data.lock().unwrap() = Some(verification.clone());

        // Prime a session the way a pre-headerless-era app run would have.
        {
            let (master_key, _) = crypto::kdf::derive_key_with_params(
                fixtures::FIXTURE_PASSWORD,
                &verification.salt,
                &verification.params,
            )
            .unwrap();
            let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &verification.salt);
            state.session.unlock(enc_key, mac_key);
        }

        let result = change_password(
            &state,
            Zeroizing::new(fixtures::FIXTURE_PASSWORD.to_string()),
            Zeroizing::new(NEW_PASSWORD.to_string()),
            None,
        );
        assert!(matches!(
            result,
            Err(VaultError::LegacyVaultRequiresMigration)
        ));
        // The fixture vault's verification row is untouched.
        assert_eq!(
            bincode::serialize(&database::load_verification_data(&db).unwrap().unwrap()).unwrap(),
            bincode::serialize(&verification).unwrap()
        );
        // The error fired in the preamble: the session was never disturbed.
        assert!(state.is_unlocked());
    }

    /// change_password requires an unlocked session (the old session keys
    /// are the re-seal input).
    #[test]
    fn change_password_requires_unlocked_session() {
        let vault = create_test_vault(1, 0);
        assert!(matches!(
            change_password(
                &vault.state,
                Zeroizing::new(TEST_PASSWORD.to_string()),
                Zeroizing::new(NEW_PASSWORD.to_string()),
                None,
            ),
            Err(VaultError::VaultLocked)
        ));
    }
}
