//! Touch ID (biometric) unlock and recovery-key credential management,
//! sharing the wrap-blob infrastructure (D4-D7).

use std::sync::Arc;
use zeroize::Zeroizing;

use crate::{AppState, VaultError};
use pwdvault_domain::BiometricStatus;
use pwdvault_infrastructure::crypto::{
    self, generate_recovery_key, generate_wrap_key, recovery_wrap_key, unwrap_secret, wrap_secret,
    SecretKey, WRAP_AAD_BIO, WRAP_AAD_RECOVERY,
};
use pwdvault_infrastructure::database::vault_store::{self, VaultStore};
use pwdvault_infrastructure::keychain::{SecretStore, SecretStoreError, BIO_WRAP_ACCOUNT};

use super::super::vault::{check_rate_limit, get_db, record_failed_attempt};
use super::shared::{
    complete_unlock, current_verification, derive_master_for_unlock, require_modern_vault,
    verify_master_and_integrity, BIO_WRAP_BLOB_KEY, RECOVERY_WRAP_BLOB_KEY,
};

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
