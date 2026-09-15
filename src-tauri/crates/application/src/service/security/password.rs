//! Master password change and vault recovery — the two D8 exclusive-clear
//! full re-seal flows.

use std::sync::Arc;
use zeroize::Zeroizing;

use crate::{validation, AppState, VaultError};
use pwdvault_infrastructure::crypto::{
    self, recovery_wrap_key, unwrap_secret, wrap_secret, SecretKey, WRAP_AAD_BIO, WRAP_AAD_RECOVERY,
};
use pwdvault_infrastructure::database::vault_store;
use pwdvault_infrastructure::keychain::BIO_WRAP_ACCOUNT;

use super::super::vault::{backup_db_file, get_db};
use super::shared::{
    collect_rewraps, complete_unlock, current_verification, derive_master_for_unlock,
    derive_new_keys, reseal_vault, verify_master_and_integrity, BlobRewrite, BIO_WRAP_BLOB_KEY,
    RECOVERY_WRAP_BLOB_KEY,
};

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
        let header = pwdvault_infrastructure::vault_header::load_header(&db, &check_enc)?;
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
