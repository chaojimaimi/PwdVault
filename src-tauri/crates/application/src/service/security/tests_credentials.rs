//! Touch ID (biometric) unlock and recovery-key tests for the security
//! services. Fixtures live in `super::tests`.

use super::super::vault::lock_vault;
use super::tests::{create_test_vault, unlock, unlock_vault_result, NEW_PASSWORD, TEST_PASSWORD};
use super::*;
use crate::fixtures;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::crypto;
use pwdvault_infrastructure::database;
use pwdvault_infrastructure::database::vault_store;
use pwdvault_infrastructure::keychain::{
    MemorySecretStore, SecretStore, SecretStoreError, BIO_WRAP_ACCOUNT,
};
use std::sync::Arc;
use zeroize::Zeroizing;

/// P1.7-4: enable → lock → Touch ID unlock full chain, with the wrap-key
/// cache semantics of D5.
#[test]
fn biometric_enable_lock_unlock_full_chain() {
    let vault = create_test_vault(1, 0);
    assert!(unlock(&vault, TEST_PASSWORD));

    let status = biometric_status(&vault.state, vault.store.as_ref()).unwrap();
    assert!(status.available);
    assert!(!status.enabled);

    enable_biometric(
        &vault.state,
        Zeroizing::new(TEST_PASSWORD.to_string()),
        vault.store.as_ref(),
    )
    .unwrap();
    assert!(
        biometric_status(&vault.state, vault.store.as_ref())
            .unwrap()
            .enabled
    );

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

fn unlock_vault_result_for(state: &Arc<AppState>, password: &str) -> Result<bool, VaultError> {
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
    assert!(
        !biometric_status(&vault.state, &MemorySecretStore::new())
            .unwrap()
            .enabled
    );
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
