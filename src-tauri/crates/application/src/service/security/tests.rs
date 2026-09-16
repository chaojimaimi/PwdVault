//! Test fixtures shared by the security test modules, plus the
//! change-password (D8 exclusive-clear) tests.

use super::*;
use crate::fixtures;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
use pwdvault_infrastructure::crypto::{self, create_verification_header};
use pwdvault_infrastructure::database;
use pwdvault_infrastructure::database::vault_store::{self, VaultStore};
use pwdvault_infrastructure::keychain::{MemorySecretStore, SecretStore, BIO_WRAP_ACCOUNT};
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::super::vault::{get_db, lock_vault, unlock_vault};

pub(super) const TEST_PASSWORD: &str = "phase-one-test-password";
pub(super) const NEW_PASSWORD: &str = "a-brand-new-password!";
const TEST_SALT: [u8; 16] = [0x41; 16];

pub(super) struct TestVault {
    pub(super) state: Arc<AppState>,
    pub(super) store: Arc<MemorySecretStore>,
    _dir: TempDir,
    entry_ids: Vec<String>,
    group_ids: Vec<String>,
}

/// Same pattern as vault.rs `create_modern_vault`, plus a group and a
/// `MemorySecretStore` wired into state.
pub(super) fn create_test_vault(entry_count: usize, group_count: usize) -> TestVault {
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
        let mut entry =
            database::PasswordEntry::new(format!("Entry {index}"), None, format!("user-{index}"));
        let encrypted = crypto::encrypt(&enc_key, format!("secret-{index}").as_bytes()).unwrap();
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
pub(super) fn unlock(vault: &TestVault, password: &str) -> bool {
    unlock_vault(&vault.state, Zeroizing::new(password.to_string())).unwrap()
}

pub(super) fn unlock_vault_result(vault: &TestVault, password: &str) -> Result<bool, VaultError> {
    crate::unlock_vault(&vault.state, Zeroizing::new(password.to_string()))
}

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
        let entry = database::load_entry(&db, &enc, id, false).unwrap().unwrap();
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
        let group = database::load_group(&db, &enc, id, false).unwrap().unwrap();
        assert_eq!(group.name, format!("Group {index}"));
    }

    // Digest passes and the header is readable with integrity required.
    assert!(database::integrity::verify_integrity(
        &db,
        &vault.state.session.get_mac_key().unwrap()
    )
    .unwrap());
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
    assert!(
        message.contains("Touch ID"),
        "unexpected message: {message}"
    );
    assert!(
        message.contains("disable Touch ID"),
        "unexpected message: {message}"
    );

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
    // Writers keep committing until the password change has fully
    // completed, so writes deterministically span the exclusive (drain)
    // window instead of racing it by timing (review P1-1: a fixed 40-write
    // budget finished before the window opened on a quiet machine).
    let stop_writes = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let mut handles = Vec::new();
    for (w, state) in writers.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        let entry_ids = Arc::clone(&entry_ids);
        let stop_writes = Arc::clone(&stop_writes);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut accepted = 0usize;
            let mut rejected = 0usize;
            // The stop flag normally ends the loop; the iteration cap only
            // guards against a changer panic leaving writers spinning.
            let mut i = 0usize;
            while !stop_writes.load(std::sync::atomic::Ordering::SeqCst) && i < 5_000 {
                let id = &entry_ids[i % entry_ids.len()];
                let request = pwdvault_domain::UpdateEntryRequest {
                    title: format!("w{w}-{i}"),
                    url: None,
                    username: format!("writer-{w}"),
                    password: None,
                    notes: None,
                    update_notes: false,
                    tags: vec![],
                    group_id: None,
                    totp_secret: None,
                };
                match crate::update_entry(&state, id.clone(), request) {
                    Ok(_) => accepted += 1,
                    Err(VaultError::VaultLocked) => rejected += 1,
                    Err(e) => panic!("unexpected write error: {e}"),
                }
                i += 1;
            }
            (accepted, rejected)
        }));
    }

    let changer = {
        let state = Arc::clone(&vault.state);
        let barrier = Arc::clone(&barrier);
        let stop_writes = Arc::clone(&stop_writes);
        thread::spawn(move || {
            barrier.wait();
            let result = change_password(
                &state,
                Zeroizing::new(TEST_PASSWORD.to_string()),
                Zeroizing::new(NEW_PASSWORD.to_string()),
                None,
            );
            // Release writers only after the swap has fully settled, so
            // at least some writes are guaranteed to land inside the
            // exclusive window.
            stop_writes.store(true, std::sync::atomic::Ordering::SeqCst);
            result
        })
    };

    let change_result = changer.join().unwrap();
    let mut total_accepted = 0usize;
    let mut total_rejected = 0usize;
    for handle in handles {
        let (accepted, rejected) = handle.join().unwrap();
        total_accepted += accepted;
        total_rejected += rejected;
    }
    change_result.unwrap();
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
    let entries =
        database::list_all_entries_bulk(&db, &vault.state.session.get_enc_key().unwrap(), None)
            .unwrap();
    assert_eq!(entries.len(), 120);
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
        pwdvault_infrastructure::vault_header::save_header_in_txn(&txn, &header, &enc_key).unwrap();
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
