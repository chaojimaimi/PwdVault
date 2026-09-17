use super::*;
use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
use redb::ReadableTable;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "phase-one-test-password";
const TEST_SALT: [u8; 16] = [0x31; 16];

struct ModernVault {
    state: Arc<AppState>,
    _dir: TempDir,
    entry_ids: Vec<String>,
}

fn create_modern_vault(entry_count: usize) -> ModernVault {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(database::init_database(dir.path().join("modern.db")).unwrap());
    let params = AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        crypto::kdf::derive_key_with_params(TEST_PASSWORD, &TEST_SALT, &params).unwrap();
    let verification = create_verification_header(&master_key, TEST_SALT, params).unwrap();
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &TEST_SALT);
    let mut entries = Vec::new();
    let mut entry_ids = Vec::new();
    for index in 0..entry_count {
        let mut entry =
            database::PasswordEntry::new(format!("Entry {index}"), None, format!("user-{index}"));
        let encrypted = crypto::encrypt(&enc_key, format!("secret-{index}").as_bytes()).unwrap();
        entry.encrypted_password = bincode::serialize(&encrypted).unwrap();
        entry_ids.push(entry.id.clone());
        entries.push(entry);
    }

    let store = database::vault_store::VaultStore::new(&db);
    store
        .write(&mac_key, |txn| {
            database::vault_store::save_verification_data_in_txn(txn, &verification)?;
            pwdvault_infrastructure::vault_header::save_header_in_txn(
                txn,
                &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
                &enc_key,
            )?;
            database::vault_store::save_settings_in_txn(txn, &Settings::default())?;
            for entry in &entries {
                database::vault_store::save_entry_in_txn(txn, &enc_key, entry)?;
            }
            Ok(())
        })
        .unwrap();

    let state = Arc::new(AppState::default());
    *state.database.lock().unwrap() = Some(db);
    *state.verification_data.lock().unwrap() = Some(verification);
    ModernVault {
        state,
        _dir: dir,
        entry_ids,
    }
}

fn assert_tamper_rejected<F>(entry_count: usize, tamper: F)
where
    F: FnOnce(&redb::Database, &[String]),
{
    let vault = create_modern_vault(entry_count);
    let db = get_db(&vault.state).unwrap();
    tamper(&db, &vault.entry_ids);

    let result = unlock_vault(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string()));
    assert!(result.is_err());
    assert!(!vault.state.is_unlocked());
    assert!(vault.state.session.get_enc_key().is_err());
    assert!(vault.state.session.get_mac_key().is_err());
}

#[test]
fn missing_digest_is_rejected_without_publishing_keys() {
    assert_tamper_rejected(1, |db, _| {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(database::integrity::META_TABLE).unwrap();
            table.remove(database::integrity::DB_DIGEST_KEY).unwrap();
        }
        txn.commit().unwrap();
    });
}

#[test]
fn unknown_digest_version_is_rejected_without_publishing_keys() {
    assert_tamper_rejected(1, |db, _| {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(database::integrity::META_TABLE).unwrap();
            table
                .insert(
                    database::integrity::DB_DIGEST_VERSION_KEY,
                    u32::MAX.to_le_bytes().as_slice(),
                )
                .unwrap();
        }
        txn.commit().unwrap();
    });
}

#[test]
fn deleted_record_is_rejected_without_publishing_keys() {
    assert_tamper_rejected(1, |db, ids| {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(database::ENTRIES_TABLE).unwrap();
            table.remove(ids[0].as_str()).unwrap();
        }
        txn.commit().unwrap();
    });
}

#[test]
fn swapped_record_blobs_are_rejected_without_publishing_keys() {
    assert_tamper_rejected(2, |db, ids| {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(database::ENTRIES_TABLE).unwrap();
            let first = table
                .get(ids[0].as_str())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            let second = table
                .get(ids[1].as_str())
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            table.insert(ids[0].as_str(), second.as_slice()).unwrap();
            table.insert(ids[1].as_str(), first.as_slice()).unwrap();
        }
        txn.commit().unwrap();
    });
}

#[test]
fn legacy_fixture_unlock_fails_closed_and_explicit_migration_succeeds() {
    let (_dir, db_path, _) = crate::fixtures::create_pre_v1_0_5(3);
    let db = Arc::new(redb::Database::open(db_path).unwrap());
    let verification = database::load_verification_data(&db).unwrap().unwrap();
    let state = Arc::new(AppState::default());
    *state.database.lock().unwrap() = Some(Arc::clone(&db));
    *state.verification_data.lock().unwrap() = Some(verification.clone());

    // B1: a headerless vault must NOT be silently migrated on unlock.
    let result = unlock_vault(
        &state,
        Zeroizing::new(crate::fixtures::FIXTURE_PASSWORD.to_string()),
    );
    assert!(matches!(
        result,
        Err(VaultError::LegacyVaultRequiresMigration)
    ));
    assert!(!state.is_unlocked());

    // Explicit migration (the 1.1.4 tool path) still works and unlocks.
    let (master_key, _) = crypto::kdf::derive_key_with_params(
        crate::fixtures::FIXTURE_PASSWORD,
        &verification.salt,
        &verification.params,
    )
    .unwrap();
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &verification.salt);
    migrate_database(&db, &master_key, &enc_key, &mac_key).unwrap();

    assert!(unlock_vault(
        &state,
        Zeroizing::new(crate::fixtures::FIXTURE_PASSWORD.to_string())
    )
    .unwrap());
    let first_header = pwdvault_infrastructure::vault_header::load_header(
        &db,
        &state.session.get_enc_key().unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(first_header.migration_generation, 1);

    lock_vault(&state);
    assert!(unlock_vault(
        &state,
        Zeroizing::new(crate::fixtures::FIXTURE_PASSWORD.to_string())
    )
    .unwrap());
    let second_header = pwdvault_infrastructure::vault_header::load_header(
        &db,
        &state.session.get_enc_key().unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(second_header.migration_generation, 1);
}

#[test]
fn failed_legacy_migration_keeps_session_locked() {
    let (_dir, db_path, _) = crate::fixtures::create_pre_v1_0_5(1);
    let db = Arc::new(redb::Database::open(db_path).unwrap());
    let verification = database::load_verification_data(&db).unwrap().unwrap();
    let ids = database::list_entries(&db).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut table = txn.open_table(database::ENTRIES_TABLE).unwrap();
        table.insert(ids[0].as_str(), &[0xFF][..]).unwrap();
    }
    txn.commit().unwrap();

    let state = Arc::new(AppState::default());
    *state.database.lock().unwrap() = Some(db.clone());
    *state.verification_data.lock().unwrap() = Some(verification.clone());
    assert!(unlock_vault(
        &state,
        Zeroizing::new(crate::fixtures::FIXTURE_PASSWORD.to_string())
    )
    .is_err());

    let (master_key, _) = crypto::kdf::derive_key_with_params(
        crate::fixtures::FIXTURE_PASSWORD,
        &verification.salt,
        &verification.params,
    )
    .unwrap();
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &verification.salt);
    assert!(migrate_database(&db, &master_key, &enc_key, &mac_key).is_err());

    assert!(!state.is_unlocked());
    assert!(state.session.get_enc_key().is_err());
    assert!(state.session.get_mac_key().is_err());
}

/// B1 test 1: deleting the header row must fail the unlock with
/// `LegacyVaultRequiresMigration`, not silently migrate.
#[test]
fn deleted_header_is_rejected_with_migration_error() {
    let vault = create_modern_vault(1);
    let db = get_db(&vault.state).unwrap();
    delete_header_row(&db);

    let result = unlock_vault(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string()));
    assert!(matches!(
        result,
        Err(VaultError::LegacyVaultRequiresMigration)
    ));
    assert!(!vault.state.is_unlocked());
    assert!(vault.state.session.get_enc_key().is_err());
    assert!(vault.state.session.get_mac_key().is_err());
}

/// Remove `VAULT_TABLE["header"]` without touching anything else.
fn delete_header_row(db: &redb::Database) {
    let txn = db.begin_write().unwrap();
    {
        let mut table = txn.open_table(database::VAULT_TABLE).unwrap();
        table
            .remove(pwdvault_infrastructure::vault_header::HEADER_KEY)
            .unwrap();
    }
    txn.commit().unwrap();
}

/// B1 test 2: after the rejected headerless unlock the stored digest is
/// untouched (no silent baseline rebuild).
#[test]
fn deleted_header_rejection_does_not_rewrite_digest() {
    let vault = create_modern_vault(1);
    let db = get_db(&vault.state).unwrap();

    fn stored_digest(db: &redb::Database) -> Option<Vec<u8>> {
        let txn = db.begin_read().unwrap();
        let table = txn
            .open_table(database::integrity::META_TABLE)
            .expect("meta table");
        table
            .get(database::integrity::DB_DIGEST_KEY)
            .unwrap()
            .map(|v| v.value().to_vec())
    }

    let digest_before = stored_digest(&db).expect("fixture must have a digest");
    delete_header_row(&db);

    assert!(unlock_vault(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string())).is_err());
    assert_eq!(
        stored_digest(&db).as_deref(),
        Some(digest_before.as_slice())
    );
}

/// B1 test 4: a spliced header with integrity_required=false (downgrade)
/// plus tampered records must be rejected BEFORE migration rebuilds the
/// digest baseline.
#[test]
fn downgraded_header_with_stale_digest_is_rejected() {
    let vault = create_modern_vault(1);
    let db = get_db(&vault.state).unwrap();

    let params = AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        crypto::kdf::derive_key_with_params(TEST_PASSWORD, &TEST_SALT, &params).unwrap();
    let (enc_key, _) = crypto::kdf::derive_subkeys(&master_key, &TEST_SALT);

    // Tamper an entry, then splice in a "legacy" header so unlock would
    // take the migration path. Plain txn: the stale digest must survive.
    let txn = db.begin_write().unwrap();
    {
        let mut table = txn.open_table(database::ENTRIES_TABLE).unwrap();
        table
            .insert(vault.entry_ids[0].as_str(), &[0xEE, 0xFF][..])
            .unwrap();
        let mut header = pwdvault_infrastructure::vault_header::VaultHeader::new_initial();
        header.integrity_required = false;
        pwdvault_infrastructure::vault_header::save_header_in_txn(&txn, &header, &enc_key).unwrap();
    }
    txn.commit().unwrap();

    let result = unlock_vault(&vault.state, Zeroizing::new(TEST_PASSWORD.to_string()));
    assert!(matches!(result, Err(VaultError::InvalidBackup(_))));
    assert!(!vault.state.is_unlocked());
}

/// B1 test 5: runtime readers reject pre-v1.0.5 plaintext records
/// regardless of header state; only the migration channel accepts them.
#[test]
fn runtime_paths_reject_plaintext_records() {
    let (_dir, db_path, _) = crate::fixtures::create_pre_v1_0_5(2);
    let db = Arc::new(redb::Database::open(db_path).unwrap());
    let verification = database::load_verification_data(&db).unwrap().unwrap();
    let (master_key, _) = crypto::kdf::derive_key_with_params(
        crate::fixtures::FIXTURE_PASSWORD,
        &verification.salt,
        &verification.params,
    )
    .unwrap();
    let (enc_key, _) = crypto::kdf::derive_subkeys(&master_key, &verification.salt);

    let ids = database::list_entries(&db).unwrap();
    assert_eq!(ids.len(), 2);

    // Runtime channel (allow_plaintext = false) must fail closed.
    assert!(database::load_entry(&db, &enc_key, &ids[0], false).is_err());
    assert!(database::list_all_entries_bulk(&db, &enc_key, None).is_err());
    assert!(database::list_all_entries_bulk(&db, &enc_key, Some("group-0")).is_err());

    // Migration channel still reads the plaintext records.
    assert!(database::load_entry(&db, &enc_key, &ids[0], true)
        .unwrap()
        .is_some());
}

/// B2 test: an existing on-disk verification row makes `init_vault` fail
/// with the existing `VaultAlreadyExists` error and leaves the row intact.
#[test]
fn init_vault_refuses_to_overwrite_existing_verification_row() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("existing.db");

    // Build a vault file that has a verification row on disk but is NOT
    // loaded into any AppState (simulates a previous app run).
    let existing_db = database::init_database(&db_path).unwrap();
    let params = AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        crypto::kdf::derive_key_with_params(TEST_PASSWORD, &TEST_SALT, &params).unwrap();
    let verification = create_verification_header(&master_key, TEST_SALT, params).unwrap();
    database::save_verification_data(&existing_db, &verification).unwrap();
    drop(existing_db);

    let row_before = {
        let db = redb::Database::open(&db_path).unwrap();
        database::load_verification_data(&db).unwrap().unwrap()
    };

    let state = Arc::new(AppState::default());
    // Sanity: the disk check (B2) sees the vault on the temp path.
    assert!(disk_has_verification(&db_path).unwrap());

    let result = init_vault_at(&db_path, &state, Zeroizing::new(TEST_PASSWORD.to_string()));
    assert!(matches!(result, Err(VaultError::VaultAlreadyExists)));
    assert!(state.session.get_enc_key().is_err());

    let row_after = {
        let db = redb::Database::open(&db_path).unwrap();
        database::load_verification_data(&db).unwrap().unwrap()
    };
    let before = bincode::serialize(&row_before).unwrap();
    let after = bincode::serialize(&row_after).unwrap();
    assert_eq!(before, after, "verification row bytes must not change");
}
