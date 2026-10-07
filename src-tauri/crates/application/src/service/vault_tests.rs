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
        entry.encrypted_password = bc_serialize(&encrypted).unwrap();
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
    let before = bc_serialize(&row_before).unwrap();
    let after = bc_serialize(&row_after).unwrap();
    assert_eq!(before, after, "verification row bytes must not change");
}

// ---------------------------------------------------------------------------
// v1.3.0 bincode 1→2 swap — full-chain round-trip over the shipped legacy
// fixture generations (DoD #5).
// ---------------------------------------------------------------------------

/// The whole service chain across every on-disk byte generation this app has
/// shipped: build fixture → (explicit migration for the headerless
/// generation) → unlock → read → write → re-read → sync rows (PVSYNC1) →
/// change password → re-read. Proves the bincode 2 `bc_serialize` /
/// `bc_deserialize` seam reads, re-seals and rotates every historical layout
/// without a single `bincode 1` call.
#[test]
fn legacy_fixtures_full_chain_round_trip() {
    use crate::service::sync::backend::MockCloudBackend;
    use crate::service::sync::engine::{
        sync_connect_with_backend, sync_now_with_backend, SyncBackendKind, SyncConfig,
    };
    use crate::service::sync::state_io::{SYNC_CONFIG_BLOB_KEY, SYNC_ROW_ENC_PREFIX};
    use crate::{change_password, create_entry, get_entry_secret, list_all_entries};
    use pwdvault_infrastructure::keychain::{MemorySecretStore, SecretStore};

    let new_password = "brand-new-chain-password";
    let fixture_password = crate::fixtures::FIXTURE_PASSWORD;

    // ---- Leg 1: pre-v1.0.5 raw-blob fixture (oldest generation). ----
    let (_dir, db_path, _) = crate::fixtures::create_pre_v1_0_5(2);
    let db = Arc::new(redb::Database::open(&db_path).unwrap());
    let verification = database::load_verification_data(&db).unwrap().unwrap();
    let state = Arc::new(AppState {
        secret_store: Arc::new(MemorySecretStore::new()) as Arc<dyn SecretStore>,
        sync_secret_store: Arc::new(MemorySecretStore::new()) as Arc<dyn SecretStore>,
        ..AppState::default()
    });
    *state.database.lock().unwrap() = Some(Arc::clone(&db));
    *state.verification_data.lock().unwrap() = Some(verification.clone());

    // The headerless legacy vault refuses plain unlock; migrate explicitly.
    assert!(matches!(
        unlock_vault(&state, Zeroizing::new(fixture_password.to_string())),
        Err(VaultError::LegacyVaultRequiresMigration)
    ));
    let (master_key, _) = crypto::kdf::derive_key_with_params(
        fixture_password,
        &verification.salt,
        &verification.params,
    )
    .unwrap();
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &verification.salt);
    migrate_database(&db, &master_key, &enc_key, &mac_key).unwrap();
    assert!(unlock_vault(&state, Zeroizing::new(fixture_password.to_string())).unwrap());

    // READ: legacy raw-blob rows decrypt through the new seam.
    let listed = list_all_entries(&state).unwrap();
    assert_eq!(listed.len(), 2);
    let legacy_id = listed
        .iter()
        .find(|entry| entry.title == "Legacy Entry 0")
        .unwrap()
        .id
        .clone();
    assert_eq!(
        get_entry_secret(&state, legacy_id.clone())
            .unwrap()
            .password
            .to_string(),
        "legacy-password-0"
    );

    // WRITE + RE-READ: a fresh entry lands in the current format.
    let new_id = create_entry(
        &state,
        crate::CreateEntryRequest {
            title: "Chain New Entry".to_string(),
            url: Some("https://chain.example.test".to_string()),
            username: "chain-user".to_string(),
            password: Zeroizing::new("chain-secret-新".to_string()),
            notes: Some("chain notes".to_string()),
            tags: vec!["chain".to_string()],
            group_id: None,
        },
    )
    .unwrap()
    .id;
    let fresh = get_entry_secret(&state, new_id.clone()).unwrap();
    assert_eq!(fresh.password.to_string(), "chain-secret-新");
    assert_eq!(fresh.notes.as_ref().unwrap().to_string(), "chain notes");

    // SYNC: connecting seals a PVSYNC1 row next to the migrated legacy rows.
    let cloud = MockCloudBackend::new();
    sync_connect_with_backend(
        &state,
        &cloud,
        SyncConfig {
            enabled: true,
            backend: SyncBackendKind::Webdav,
            server_url: "https://dav.example.com/dav".to_string(),
            remote_dir: "PwdVault".to_string(),
            username: "chain@example.com".to_string(),
        },
        Zeroizing::new("container-passphrase".to_string()),
        None,
    )
    .unwrap();
    let sync_row = {
        let db_ref = get_db(&state).unwrap();
        let txn = db_ref.begin_read().unwrap();
        let table = txn.open_table(database::VAULT_TABLE).unwrap();
        table
            .get(SYNC_CONFIG_BLOB_KEY)
            .unwrap()
            .unwrap()
            .value()
            .to_vec()
    };
    assert!(
        sync_row.starts_with(SYNC_ROW_ENC_PREFIX),
        "sync config row must be sealed in the PVSYNC1 layout"
    );

    // CHANGE PASSWORD, then re-read everything under the new credential.
    change_password(
        &state,
        Zeroizing::new(fixture_password.to_string()),
        Zeroizing::new(new_password.to_string()),
        None,
    )
    .unwrap();
    lock_vault(&state);
    assert!(unlock_vault(&state, Zeroizing::new(new_password.to_string())).unwrap());
    assert_eq!(
        get_entry_secret(&state, legacy_id)
            .unwrap()
            .password
            .to_string(),
        "legacy-password-0"
    );
    assert_eq!(
        get_entry_secret(&state, new_id)
            .unwrap()
            .password
            .to_string(),
        "chain-secret-新"
    );
    // The PVSYNC1 rows survived the rotation; sync still round-trips.
    let status = sync_now_with_backend(&state, &cloud).unwrap();
    assert_eq!(status.last_result.as_deref(), Some("ok"));

    // ---- Leg 2: v1.0.5 sealed fixture (HKDF subkeys + seal + digest v3). ----
    let fixture = crate::fixtures::create_v1_0_5_digest_v3(2);
    drop(fixture.db);
    let db2 = Arc::new(redb::Database::open(&fixture.db_path).unwrap());
    let verification2 = database::load_verification_data(&db2).unwrap().unwrap();
    let state2 = Arc::new(AppState {
        secret_store: Arc::new(MemorySecretStore::new()) as Arc<dyn SecretStore>,
        sync_secret_store: Arc::new(MemorySecretStore::new()) as Arc<dyn SecretStore>,
        ..AppState::default()
    });
    *state2.database.lock().unwrap() = Some(Arc::clone(&db2));
    *state2.verification_data.lock().unwrap() = Some(verification2);
    // The digest-v3 generation has no vault header either (headers arrived
    // later) — explicit migration, then unlock.
    assert!(matches!(
        unlock_vault(&state2, Zeroizing::new(fixture.password.to_string())),
        Err(VaultError::LegacyVaultRequiresMigration)
    ));
    let (master_key2, _) = crypto::kdf::derive_key_with_params(
        fixture.password,
        &fixture.salt,
        &crypto::kdf::AdaptiveParams {
            m_cost: 16384,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .unwrap();
    let (enc_key2, mac_key2) = crypto::kdf::derive_subkeys(&master_key2, &fixture.salt);
    migrate_database(&db2, &master_key2, &enc_key2, &mac_key2).unwrap();
    // The sealed generation unlocks directly after migration.
    assert!(unlock_vault(&state2, Zeroizing::new(fixture.password.to_string())).unwrap());
    let listed2 = list_all_entries(&state2).unwrap();
    assert_eq!(listed2.len(), 2);
    let sealed_id = listed2
        .iter()
        .find(|entry| entry.title == "Fixture Entry 0")
        .unwrap()
        .id
        .clone();
    let sealed = get_entry_secret(&state2, sealed_id.clone()).unwrap();
    assert_eq!(sealed.password.to_string(), "fixture-password-0");
    assert_eq!(
        sealed.notes.as_ref().unwrap().to_string(),
        "Notes for entry 0"
    );

    let sealed_new_id = create_entry(
        &state2,
        crate::CreateEntryRequest {
            title: "Sealed Chain Entry".to_string(),
            url: None,
            username: "sealed-user".to_string(),
            password: Zeroizing::new("sealed-secret".to_string()),
            notes: None,
            tags: vec![],
            group_id: None,
        },
    )
    .unwrap()
    .id;
    assert_eq!(
        get_entry_secret(&state2, sealed_new_id)
            .unwrap()
            .password
            .to_string(),
        "sealed-secret"
    );

    change_password(
        &state2,
        Zeroizing::new(fixture.password.to_string()),
        Zeroizing::new(new_password.to_string()),
        None,
    )
    .unwrap();
    lock_vault(&state2);
    assert!(unlock_vault(&state2, Zeroizing::new(new_password.to_string())).unwrap());
    assert_eq!(
        get_entry_secret(&state2, sealed_id)
            .unwrap()
            .password
            .to_string(),
        "fixture-password-0"
    );
}
