use super::*;
use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
use pwdvault_infrastructure::database::Settings;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "backup-test-password";

fn unlocked_state_with_entries<F>(build_entries: F) -> (Arc<AppState>, TempDir, Vec<String>)
where
    F: FnOnce(&[u8; 32]) -> Vec<PasswordEntry>,
{
    let dir = TempDir::new().unwrap();
    let db = Arc::new(database::init_database(dir.path().join("backup.db")).unwrap());
    let salt = [0x41; 16];
    let params = AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        crypto::kdf::derive_key_with_params(TEST_PASSWORD, &salt, &params).unwrap();
    let verification = crypto::create_verification_header(&master_key, salt, params).unwrap();
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);
    let entries = build_entries(&enc_key);
    let entry_ids = entries.iter().map(|entry| entry.id.clone()).collect();

    database::vault_store::VaultStore::new(&db)
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
    state.session.unlock(enc_key, mac_key);
    (state, dir, entry_ids)
}

fn unlocked_state() -> (Arc<AppState>, TempDir) {
    let (state, dir, _) = unlocked_state_with_entries(|enc_key| {
        let mut entry = PasswordEntry::new("Backup entry".into(), None, "backup-user".into());
        let encrypted_password = crypto::encrypt(enc_key, b"backup-secret").unwrap();
        entry.encrypted_password = bincode::serialize(&encrypted_password).unwrap();
        vec![entry]
    });
    (state, dir)
}

#[test]
fn v2_export_import_round_trip() {
    let (state, _dir) = unlocked_state();
    let backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    assert_eq!(backup.version, BACKUP_VERSION_V2);
    assert_eq!(backup.magic.as_deref(), Some(BACKUP_MAGIC));
    let result = import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    assert_eq!(result.entries_imported, 1);
}

#[test]
fn export_supports_raw_historical_secrets_and_empty_passwords() {
    let (state, _dir, _) = unlocked_state_with_entries(|enc_key| {
        let mut raw = PasswordEntry::new("Historical raw entry".into(), None, "legacy-user".into());
        raw.encrypted_password = crypto::encrypt(enc_key, b"legacy-secret")
            .unwrap()
            .to_bytes();
        raw.encrypted_notes = Some(
            crypto::encrypt(enc_key, b"legacy-notes")
                .unwrap()
                .to_bytes(),
        );

        let mut empty =
            PasswordEntry::new("Historical empty entry".into(), None, "empty-user".into());
        empty.encrypted_password = Vec::new();
        empty.encrypted_notes = Some(Vec::new());
        vec![raw, empty]
    });

    let backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    let result = import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    assert_eq!(result.entries_imported, 2);

    let entries = crate::service::list_all_entries(&state).unwrap();
    let raw_id = entries
        .iter()
        .find(|entry| entry.title == "Historical raw entry")
        .unwrap()
        .id
        .clone();
    let empty_id = entries
        .iter()
        .find(|entry| entry.title == "Historical empty entry")
        .unwrap()
        .id
        .clone();

    let raw = crate::service::get_entry_secret(&state, raw_id).unwrap();
    assert_eq!(raw.password.as_str(), "legacy-secret");
    assert_eq!(
        raw.notes.as_deref().map(String::as_str),
        Some("legacy-notes")
    );

    let empty = crate::service::get_entry_secret(&state, empty_id).unwrap();
    assert_eq!(empty.password.as_str(), "");
    assert!(empty.notes.is_none());
}

#[test]
fn export_normalizes_historical_empty_urls() {
    let (state, _dir, _) = unlocked_state_with_entries(|enc_key| {
        let mut empty_url = PasswordEntry::new(
            "Historical empty URL".into(),
            Some("   ".into()),
            "legacy-user".into(),
        );
        let encrypted_password = crypto::encrypt(enc_key, b"legacy-secret").unwrap();
        empty_url.encrypted_password = bincode::serialize(&encrypted_password).unwrap();
        vec![empty_url]
    });

    let backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    let result = import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    assert_eq!(result.entries_imported, 1);

    let entries = crate::service::list_all_entries(&state).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].url, None);
}

/// P2.2 + P3.6 item 1: export excludes tombstoned entries and groups,
/// and normalizes dangling group references (cascade-free group removal)
/// to "ungrouped" so the payload stays referentially valid.
#[test]
fn export_excludes_tombstones_and_normalizes_dangling_groups() {
    let (state, _dir) = unlocked_state();
    let db = crate::service::vault::get_db(&state).unwrap();
    let enc_key = state.session.get_enc_key().unwrap();
    let mac_key = state.session.get_mac_key().unwrap();

    let live_group = database::Group::new("Live".into());
    let mut dead_group = database::Group::new("Dead".into());
    dead_group.deleted_at = Some(1_700_000_000);

    let mut live = PasswordEntry::new("Live entry".into(), None, "user".into());
    live.encrypted_password =
        bincode::serialize(&crypto::encrypt(&enc_key, b"pw").unwrap()).unwrap();
    live.group_id = Some(live_group.id.clone());

    let mut dangling = PasswordEntry::new("Dangling entry".into(), None, "user".into());
    dangling.encrypted_password =
        bincode::serialize(&crypto::encrypt(&enc_key, b"pw").unwrap()).unwrap();
    // References the tombstoned group: cascade clearing is gone (P2.2).
    dangling.group_id = Some(dead_group.id.clone());

    let mut dead = PasswordEntry::new("Dead entry".into(), None, "user".into());
    dead.encrypted_password =
        bincode::serialize(&crypto::encrypt(&enc_key, b"pw").unwrap()).unwrap();
    dead.deleted_at = Some(1_700_000_100);

    database::vault_store::VaultStore::new(&db)
        .write(&mac_key, |txn| {
            database::vault_store::save_group_in_txn(txn, &enc_key, &live_group)?;
            database::vault_store::save_group_in_txn(txn, &enc_key, &dead_group)?;
            database::vault_store::save_entry_in_txn(txn, &enc_key, &live)?;
            database::vault_store::save_entry_in_txn(txn, &enc_key, &dangling)?;
            database::vault_store::save_entry_in_txn(txn, &enc_key, &dead)?;
            Ok(())
        })
        .unwrap();

    // Export validation would fail without tombstone exclusion + dangling
    // reference normalization; the round trip proves both. The fixture's
    // own "Backup entry" adds a third live entry.
    let backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    let result = import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    assert_eq!(result.entries_imported, 3);
    assert_eq!(result.groups_imported, 1);

    let entries = crate::service::list_all_entries(&state).unwrap();
    assert!(entries.iter().all(|entry| entry.title != "Dead entry"));
    let dangling_entry = entries
        .iter()
        .find(|entry| entry.title == "Dangling entry")
        .unwrap();
    assert_eq!(dangling_entry.group_id, None);
}

#[test]
fn v1_fixture_remains_importable() {
    let (state, _dir) = unlocked_state();
    let (json, password) = crate::fixtures::create_backup_v1(2);
    let backup: VaultBackup = serde_json::from_str(&json).unwrap();
    let result = import_vault(&state, backup, Zeroizing::new(password.to_string())).unwrap();
    assert_eq!(result.entries_imported, 2);
}

#[test]
fn v2_header_nonce_and_ciphertext_tampering_fail() {
    let (state, _dir) = unlocked_state();
    let backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();

    let mut header = backup.clone();
    header.created_at += 1;
    assert!(import_vault(&state, header, Zeroizing::new(TEST_PASSWORD.to_string())).is_err());

    let mut nonce = backup.clone();
    nonce.nonce.replace_range(
        ..1,
        if nonce.nonce.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    assert!(import_vault(&state, nonce, Zeroizing::new(TEST_PASSWORD.to_string())).is_err());

    let mut ciphertext = backup;
    ciphertext.data.replace_range(
        ..1,
        if ciphertext.data.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    assert!(import_vault(
        &state,
        ciphertext,
        Zeroizing::new(TEST_PASSWORD.to_string())
    )
    .is_err());
}

#[test]
fn invalid_kdf_and_oversized_backup_rejected_before_work() {
    let (state, _dir) = unlocked_state();
    let mut backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    backup.kdf_memory = u32::MAX;
    let start = std::time::Instant::now();
    assert!(import_vault(
        &state,
        backup.clone(),
        Zeroizing::new(TEST_PASSWORD.to_string())
    )
    .is_err());
    assert!(start.elapsed().as_millis() < 50);

    backup.data = "A".repeat(
        pwdvault_domain::validation::MAX_BACKUP_DECODED_BYTES
            .saturating_mul(4)
            .div_ceil(3)
            .saturating_add(5),
    );
    assert!(import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).is_err());
}

/// X6 helper: build a minimal VALID backup-v1 envelope whose KDF params
/// are fixed explicitly (v1 has no AAD, so the params are freely chosen
/// without breaking the ciphertext). Used to probe the import floor.
fn v1_backup_with_params(params: AdaptiveParams) -> VaultBackup {
    let payload = BackupPayload {
        entries: vec![],
        groups: vec![],
        settings: Settings::default(),
    };
    let payload_json = serde_json::to_vec(&payload).unwrap();
    let salt = [0x42u8; 16];
    let (key, _) = crypto::kdf::derive_key_with_params(TEST_PASSWORD, &salt, &params).unwrap();
    let encrypted = crypto::encrypt(&key, &payload_json).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    VaultBackup {
        version: BACKUP_VERSION_V1,
        created_at: 0,
        magic: None,
        kdf_name: None,
        cipher_name: None,
        salt: b64.encode(salt),
        kdf_memory: params.m_cost,
        kdf_iterations: params.t_cost,
        kdf_parallelism: params.p_cost,
        nonce: b64.encode(&encrypted.nonce),
        data: b64.encode(&encrypted.ciphertext),
    }
}

/// X6: a backup embedded with params exactly at the import floor
/// (19456 KiB / t=2) is accepted.
#[test]
fn import_accepts_backup_exactly_at_kdf_floor() {
    let (state, _dir) = unlocked_state();
    let backup = v1_backup_with_params(AdaptiveParams {
        m_cost: crypto::kdf::KdfPolicy::IMPORT_MIN_MEMORY_KIB,
        t_cost: crypto::kdf::KdfPolicy::IMPORT_MIN_ITERATIONS,
        p_cost: 1,
    });
    let result = import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    assert_eq!(result.entries_imported, 0);
}

/// X6: params one step below the floor on either axis (19455 KiB, or the
/// legacy t=1 shape) are rejected with the dedicated error — without ever
/// reaching key derivation.
#[test]
fn import_rejects_backup_below_kdf_floor() {
    let (state, _dir) = unlocked_state();

    let weak_memory = v1_backup_with_params(AdaptiveParams {
        m_cost: crypto::kdf::KdfPolicy::IMPORT_MIN_MEMORY_KIB - 1,
        t_cost: crypto::kdf::KdfPolicy::IMPORT_MIN_ITERATIONS,
        p_cost: 1,
    });
    assert!(matches!(
        import_vault(
            &state,
            weak_memory,
            Zeroizing::new(TEST_PASSWORD.to_string())
        ),
        Err(VaultError::WeakKdfParams)
    ));

    let weak_iterations = v1_backup_with_params(AdaptiveParams {
        m_cost: crypto::kdf::KdfPolicy::IMPORT_MIN_MEMORY_KIB,
        t_cost: crypto::kdf::KdfPolicy::IMPORT_MIN_ITERATIONS - 1,
        p_cost: 1,
    });
    assert!(matches!(
        import_vault(
            &state,
            weak_iterations,
            Zeroizing::new(TEST_PASSWORD.to_string())
        ),
        Err(VaultError::WeakKdfParams)
    ));
}

// ---------------------------------------------------------------------------
// SEC-M2: parse_backup_file_bytes — the file-level pre-flight of the
// read_backup_file IPC command. These complement (never replace) the import
// round-trip tests above.
// ---------------------------------------------------------------------------

/// Files larger than the frontend-aligned 14 MiB cap are rejected before any
/// JSON parsing (BACKUP_TOO_LARGE, mirroring ImportExportScreen).
#[test]
fn parse_rejects_oversized_file_bytes() {
    let oversized = vec![0u8; MAX_BACKUP_FILE_BYTES + 1];
    match parse_backup_file_bytes(&oversized) {
        Err(VaultError::InvalidInput { code, .. }) => assert_eq!(code, "BACKUP_TOO_LARGE"),
        other => panic!("expected BACKUP_TOO_LARGE, got {other:?}"),
    }
}

#[test]
fn parse_rejects_invalid_json() {
    assert!(parse_backup_file_bytes(b"this is not json").is_err());
}

/// A structurally valid envelope with an unsupported version fails the
/// pre-flight exactly like the frontend isSupportedBackup check.
#[test]
fn parse_rejects_unsupported_version() {
    let mut backup = v1_backup_with_params(AdaptiveParams {
        m_cost: 19456,
        t_cost: 2,
        p_cost: 1,
    });
    backup.version = 7;
    let bytes = serde_json::to_vec(&backup).unwrap();
    assert!(parse_backup_file_bytes(&bytes).is_err());
}

/// A v2 envelope without the expected magic/kdf/cipher header names is
/// rejected at file-pick time (same rule import_vault enforces).
#[test]
fn parse_rejects_v2_without_magic() {
    let mut backup = v1_backup_with_params(AdaptiveParams {
        m_cost: 19456,
        t_cost: 2,
        p_cost: 1,
    });
    backup.version = BACKUP_VERSION_V2;
    let bytes = serde_json::to_vec(&backup).unwrap();
    assert!(parse_backup_file_bytes(&bytes).is_err());
}

/// A well-formed v1 envelope round-trips through the parser untouched.
#[test]
fn parse_accepts_well_formed_v1_envelope() {
    let backup = v1_backup_with_params(AdaptiveParams {
        m_cost: 19456,
        t_cost: 2,
        p_cost: 1,
    });
    let bytes = serde_json::to_vec(&backup).unwrap();
    let parsed = parse_backup_file_bytes(&bytes).unwrap();
    assert_eq!(parsed.version, backup.version);
    assert_eq!(parsed.salt, backup.salt);
    assert_eq!(parsed.nonce, backup.nonce);
    assert_eq!(parsed.data, backup.data);
}
