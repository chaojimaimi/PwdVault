//! SEC-L2 tests: the sealed sync config/state rows — roundtrip + AAD
//! row-binding, the v1.1.x plaintext dual-read migration (read-time re-seal),
//! tamper fail-closedness, and the re-seal rotation of LEGACY plaintext rows
//! through change_password / recover_vault (the upgraded-but-never-migrated
//! user must still be able to change the master password, and sync must
//! survive it — the repo's standing reseal-inheritance standard).

use std::sync::Arc;
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::backend::MockCloudBackend;
use super::engine::{SyncState, SyncStatusResponse};
use super::state_io::{
    load_config, load_sync_state, save_sync_rows, validate_config, SessionKeys,
    SYNC_CONFIG_BLOB_KEY, SYNC_ROW_ENC_PREFIX, SYNC_STATE_BLOB_KEY,
};
use super::tests_engine::{
    test_config, test_state, CONTAINER_PASSWORD, NEW_PASSWORD, TEST_PASSWORD,
};
use crate::{AppState, VaultError};
use pwdvault_infrastructure::database::{self, vault_store, vault_store::VaultStore};

fn get_db(state: &Arc<AppState>) -> Arc<redb::Database> {
    crate::service::vault::get_db(state).unwrap()
}

fn row_bytes(state: &Arc<AppState>, key: &str) -> Vec<u8> {
    vault_store::load_blob(&get_db(state), key)
        .unwrap()
        .expect("row exists")
}

fn session_keys(state: &Arc<AppState>) -> ([u8; 32], [u8; 32]) {
    (
        state.session.get_enc_key().unwrap(),
        state.session.get_mac_key().unwrap(),
    )
}

fn contains_substring(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn assert_corrupt(err: &VaultError, code: &str) {
    assert!(
        matches!(err, VaultError::InvalidInput { code: c, .. } if c == code),
        "unexpected error: {err:?}"
    );
}

fn sample_sync_state() -> SyncState {
    SyncState {
        device_id: Some("deadbeef1234".to_string()),
        last_sync_at: Some(1_700_000_000),
        last_result: Some("ok".to_string()),
        remote_rev: Some(7),
        last_snapshot_hash: Some("abc123".to_string()),
        envelope: None,
        history: vec!["h-1".to_string(), "h-2".to_string()],
    }
}

/// Digest-consistent raw-row overwrite (the fixture tool for tamper/swap
/// setups — keeps the integrity digest valid so the failure under test comes
/// from the row parse itself, not from a stale digest).
fn write_row(state: &Arc<AppState>, key: &str, bytes: &[u8]) {
    let (_, mac) = session_keys(state);
    VaultStore::new(&get_db(state))
        .write(&mac, |txn| {
            vault_store::save_blob_in_txn(txn, key, bytes)?;
            Ok(())
        })
        .unwrap();
}

/// v1.1.9 fixture: write the two rows as plaintext JSON exactly like the
/// pre-SEC-L2 engine did.
fn overwrite_rows_with_legacy_plaintext(
    state: &Arc<AppState>,
    config: &super::engine::SyncConfig,
    sync_state: &SyncState,
) {
    let config_json = serde_json::to_vec(config).unwrap();
    let state_json = serde_json::to_vec(sync_state).unwrap();
    write_row(state, SYNC_CONFIG_BLOB_KEY, &config_json);
    write_row(state, SYNC_STATE_BLOB_KEY, &state_json);
}

fn assert_digest_verifies(state: &Arc<AppState>) {
    let (_, mac) = session_keys(state);
    assert!(database::integrity::verify_integrity(&get_db(state), &mac).unwrap());
}

// ---------------------------------------------------------------------------
// a) Sealed roundtrip + AAD row-binding
// ---------------------------------------------------------------------------

/// Rows saved through the engine are sealed (magic prefix, no plaintext
/// metadata), load back to the same values, and the row-key AAD makes a
/// config↔state row swap fail closed.
#[test]
fn sealed_rows_roundtrip_and_resist_row_swap() {
    let (state, _dir): (Arc<AppState>, TempDir) = test_state();
    let config = test_config();
    let sync_state = sample_sync_state();
    let keys = SessionKeys::copy(&state).unwrap();
    save_sync_rows(&state, &keys, &config, &sync_state, None).unwrap();

    // Sealed on disk: prefix present, plaintext metadata absent.
    let config_row = row_bytes(&state, SYNC_CONFIG_BLOB_KEY);
    assert!(config_row.starts_with(SYNC_ROW_ENC_PREFIX));
    assert!(!contains_substring(&config_row, config.username.as_bytes()));
    assert!(!contains_substring(
        &config_row,
        config.server_url.as_bytes()
    ));
    assert!(row_bytes(&state, SYNC_STATE_BLOB_KEY).starts_with(SYNC_ROW_ENC_PREFIX));

    // Roundtrip through the decrypting loads.
    let (enc, mac) = session_keys(&state);
    let db = get_db(&state);
    let loaded = load_config(&db, &enc, &mac).unwrap().expect("config loads");
    assert_eq!(loaded.username, config.username);
    assert_eq!(loaded.server_url, config.server_url);
    assert_eq!(loaded.remote_dir, config.remote_dir);
    assert_eq!(loaded.backend.as_str(), config.backend.as_str());
    let loaded_state = load_sync_state(&db, &enc, &mac).unwrap();
    assert_eq!(loaded_state.device_id.as_deref(), Some("deadbeef1234"));
    assert_eq!(loaded_state.remote_rev, Some(7));
    assert_eq!(loaded_state.history, sync_state.history);
    assert_digest_verifies(&state);

    // AAD row-binding: swap the two sealed rows — neither opens under the
    // other's key (GCM auth fails), reported as corrupt.
    let state_row = row_bytes(&state, SYNC_STATE_BLOB_KEY);
    write_row(&state, SYNC_CONFIG_BLOB_KEY, &state_row);
    write_row(&state, SYNC_STATE_BLOB_KEY, &config_row);
    assert_corrupt(
        &load_config(&db, &enc, &mac).unwrap_err(),
        "SYNC_CONFIG_CORRUPT",
    );
    assert_corrupt(
        &load_sync_state(&db, &enc, &mac).unwrap_err(),
        "SYNC_STATE_CORRUPT",
    );
}

// ---------------------------------------------------------------------------
// b) Legacy plaintext rows migrate on read
// ---------------------------------------------------------------------------

/// v1.1.x plaintext JSON rows still load, and the very read that parsed them
/// re-seals them in one digest-covered transaction — the username never
/// survives on disk past first read.
#[test]
fn legacy_plaintext_rows_migrate_on_read() {
    let (state, _dir) = test_state();
    let config = test_config();
    let sync_state = sample_sync_state();
    overwrite_rows_with_legacy_plaintext(&state, &config, &sync_state);
    assert!(contains_substring(
        &row_bytes(&state, SYNC_CONFIG_BLOB_KEY),
        config.username.as_bytes()
    ));

    let (enc, mac) = session_keys(&state);
    let db = get_db(&state);
    let loaded = load_config(&db, &enc, &mac)
        .unwrap()
        .expect("legacy row loads");
    assert_eq!(loaded.username, config.username);
    let loaded_state = load_sync_state(&db, &enc, &mac).unwrap();
    assert_eq!(loaded_state.device_id, sync_state.device_id);

    // Both rows are now sealed and plaintext-free; the migration wrote
    // through VaultStore::write, so the digest still verifies.
    let config_row = row_bytes(&state, SYNC_CONFIG_BLOB_KEY);
    assert!(config_row.starts_with(SYNC_ROW_ENC_PREFIX));
    assert!(!contains_substring(&config_row, config.username.as_bytes()));
    assert!(row_bytes(&state, SYNC_STATE_BLOB_KEY).starts_with(SYNC_ROW_ENC_PREFIX));
    assert_digest_verifies(&state);

    // And a second read takes the sealed path (same values, idempotent).
    assert_eq!(
        load_config(&db, &enc, &mac).unwrap().unwrap().username,
        config.username
    );
}

// ---------------------------------------------------------------------------
// c) Tamper fail-closedness
// ---------------------------------------------------------------------------

/// A flipped ciphertext byte (written digest-consistently) fails the GCM
/// authentication and surfaces as a corrupt-row error — never as plaintext
/// garbage or a silent success.
#[test]
fn tampered_sealed_row_fails_closed() {
    let (state, _dir) = test_state();
    let keys = SessionKeys::copy(&state).unwrap();
    save_sync_rows(&state, &keys, &test_config(), &sample_sync_state(), None).unwrap();

    let mut row = row_bytes(&state, SYNC_CONFIG_BLOB_KEY);
    let last = row.len() - 4;
    row[last] ^= 0x5A;
    write_row(&state, SYNC_CONFIG_BLOB_KEY, &row);

    let (enc, mac) = session_keys(&state);
    assert_corrupt(
        &load_config(&get_db(&state), &enc, &mac).unwrap_err(),
        "SYNC_CONFIG_CORRUPT",
    );
}

// ---------------------------------------------------------------------------
// d) Re-seal rotation of LEGACY plaintext rows (the never-migrated upgrader)
// ---------------------------------------------------------------------------

/// The plan's P1 scenario: a user upgraded to v1.2.0 but never opened the
/// sync settings — the rows are still v1.1.9 plaintext. change_password must
/// rotate them (dual-read parse, NOT a bare unwrap) and sync must survive.
#[test]
fn change_password_reseals_legacy_sync_rows_and_sync_survives() {
    let (state, _dir) = test_state();
    let cloud = MockCloudBackend::new();
    super::engine::sync_connect_with_backend(
        &state,
        &cloud,
        test_config(),
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        None,
    )
    .unwrap();

    // Downgrade the two rows to the v1.1.9 plaintext layout.
    let (enc, mac) = session_keys(&state);
    let db = get_db(&state);
    let config_before = load_config(&db, &enc, &mac).unwrap().unwrap();
    let state_before = load_sync_state(&db, &enc, &mac).unwrap();
    overwrite_rows_with_legacy_plaintext(&state, &config_before, &state_before);
    assert!(contains_substring(
        &row_bytes(&state, SYNC_CONFIG_BLOB_KEY),
        config_before.username.as_bytes()
    ));

    crate::change_password(
        &state,
        Zeroizing::new(TEST_PASSWORD.to_string()),
        Zeroizing::new(NEW_PASSWORD.to_string()),
        None,
    )
    .unwrap();

    // Rotated AND sealed: readable under the new keys, plaintext gone.
    let (enc, mac) = session_keys(&state);
    let db = get_db(&state);
    let config_after = load_config(&db, &enc, &mac)
        .unwrap()
        .expect("row readable after reseal");
    assert_eq!(config_after.username, config_before.username);
    assert_eq!(config_after.server_url, config_before.server_url);
    let row = row_bytes(&state, SYNC_CONFIG_BLOB_KEY);
    assert!(row.starts_with(SYNC_ROW_ENC_PREFIX));
    assert!(!contains_substring(&row, config_before.username.as_bytes()));
    assert_digest_verifies(&state);

    // The standing standard: sync keeps working without the container
    // password.
    let status: SyncStatusResponse = super::engine::sync_now_with_backend(&state, &cloud).unwrap();
    assert_eq!(status.last_result.as_deref(), Some("ok"));
}

/// Same fixture through the recovery re-seal path.
#[test]
fn recover_vault_reseals_legacy_sync_rows_and_sync_survives() {
    let (state, _dir) = test_state();
    let cloud = MockCloudBackend::new();
    super::engine::sync_connect_with_backend(
        &state,
        &cloud,
        test_config(),
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        None,
    )
    .unwrap();
    let recovery_key =
        crate::enable_recovery(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();

    let (enc, mac) = session_keys(&state);
    let db = get_db(&state);
    let config_before = load_config(&db, &enc, &mac).unwrap().unwrap();
    let state_before = load_sync_state(&db, &enc, &mac).unwrap();
    overwrite_rows_with_legacy_plaintext(&state, &config_before, &state_before);
    assert!(contains_substring(
        &row_bytes(&state, SYNC_CONFIG_BLOB_KEY),
        config_before.username.as_bytes()
    ));

    crate::recover_vault(
        &state,
        &recovery_key,
        Zeroizing::new(NEW_PASSWORD.to_string()),
    )
    .unwrap();

    let (enc, mac) = session_keys(&state);
    let db = get_db(&state);
    let config_after = load_config(&db, &enc, &mac)
        .unwrap()
        .expect("row readable after reseal");
    assert_eq!(config_after.username, config_before.username);
    let row = row_bytes(&state, SYNC_CONFIG_BLOB_KEY);
    assert!(row.starts_with(SYNC_ROW_ENC_PREFIX));
    assert!(!contains_substring(&row, config_before.username.as_bytes()));
    assert_digest_verifies(&state);

    let status = super::engine::sync_now_with_backend(&state, &cloud).unwrap();
    assert_eq!(status.last_result.as_deref(), Some("ok"));
}

// ---------------------------------------------------------------------------
// validate_config: embedded userinfo (SEC-L2 rider)
// ---------------------------------------------------------------------------

/// `user:pass@host` (and bare `user@host`) in the server URL is rejected;
/// a plain https URL still passes.
#[test]
fn validate_config_rejects_embedded_userinfo() {
    let mut config = test_config();

    config.server_url = "https://user:pass@dav.example.com/dav".to_string();
    assert_corrupt(
        &validate_config(&config).unwrap_err(),
        "SYNC_INVALID_CONFIG",
    );

    config.server_url = "https://user@dav.example.com/dav".to_string();
    assert_corrupt(
        &validate_config(&config).unwrap_err(),
        "SYNC_INVALID_CONFIG",
    );

    // Credentials in a PATH segment are none of the authority's business.
    config.server_url = "https://dav.example.com/dav/user@example.com".to_string();
    assert!(validate_config(&config).is_ok());

    config.server_url = "https://dav.example.com/dav".to_string();
    assert!(validate_config(&config).is_ok());
}
