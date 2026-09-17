//! Connect-flow regression tests (real `sync_connect`, no test seam).

use std::sync::Arc;

use zeroize::Zeroizing;

use super::backend::MockCloudBackend;
use super::engine::{sync_connect, sync_connect_with_backend, SyncBackendKind, SyncConfig};
use super::tests_engine::{
    test_config, test_state, CONTAINER_PASSWORD, NEW_PASSWORD, TEST_PASSWORD,
};
use crate::service::security::SYNC_CEK_BLOB_KEY;
use crate::service::vault;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::database::vault_store::{self, VaultStore};
use pwdvault_infrastructure::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT;

fn get_db(state: &Arc<AppState>) -> Arc<redb::Database> {
    vault::get_db(state).unwrap()
}

/// Manual-QA regression: the REAL `sync_connect` (no test seam) must persist
/// the WebDAV password BEFORE resolving the backend — `open_backend` reads it
/// from the store, and on first-ever connect the store is empty, so the old
/// order failed every initial connect with SYNC_CREDENTIALS_MISSING.
#[test]
fn first_time_connect_stores_webdav_password_before_backend() {
    let (state, _dir) = test_state();
    // Unreachable server (discard port): connection refused immediately, so
    // the connect fails at the network step — far past the credential store.
    let config = SyncConfig {
        enabled: true,
        backend: SyncBackendKind::Webdav,
        server_url: "http://127.0.0.1:9".to_string(),
        remote_dir: "PwdVault".to_string(),
        username: "user@example.com".to_string(),
    };

    let result = sync_connect(
        &state,
        config,
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        Some(Zeroizing::new("dav-pass".to_string())),
    );

    // The failure must come from the (deliberately unreachable) network, NOT
    // from missing credentials.
    match &result {
        Err(VaultError::InvalidInput { code, .. }) => {
            assert_ne!(code.as_str(), "SYNC_CREDENTIALS_MISSING");
        }
        Err(other) => panic!("unexpected error shape: {other}"),
        Ok(_) => panic!("unreachable server must not connect"),
    }

    // And the credential is now persisted for the next attempt.
    assert_eq!(
        state
            .sync_secret_store
            .get(SYNC_WEBDAV_PASSWORD_ACCOUNT)
            .unwrap(),
        b"dav-pass".to_vec()
    );
}

/// A corrupt sync_cek row fails the reseal CLOSED: the whole password
/// change aborts (disk unchanged) instead of stranding an undecryptable
/// sync key (D2 fail-closed rule).
#[test]
fn corrupt_sync_cek_aborts_reseal_fail_closed() {
    let (state, _dir) = test_state();
    let cloud = MockCloudBackend::new();
    sync_connect_with_backend(
        &state,
        &cloud,
        test_config(),
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        None,
    )
    .unwrap();

    // Corrupt the stored cek blob (in place, same digest — do it through a
    // VaultStore::write so the integrity digest stays consistent).
    {
        let db = get_db(&state);
        let store = VaultStore::new(&db);
        store
            .write(&state.session.get_mac_key().unwrap(), |txn| {
                vault_store::save_blob_in_txn(txn, SYNC_CEK_BLOB_KEY, &[0u8; 48])
            })
            .unwrap();
    }

    let result = crate::change_password(
        &state,
        Zeroizing::new(TEST_PASSWORD.to_string()),
        Zeroizing::new(NEW_PASSWORD.to_string()),
        None,
    );
    assert!(matches!(result, Err(VaultError::WrapBlobCorrupt)));
    // Disk unchanged: the old password still unlocks.
    assert!(!crate::unlock_vault(&state, Zeroizing::new(NEW_PASSWORD.to_string())).unwrap());
    assert!(crate::unlock_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap());
}
