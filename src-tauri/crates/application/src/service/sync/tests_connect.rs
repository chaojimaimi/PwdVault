//! Connect-flow regression tests (real `sync_connect`, no test seam).

use std::sync::Arc;

use zeroize::Zeroizing;

use super::engine::{sync_connect, SyncConfig, SyncBackendKind};
use super::tests_engine::{test_state, CONTAINER_PASSWORD};
use crate::VaultError;
use pwdvault_infrastructure::keychain::{SecretStore, SYNC_WEBDAV_PASSWORD_ACCOUNT};

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
