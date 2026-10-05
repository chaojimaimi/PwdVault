//! SEC-L5 (v1.2.0) touch-policy regression tests that need a REAL service
//! call: every service-layer lease touch must extend the short REMOTE grace
//! window, never the full local auto-lock window. The deadline-semantics
//! tests live in [`crate::session`]; this file proves the bright-line service rule
//! end to end through the public service API.

use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;

use crate::{service, AppState};
use pwdvault_infrastructure::crypto;
use pwdvault_infrastructure::database::{self, Settings};

/// Minimal unlocked modern vault — same fixture pattern as
/// recovery_file.rs (verification + integrity header + settings row), which
/// `get_settings` needs for its lease + DB reads.
fn unlocked_state() -> (Arc<AppState>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(database::init_database(dir.path().join("touch.db")).unwrap());
    let salt = [0x41; 16];
    let params = crypto::kdf::AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        crypto::kdf::derive_key_with_params("touch-policy-test", &salt, &params).unwrap();
    let verification = crypto::create_verification_header(&master_key, salt, params).unwrap();
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);

    database::vault_store::VaultStore::new(&db)
        .write(&mac_key, |txn| {
            database::vault_store::save_verification_data_in_txn(txn, &verification)?;
            pwdvault_infrastructure::vault_header::save_header_in_txn(
                txn,
                &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
                &enc_key,
            )?;
            database::vault_store::save_settings_in_txn(txn, &Settings::default())?;
            Ok(())
        })
        .unwrap();

    let state = Arc::new(AppState::default());
    *state.database.lock().unwrap() = Some(db);
    state.session.unlock(enc_key, mac_key);
    (state, dir)
}

/// A service operation must touch the REMOTE activity slot, not the local
/// auto-lock window: the full-window deadline stays pinned to the unlock
/// instant, while the pending grace blocks auto-lock even with an already
/// expired local window (timeout=0).
#[test]
fn service_op_touches_remote_not_local() {
    let (state, _dir) = unlocked_state();

    // Baseline: the full-window deadline comes from the unlock alone.
    let full_window = state.session.auto_lock_deadline(600).unwrap();
    std::thread::sleep(Duration::from_millis(10));

    // A real service op exercising the lease-touch path.
    service::get_settings(&state).expect("get_settings must succeed");

    // The LOCAL window did not move: with a long timeout the deadline is
    // still unlock + 600s. (A local touch would have pushed it forward and
    // this comparison would fail.)
    assert_eq!(
        state.session.auto_lock_deadline(600).unwrap(),
        full_window,
        "a service op must not extend the full local auto-lock window"
    );

    // The REMOTE grace slot did move: even with the local window expired
    // (timeout=0), the pending grace blocks the lock decision.
    assert!(
        !state.session.should_auto_lock(0),
        "a service op must arm the remote grace window"
    );
}
