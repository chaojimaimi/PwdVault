//! v1.8.3 F4: failed sync cycles are persisted into `SyncState.last_result`
//! so the settings "Last sync failed" banner reflects reality (the banner
//! was dead code — `last_result` was only ever written as "ok"). The
//! persistence is best-effort: a locked session (e.g. a lock that fired
//! mid-cycle) skips silently, and the next success overwrites the failure.

use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::backend::MockCloudBackend;
use super::engine::{
    run_sync_cycle_if_due, sync_connect_with_backend, sync_now, sync_now_with_backend,
};
use super::tests_engine::{test_config, test_state, TEST_PASSWORD};
use crate::{AppState, VaultError};
use pwdvault_infrastructure::keychain::{SecretStoreError, SYNC_WEBDAV_PASSWORD_ACCOUNT};

fn instant_ago(secs: u64) -> Option<Instant> {
    Instant::now().checked_sub(Duration::from_secs(secs))
}

fn set_interval(state: &Arc<AppState>, minutes: u32) {
    *state
        .auto_sync_interval_min
        .lock()
        .expect("auto sync interval lock poisoned") = minutes;
}

fn reset_marker(state: &Arc<AppState>) {
    // `sync_connect` primes `last_sync_finished` (mark_cycle_finished) —
    // reset it so the next scheduler tick is due.
    *state.last_sync_finished.lock().unwrap() = instant_ago(600);
}

/// The exact wire shape the SYNC_CREDENTIALS_MISSING failure carries into
/// `last_result`, derived from the real mapping (public message = the
/// sanitized "CODE: message" string, v1.3.2 contract) — no copy drift.
fn credentials_missing_message() -> String {
    super::state_io::sync_secret_error(SecretStoreError::NotFound).public_message()
}

/// Connect an unlocked device and leave the scheduler one tick from firing.
fn connected_and_due(state: &Arc<AppState>) -> MockCloudBackend {
    let cloud = MockCloudBackend::new();
    sync_connect_with_backend(
        state,
        &cloud.handle(),
        test_config(),
        Zeroizing::new("container-passphrase".to_string()),
        Some(Zeroizing::new("webdav-pass".to_string())),
    )
    .unwrap();
    set_interval(state, 5);
    reset_marker(state);
    cloud
}

/// A failed auto-sync cycle must surface its sanitized public message on
/// the status line (red before the fix: `last_result` stayed at the
/// connect-era "ok" forever). The failure is induced OFFLINE: dropping the
/// stored WebDAV password makes the tick's `open_backend` fail with
/// SYNC_CREDENTIALS_MISSING deterministically, before any network I/O.
#[test]
fn auto_cycle_failure_is_persisted_to_sync_state() {
    let (state, _dir) = test_state();
    connected_and_due(&state);

    state
        .sync_secret_store
        .delete(SYNC_WEBDAV_PASSWORD_ACCOUNT)
        .unwrap();

    assert!(run_sync_cycle_if_due(&state));
    let status = crate::sync_status(&state).unwrap();
    assert_eq!(
        status.last_result.as_deref(),
        Some(credentials_missing_message().as_str()),
        "a failed auto cycle must surface its public message on the status line"
    );
}

/// The next successful cycle overwrites a persisted failure back to "ok"
/// (anti-regression pin: green before AND after the fix — a failure cannot
/// be persisted at all before it, so the overwrite is only exercisable
/// afterwards).
#[test]
fn success_overwrites_failure() {
    let (state, _dir) = test_state();
    let cloud = connected_and_due(&state);

    state
        .sync_secret_store
        .delete(SYNC_WEBDAV_PASSWORD_ACCOUNT)
        .unwrap();
    assert!(run_sync_cycle_if_due(&state));

    // Restore the credential and run a successful manual cycle over the
    // mock backend.
    state
        .sync_secret_store
        .set(SYNC_WEBDAV_PASSWORD_ACCOUNT, b"webdav-pass")
        .unwrap();
    sync_now_with_backend(&state, &cloud.handle()).unwrap();

    let status = crate::sync_status(&state).unwrap();
    assert_eq!(status.last_result.as_deref(), Some("ok"));
}

/// The locked-session skip (R1-P3 fold): `sync_now` on a locked vault fails
/// on the lease BEFORE any cycle work; the persistence helper must skip
/// silently (its `SessionKeys::copy` cannot succeed either) — no panic, and
/// the status row is untouched.
#[test]
fn locked_session_skip_is_silent() {
    let (state, _dir) = test_state();
    connected_and_due(&state);

    state.lock_vault();
    let result = sync_now(&state);
    assert!(
        matches!(result, Err(VaultError::VaultLocked)),
        "unexpected result: {result:?}"
    );

    // Unlock and verify the status row was not disturbed by the skipped
    // persistence attempt.
    assert!(crate::unlock_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap());
    let status = crate::sync_status(&state).unwrap();
    assert_eq!(status.last_result.as_deref(), Some("ok"));
}
