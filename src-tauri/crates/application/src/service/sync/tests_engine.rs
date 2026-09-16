//! P3.6 items 4 + 7: sync engine tests against the [`MockCloudBackend`] —
//! two-device convergence, conflict retries, bootstrap gating, the D8
//! exclusive window under concurrent writes, and the reseal inheritance of
//! the `sync_cek` row through change_password / recover_vault.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::backend::{BackendError, CloudBackend, MockCloudBackend, Precondition, RemoteStat};
use super::engine::{
    sync_connect_with_backend, sync_disconnect, sync_now, sync_now_with_backend, sync_status,
    SyncConfig, SyncBackendKind,
};
use crate::service::security::SYNC_CEK_BLOB_KEY;
use crate::{create_entry, AppState, VaultError};
use pwdvault_infrastructure::crypto::{
    kdf::AdaptiveParams, unwrap_secret, WRAP_AAD_SYNC,
};
use pwdvault_infrastructure::database::{self, vault_store::{self, VaultStore}};
use pwdvault_infrastructure::keychain::{MemorySecretStore, SecretStore};

const TEST_PASSWORD: &str = "sync-test-password";
const NEW_PASSWORD: &str = "a-whole-new-password!";
const CONTAINER_PASSWORD: &str = "container-passphrase";

/// One primed, unlocked device: own redb file, weak KDF (fast tests),
/// memory credential stores, session unlocked directly.
fn test_state() -> (Arc<AppState>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(database::init_database(dir.path().join("sync.db")).unwrap());
    let salt = [0x5D; 16];
    let params = AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        pwdvault_infrastructure::crypto::kdf::derive_key_with_params(TEST_PASSWORD, &salt, &params)
            .unwrap();
    let verification = pwdvault_infrastructure::crypto::create_verification_header(
        &master_key, salt, params,
    )
    .unwrap();
    let (enc_key, mac_key) =
        pwdvault_infrastructure::crypto::kdf::derive_subkeys(&master_key, &salt);

    VaultStore::new(&db)
        .write(&mac_key, |txn| {
            vault_store::save_verification_data_in_txn(txn, &verification)?;
            pwdvault_infrastructure::vault_header::save_header_in_txn(
                txn,
                &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
                &enc_key,
            )?;
            vault_store::save_settings_in_txn(txn, &pwdvault_domain::Settings::default())?;
            Ok(())
        })
        .unwrap();

    let state = Arc::new(AppState {
        secret_store: Arc::new(MemorySecretStore::new()) as Arc<dyn SecretStore>,
        sync_secret_store: Arc::new(MemorySecretStore::new()) as Arc<dyn SecretStore>,
        ..AppState::default()
    });
    *state.database.lock().unwrap() = Some(db);
    *state.verification_data.lock().unwrap() = Some(verification);
    state.session.unlock(enc_key, mac_key);
    (state, dir)
}

fn test_config() -> SyncConfig {
    SyncConfig {
        enabled: true,
        backend: SyncBackendKind::Webdav,
        server_url: "https://dav.example.com/dav".to_string(),
        remote_dir: "PwdVault".to_string(),
        username: "user@example.com".to_string(),
    }
}

fn create_entry_titled(state: &Arc<AppState>, title: &str) -> String {
    create_entry(
        state,
        crate::CreateEntryRequest {
            title: title.to_string(),
            url: None,
            username: format!("user-{title}"),
            password: Zeroizing::new(format!("secret-{title}")),
            notes: None,
            tags: vec![],
            group_id: None,
        },
    )
    .unwrap()
    .id
}

fn live_entries(state: &Arc<AppState>) -> Vec<(String, String)> {
    let mut list: Vec<(String, String)> = crate::list_all_entries(state)
        .unwrap()
        .into_iter()
        .map(|summary| (summary.id, summary.title))
        .collect();
    list.sort();
    list
}

// ---------------------------------------------------------------------------
// P3.6 item 4: full-flow convergence
// ---------------------------------------------------------------------------

/// The centerpiece: bootstrap device A onto an empty cloud, join device B,
/// alternate local edits, and prove both AppState copies converge to the
/// same entry set — plus anti-echo (a no-op cycle does not bump the rev).
#[test]
fn two_devices_converge_through_mock_cloud() {
    let (device_a, _dir_a) = test_state();
    let (device_b, _dir_b) = test_state();
    let cloud = MockCloudBackend::new();

    // A: local edit, then bootstrap onto the empty cloud (creates rev 1).
    let alpha = create_entry_titled(&device_a, "alpha");
    let status_a = sync_connect_with_backend(
        &device_a,
        &cloud,
        test_config(),
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        Some(Zeroizing::new("dav-pass".to_string())),
    )
    .unwrap();
    assert_eq!(status_a.remote_rev, Some(1));
    assert!(cloud.stat("PwdVault/pwdvault-sync.pwsync").unwrap().is_some());
    // The bootstrap wrote a manifest for the rev fast path.
    assert!(cloud.stat("PwdVault/pwdvault-sync.manifest.json").unwrap().is_some());
    // The WebDAV password landed in the non-interactive store.
    assert_eq!(
        device_a.sync_secret_store.get("sync-webdav-password").unwrap(),
        b"dav-pass".to_vec()
    );

    // B: joins with the same container password and sees A's entry.
    let status_b = sync_connect_with_backend(
        &device_b,
        &cloud.handle(),
        test_config(),
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        None,
    )
    .unwrap();
    assert_eq!(status_b.remote_rev, Some(1));
    assert_eq!(live_entries(&device_b), vec![(alpha.clone(), "alpha".to_string())]);

    // B edits locally and pushes rev 2; A pulls it and pushes rev 3 with
    // its own new entry.
    let beta = create_entry_titled(&device_b, "beta");
    let status = sync_now_with_backend(&device_b, &cloud.handle()).unwrap();
    assert_eq!(status.remote_rev, Some(2));

    let gamma = create_entry_titled(&device_a, "gamma");
    let status = sync_now_with_backend(&device_a, &cloud).unwrap();
    assert_eq!(status.remote_rev, Some(3));

    // A catches up on B's beta; both devices are now identical.
    sync_now_with_backend(&device_a, &cloud).unwrap();
    sync_now_with_backend(&device_b, &cloud.handle()).unwrap();
    let entries_a = live_entries(&device_a);
    let entries_b = live_entries(&device_b);
    assert_eq!(entries_a.len(), 3);
    assert_eq!(entries_a, entries_b);
    assert!(entries_a.contains(&(alpha, "alpha".to_string())));
    assert!(entries_a.contains(&(beta, "beta".to_string())));
    assert!(entries_a.contains(&(gamma, "gamma".to_string())));

    // Anti-echo: a cycle with nothing new must not bump the remote rev.
    let before = sync_status(&device_a).unwrap().remote_rev;
    sync_now_with_backend(&device_a, &cloud).unwrap();
    assert_eq!(sync_status(&device_a).unwrap().remote_rev, before);

    // The fast path still pushes local edits made while up to date
    // (no remote rev change since our last cycle).
    let _ = create_entry_titled(&device_a, "delta");
    let status = sync_now_with_backend(&device_a, &cloud).unwrap();
    assert_eq!(status.remote_rev, Some(4));
    sync_now_with_backend(&device_b, &cloud.handle()).unwrap();
    assert_eq!(live_entries(&device_b).len(), 4);
}

/// Conflict loop: up to MAX attempts of injected races are absorbed by
/// re-pull + re-merge; beyond that the engine fails with SYNC_CONFLICT and
/// the vault stays intact.
#[test]
fn upload_conflicts_are_retried_then_surface() {
    let (device_a, _dir) = test_state();
    let cloud = MockCloudBackend::new();

    sync_connect_with_backend(
        &device_a,
        &cloud,
        test_config(),
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        None,
    )
    .unwrap();

    // Two injected races: absorbed within the 3-attempt budget.
    cloud.push_conflicts(2);
    let _ = create_entry_titled(&device_a, "survivor");
    let status = sync_now_with_backend(&device_a, &cloud).unwrap();
    assert_eq!(status.last_result.as_deref(), Some("ok"));
    // The bootstrap ran on an empty vault, so "survivor" is the only entry.
    assert_eq!(live_entries(&device_a).len(), 1);

    // More races than attempts: the conflict surfaces, content intact.
    cloud.push_conflicts(4);
    let _ = create_entry_titled(&device_a, "blocked");
    let err = sync_now_with_backend(&device_a, &cloud).unwrap_err();
    assert!(
        matches!(&err, VaultError::InvalidInput { code, .. } if code == "SYNC_CONFLICT"),
        "unexpected error: {err:?}"
    );
    // The vault kept everything written before the failed push.
    assert_eq!(live_entries(&device_a).len(), 2);
    assert!(database::integrity::verify_integrity(
        &get_db(&device_a),
        &device_a.session.get_mac_key().unwrap()
    )
    .unwrap());
}

fn get_db(state: &Arc<AppState>) -> Arc<redb::Database> {
    crate::service::vault::get_db(state).unwrap()
}

// ---------------------------------------------------------------------------
// Bootstrap / session gating
// ---------------------------------------------------------------------------

/// sync_now without a completed bootstrap reports SYNC_NOT_CONFIGURED.
#[test]
fn sync_now_without_bootstrap_is_rejected() {
    let (state, _dir) = test_state();
    let cloud = MockCloudBackend::new();
    let err = sync_now_with_backend(&state, &cloud).unwrap_err();
    assert!(
        matches!(&err, VaultError::InvalidInput { code, .. } if code == "SYNC_NOT_CONFIGURED"),
        "unexpected error: {err:?}"
    );
}

/// Every sync command requires an unlocked session (D2/D5).
#[test]
fn sync_commands_require_unlocked_session() {
    let (state, _dir) = test_state();
    let cloud = MockCloudBackend::new();
    state.session.exclusive_lock_and_clear();

    assert!(matches!(
        sync_connect_with_backend(
            &state,
            &cloud,
            test_config(),
            Zeroizing::new(CONTAINER_PASSWORD.to_string()),
            None,
        ),
        Err(VaultError::VaultLocked)
    ));
    assert!(matches!(sync_now(&state), Err(VaultError::VaultLocked)));
    assert!(matches!(sync_status(&state), Err(VaultError::VaultLocked)));
    assert!(matches!(sync_disconnect(&state), Err(VaultError::VaultLocked)));
}

/// Joining an existing container with the WRONG container password is
/// rejected with the unified container error (no oracle for wrong password
/// vs tampering).
#[test]
fn connect_with_wrong_container_password_is_rejected() {
    let (device_a, _dir_a) = test_state();
    let (device_b, _dir_b) = test_state();
    let cloud = MockCloudBackend::new();

    sync_connect_with_backend(
        &device_a,
        &cloud,
        test_config(),
        Zeroizing::new("right-passphrase".to_string()),
        None,
    )
    .unwrap();

    let err = sync_connect_with_backend(
        &device_b,
        &cloud.handle(),
        test_config(),
        Zeroizing::new("wrong-passphrase".to_string()),
        None,
    )
    .unwrap_err();
    assert!(
        matches!(&err, VaultError::InvalidInput { code, .. } if code == "SYNC_CONTAINER_INVALID"),
        "unexpected error: {err:?}"
    );
}

/// Disconnect removes the local rows but keeps the cloud files (documented
/// semantics), and sync_now afterwards reports not-configured again.
#[test]
fn disconnect_clears_rows_and_keeps_cloud_files() {
    let (state, _dir) = test_state();
    let cloud = MockCloudBackend::new();
    sync_connect_with_backend(
        &state,
        &cloud,
        test_config(),
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        Some(Zeroizing::new("dav-pass".to_string())),
    )
    .unwrap();

    sync_disconnect(&state).unwrap();

    let status = sync_status(&state).unwrap();
    assert!(!status.enabled);
    assert!(status.backend.is_none());
    assert_eq!(status.remote_rev, None);
    // Cloud files survive.
    assert!(cloud.stat("PwdVault/pwdvault-sync.pwsync").unwrap().is_some());
    // Credentials were dropped with the connection.
    assert!(state.sync_secret_store.get("sync-webdav-password").is_err());
    // And a cycle reports the missing bootstrap.
    let err = sync_now_with_backend(&state, &cloud).unwrap_err();
    assert!(
        matches!(&err, VaultError::InvalidInput { code, .. } if code == "SYNC_NOT_CONFIGURED")
    );
}

// ---------------------------------------------------------------------------
// D8 exclusive window under concurrent writes
// ---------------------------------------------------------------------------

/// D8 P0 regression (Phase 1 pattern): writes racing the sync's exclusive
/// window are either accepted before it or rejected with `VaultLocked` —
/// never mixed-key. After the sync the vault passes digest verification and
/// every accepted write is readable.
#[test]
fn concurrent_writes_during_sync_do_not_corrupt_vault() {
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

    // Seed the remote with content from a "second device" so the sync has a
    // real merge to perform inside the window.
    let (device_b, _dir_b) = test_state();
    let remote_entry_id = {
        let handle = cloud.handle();
        sync_connect_with_backend(
            &device_b,
            &handle,
            test_config(),
            Zeroizing::new(CONTAINER_PASSWORD.to_string()),
            None,
        )
        .unwrap();
        create_entry_titled(&device_b, "from-b");
        sync_now_with_backend(&device_b, &handle).unwrap();
        live_entries(&device_b)
            .into_iter()
            .find(|(_, title)| title == "from-b")
            .unwrap()
            .0
    };
    // Bumped the remote rev — device A will pull it in its window.
    let _ = remote_entry_id;

    let entry_ids: Vec<String> = (0..60)
        .map(|index| create_entry_titled(&state, &format!("local-{index}")))
        .collect();
    let entry_ids = Arc::new(entry_ids);
    let stop_writes = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let barrier = Arc::new(std::sync::Barrier::new(3));

    let mut writers = Vec::new();
    for writer in 0..2 {
        let state = Arc::clone(&state);
        let entry_ids = Arc::clone(&entry_ids);
        let stop_writes = Arc::clone(&stop_writes);
        let barrier = Arc::clone(&barrier);
        writers.push(thread::spawn(move || {
            barrier.wait();
            let mut accepted = 0usize;
            let mut rejected = 0usize;
            let mut i = 0usize;
            while !stop_writes.load(std::sync::atomic::Ordering::SeqCst) && i < 5_000 {
                let id = &entry_ids[i % entry_ids.len()];
                let request = crate::UpdateEntryRequest {
                    title: format!("w{writer}-{i}"),
                    url: None,
                    username: format!("writer-{writer}"),
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

    let syncer = {
        let state = Arc::clone(&state);
        let cloud = cloud.handle();
        let stop_writes = Arc::clone(&stop_writes);
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            let result = sync_now_with_backend(&state, &cloud);
            // Release writers only after the sync fully settled, so at
            // least some writes are guaranteed to hit the window.
            stop_writes.store(true, std::sync::atomic::Ordering::SeqCst);
            result
        })
    };

    let sync_result = syncer.join().unwrap();
    let mut total_rejected = 0usize;
    for handle in writers {
        let (_accepted, rejected) = handle.join().unwrap();
        total_rejected += rejected;
    }
    sync_result.unwrap();
    assert!(
        total_rejected > 0,
        "test expects at least one write to hit the exclusive window"
    );

    // The vault is consistent: digest passes, all rows decrypt, and the
    // remote entry arrived through the merge.
    assert_eq!(sync_status(&state).unwrap().last_result.as_deref(), Some("ok"));
    let db = get_db(&state);
    assert!(database::integrity::verify_integrity(
        &db,
        &state.session.get_mac_key().unwrap()
    )
    .unwrap());
    let rows =
        database::list_all_entries_bulk(&db, &state.session.get_enc_key().unwrap(), None).unwrap();
    assert_eq!(rows.len(), 61);
    let titles: Vec<String> = rows.into_iter().map(|row| row.title).collect();
    assert!(titles.iter().any(|title| title == "from-b"));
}

// ---------------------------------------------------------------------------
// P1-1: stale-key guard on the post-window bookkeeping save
// ---------------------------------------------------------------------------

/// Test double wrapping the mock: the Nth `upload` blocks until the test
/// opens the gate. This creates the deterministic P1-1 interleave point —
/// after the D8 window's republish, before `save_sync_rows` runs.
struct GatedBackend {
    inner: MockCloudBackend,
    gate_at: usize,
    uploads_seen: AtomicUsize,
    arrived: (Mutex<bool>, Condvar),
    open: (Mutex<bool>, Condvar),
}

impl GatedBackend {
    fn new(inner: MockCloudBackend, gate_at: usize) -> Self {
        Self {
            inner,
            gate_at,
            uploads_seen: AtomicUsize::new(0),
            arrived: (Mutex::new(false), Condvar::new()),
            open: (Mutex::new(false), Condvar::new()),
        }
    }

    /// Block until the gated upload has been reached.
    fn wait_until_arrived(&self) {
        let (lock, signal) = &self.arrived;
        let mut arrived = lock.lock().unwrap();
        while !*arrived {
            arrived = signal.wait(arrived).unwrap();
        }
    }

    fn open(&self) {
        let (lock, signal) = &self.open;
        *lock.lock().unwrap() = true;
        signal.notify_all();
    }
}

impl CloudBackend for GatedBackend {
    fn stat(&self, path: &str) -> Result<Option<RemoteStat>, BackendError> {
        self.inner.stat(path)
    }

    fn download(&self, path: &str) -> Result<Vec<u8>, BackendError> {
        self.inner.download(path)
    }

    fn upload(
        &self,
        path: &str,
        body: &[u8],
        precondition: Precondition,
    ) -> Result<(), BackendError> {
        let index = self.uploads_seen.fetch_add(1, Ordering::SeqCst);
        if index == self.gate_at {
            {
                let (lock, signal) = &self.arrived;
                *lock.lock().unwrap() = true;
                signal.notify_all();
            }
            let (lock, signal) = &self.open;
            let mut opened = lock.lock().unwrap();
            while !*opened {
                opened = signal.wait(opened).unwrap();
            }
        }
        self.inner.upload(path, body, precondition)
    }

    fn upload_unique(&self, path: &str, body: &[u8]) -> Result<(), BackendError> {
        self.inner.upload_unique(path, body)
    }

    fn delete(&self, path: &str) -> Result<(), BackendError> {
        self.inner.delete(path)
    }
}

/// P1-1 regression: a change_password completing AFTER the sync's D8 window
/// (while the sync is parked in its network push phase) must not let the
/// bookkeeping save refresh the integrity digest / sync_cek with the stale
/// copied keys — that would leave the vault unopenable with the NEW
/// password. The engine skips the save instead (bookkeeping loss only).
#[test]
fn change_password_after_sync_window_does_not_let_stale_keys_write() {
    let (device_a, _dir_a) = test_state();
    let cloud = MockCloudBackend::new();

    // A bootstraps the empty cloud (rev 1, no entries).
    sync_connect_with_backend(
        &device_a,
        &cloud,
        test_config(),
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        None,
    )
    .unwrap();

    // Device B joins, edits, pushes rev 2 — A's next cycle has a real pull
    // and a real push.
    let (device_b, _dir_b) = test_state();
    {
        let handle = cloud.handle();
        sync_connect_with_backend(
            &device_b,
            &handle,
            test_config(),
            Zeroizing::new(CONTAINER_PASSWORD.to_string()),
            None,
        )
        .unwrap();
        create_entry_titled(&device_b, "from-b");
        sync_now_with_backend(&device_b, &handle).unwrap();
    }

    // A local-only edit guarantees the cycle has a PUSH (merge result
    // differs from the remote) — without it a pure pull would skip the
    // upload phase entirely and never reach the gate.
    let _alpha = create_entry_titled(&device_a, "local-only-a");

    // Snapshot the on-disk sync_state row: the guarded save must NOT touch
    // it (still the connect-era row after the run).
    let state_row_before = vault_store::load_blob(&get_db(&device_a), "sync_state")
        .unwrap()
        .expect("sync_state row exists after connect");

    // Gate A's container upload (the cycle's first upload) — exactly between
    // the D8 window's republish and save_sync_rows.
    let gated = Arc::new(GatedBackend::new(cloud.handle(), 0));

    let syncer = {
        let state = Arc::clone(&device_a);
        let gated = Arc::clone(&gated);
        thread::spawn(move || sync_now_with_backend(&state, gated.as_ref()))
    };

    // Wait for the sync to park inside the gated upload: the window has
    // closed and republished the COPIED (old) keys by this point.
    gated.wait_until_arrived();

    // Concurrent key rotation while the sync is parked in its push phase.
    crate::change_password(
        &device_a,
        Zeroizing::new(TEST_PASSWORD.to_string()),
        Zeroizing::new(NEW_PASSWORD.to_string()),
        None,
    )
    .unwrap();

    gated.open();
    // The cycle still succeeds — the save was skipped, not failed.
    syncer.join().unwrap().unwrap();

    // The bookkeeping row was NOT rewritten with the stale keys.
    let state_row_after = vault_store::load_blob(&get_db(&device_a), "sync_state")
        .unwrap()
        .expect("sync_state row survives");
    assert_eq!(state_row_after, state_row_before);

    // The NEW password unlocks and the digest verifies under the NEW keys.
    // Without the guard, the save would have refreshed the digest with the
    // stale mac and bricked the vault for the new password.
    device_a.session.exclusive_lock_and_clear();
    assert!(crate::unlock_vault(&device_a, Zeroizing::new(NEW_PASSWORD.to_string())).unwrap());
    let db = get_db(&device_a);
    assert!(database::integrity::verify_integrity(
        &db,
        &device_a.session.get_mac_key().unwrap()
    )
    .unwrap());

    // The merge itself still landed (the window completed before the
    // rotation) and survived the reseal under the new keys.
    let titles: Vec<String> =
        live_entries(&device_a).into_iter().map(|(_, title)| title).collect();
    assert!(titles.contains(&"from-b".to_string()));
    assert!(titles.contains(&"local-only-a".to_string()));
}

// ---------------------------------------------------------------------------
// P3.6 item 7: reseal inheritance (sync_cek re-wrapped by D8 flows)
// ---------------------------------------------------------------------------

/// change_password rotates the session enc subkey; the sync_cek row must be
/// re-wrapped under the NEW key inside the reseal (D2 inheritance) — the
/// old key must no longer open it, and sync_now must keep working.
#[test]
fn change_password_rewraps_sync_cek_and_sync_survives() {
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

    let old_enc: [u8; 32] = state.session.get_enc_key().unwrap();
    let cek_before = {
        let blob = vault_store::load_blob(&get_db(&state), SYNC_CEK_BLOB_KEY)
            .unwrap()
            .unwrap();
        *unwrap_secret(&old_enc, &blob, WRAP_AAD_SYNC).unwrap()
    };

    crate::change_password(
        &state,
        Zeroizing::new(TEST_PASSWORD.to_string()),
        Zeroizing::new(NEW_PASSWORD.to_string()),
        None,
    )
    .unwrap();

    let new_enc: [u8; 32] = state.session.get_enc_key().unwrap();
    assert_ne!(new_enc, old_enc);
    let blob = vault_store::load_blob(&get_db(&state), SYNC_CEK_BLOB_KEY)
        .unwrap()
        .expect("sync_cek row survives the reseal");
    // New key opens it; the OLD key must not.
    assert_eq!(*unwrap_secret(&new_enc, &blob, WRAP_AAD_SYNC).unwrap(), cek_before);
    assert!(unwrap_secret(&old_enc, &blob, WRAP_AAD_SYNC).is_err());

    // The engine keeps working without the container password.
    let _ = create_entry_titled(&state, "after-change");
    let status = sync_now_with_backend(&state, &cloud).unwrap();
    assert_eq!(status.last_result.as_deref(), Some("ok"));
}

/// recover_vault (the exclusive-path reseal) inherits the same re-wrap.
#[test]
fn recover_vault_rewraps_sync_cek_and_sync_survives() {
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
    let recovery_key =
        crate::enable_recovery(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();

    let old_enc: [u8; 32] = state.session.get_enc_key().unwrap();
    let cek_before = {
        let blob = vault_store::load_blob(&get_db(&state), SYNC_CEK_BLOB_KEY)
            .unwrap()
            .unwrap();
        *unwrap_secret(&old_enc, &blob, WRAP_AAD_SYNC).unwrap()
    };

    crate::recover_vault(
        &state,
        &recovery_key,
        Zeroizing::new(NEW_PASSWORD.to_string()),
    )
    .unwrap();

    let new_enc: [u8; 32] = state.session.get_enc_key().unwrap();
    assert_ne!(new_enc, old_enc);
    let blob = vault_store::load_blob(&get_db(&state), SYNC_CEK_BLOB_KEY)
        .unwrap()
        .expect("sync_cek row survives the recovery reseal");
    assert_eq!(*unwrap_secret(&new_enc, &blob, WRAP_AAD_SYNC).unwrap(), cek_before);
    assert!(unwrap_secret(&old_enc, &blob, WRAP_AAD_SYNC).is_err());

    let status = sync_now_with_backend(&state, &cloud).unwrap();
    assert_eq!(status.last_result.as_deref(), Some("ok"));
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
