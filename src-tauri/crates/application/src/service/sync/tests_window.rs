//! Fix plan A (P0) regression suite: D8 exclusive-window serialization,
//! digest pre-verification fallout, mid-window lock semantics, and the
//! M5 history-rotation cap. The deterministic interleave points come from
//! the one-shot, instance-scoped `WindowGate` seams on `AppState` (parked
//! right after each window's drain — review P3-2: instance-scoped so the
//! parallel test suite is never disturbed).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::backend::{BackendError, CloudBackend, MockCloudBackend, Precondition, RemoteStat};
use super::engine::{sync_connect_with_backend, sync_now_with_backend, HISTORY_KEEP};
use super::tests_engine::{
    create_entry_titled, test_config, test_state, CONTAINER_PASSWORD, NEW_PASSWORD, TEST_PASSWORD,
};
use crate::{change_password, list_all_entries, AppState, VaultError};
use pwdvault_infrastructure::crypto::bc_deserialize;
use pwdvault_infrastructure::database;

/// Settle time for a spawned unlock thread. The unlock must pass the
/// verification-capture point (the mutex clone at the top of
/// `unlock_vault`/`unlock_biometric`) BEFORE the gated window's re-seal
/// replaces the verification row — the capture happens microseconds after
/// spawn (rate-limit check + clone), while derivation (weak test KDF) plus
/// the pre-window verification chain finish in well under this budget, so
/// after the settle the unlock is parked on `exclusive_window` (held by the
/// changer) and the gate can be released deterministically. See T1.
const UNLOCK_SETTLE_MS: u64 = 500;

/// Ids + titles of the live entries of a device (test assertion helper).
fn live_titles(state: &Arc<AppState>) -> Vec<String> {
    let mut titles: Vec<String> = list_all_entries(state)
        .unwrap()
        .into_iter()
        .map(|summary| summary.title)
        .collect();
    titles.sort();
    titles
}

/// Bootstrap the shared test topology: device A connected at rev 1, device
/// B connected and having pushed one extra entry ("from-b") at rev 2. A's
/// next sync cycle therefore has a real pull + merge to run in its window.
fn connected_pair_with_remote_entry() -> (Arc<AppState>, MockCloudBackend, TempDir) {
    let (device_a, dir_a) = test_state();
    let cloud = MockCloudBackend::new();
    sync_connect_with_backend(
        &device_a,
        &cloud,
        test_config(),
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        None,
    )
    .unwrap();

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
    (device_a, cloud, dir_a)
}

// ---------------------------------------------------------------------------
// Case 1: sync parked inside its window → change_password cannot overlap
// ---------------------------------------------------------------------------

/// While the sync's exclusive window is open (parked after its drain), a
/// concurrent change_password fails fast on the drained session instead of
/// interleaving. After the window settles, the change goes through and
/// leaves a fully consistent vault: new password unlocks, digest verifies,
/// every row decrypts under the NEW keys (no stale old-key rows).
#[test]
fn sync_window_and_change_password_cannot_overlap() {
    let (device_a, cloud, _dir) = connected_pair_with_remote_entry();

    device_a.merge_window_gate.arm();
    let syncer = {
        let state = Arc::clone(&device_a);
        let cloud = cloud.handle();
        thread::spawn(move || sync_now_with_backend(&state, &cloud))
    };
    device_a.merge_window_gate.wait_until_arrived();

    // The change cannot even start: its lease fails against the drained
    // session (fix plan A §2.1 — serialization, not interleave).
    let change = change_password(
        &device_a,
        Zeroizing::new(TEST_PASSWORD.to_string()),
        Zeroizing::new(NEW_PASSWORD.to_string()),
        None,
    );
    assert!(
        matches!(change, Err(VaultError::VaultLocked)),
        "unexpected result: {change:?}"
    );

    device_a.merge_window_gate.open();
    syncer.join().unwrap().unwrap();

    // Now the change runs normally and leaves a consistent vault.
    change_password(
        &device_a,
        Zeroizing::new(TEST_PASSWORD.to_string()),
        Zeroizing::new(NEW_PASSWORD.to_string()),
        None,
    )
    .unwrap();
    device_a.session.exclusive_lock_and_clear();
    assert!(!crate::unlock_vault(&device_a, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap());
    assert!(crate::unlock_vault(&device_a, Zeroizing::new(NEW_PASSWORD.to_string())).unwrap());

    let db = crate::service::vault::get_db(&device_a).unwrap();
    assert!(
        database::integrity::verify_integrity(&db, &device_a.session.get_mac_key().unwrap())
            .unwrap()
    );
    // Every row re-sealed under the new keys: the full bulk read succeeds.
    let titles = live_titles(&device_a);
    assert!(titles.contains(&"from-b".to_string()));
}

// ---------------------------------------------------------------------------
// Case 2: change_password parked inside its window → sync fails cleanly
// ---------------------------------------------------------------------------

/// A sync cycle firing while the re-seal window is open fails explicitly
/// (retriable) — the remote entry is NOT silently lost: nothing merges, and
/// the retry after the change pulls it under the new keys.
#[test]
fn change_password_window_sync_fails_cleanly_and_retry_converges() {
    let (device_a, cloud, _dir) = connected_pair_with_remote_entry();
    assert!(!live_titles(&device_a).contains(&"from-b".to_string()));

    device_a.reseal_window_gate.arm();
    let changer = {
        let state = Arc::clone(&device_a);
        thread::spawn(move || {
            change_password(
                &state,
                Zeroizing::new(TEST_PASSWORD.to_string()),
                Zeroizing::new(NEW_PASSWORD.to_string()),
                None,
            )
        })
    };
    device_a.reseal_window_gate.wait_until_arrived();

    // The cycle's key copy fails against the drained session: explicit,
    // retriable failure — no silent partial merge.
    let err = sync_now_with_backend(&device_a, &cloud.handle()).unwrap_err();
    assert!(
        matches!(err, VaultError::VaultLocked),
        "unexpected: {err:?}"
    );

    device_a.reseal_window_gate.open();
    changer.join().unwrap().unwrap();

    // The retry converges: the remote entry arrives under the NEW keys.
    let status = sync_now_with_backend(&device_a, &cloud.handle()).unwrap();
    assert_eq!(status.last_result.as_deref(), Some("ok"));
    assert!(live_titles(&device_a).contains(&"from-b".to_string()));
    let db = crate::service::vault::get_db(&device_a).unwrap();
    assert!(
        database::integrity::verify_integrity(&db, &device_a.session.get_mac_key().unwrap())
            .unwrap()
    );
}

// ---------------------------------------------------------------------------
// Case 4: mid-window lock is never silently revoked
// ---------------------------------------------------------------------------

/// Locking while the sync window is parked must stand: the window's
/// republish is skipped, the sync reports VaultLocked (retriable; the
/// in-window outcome is logged), and the old password still opens the
/// vault (sync never rotates keys) with a consistent digest.
#[test]
fn lock_during_sync_window_is_not_silently_revoked() {
    let (device_a, cloud, _dir) = connected_pair_with_remote_entry();

    device_a.merge_window_gate.arm();
    let syncer = {
        let state = Arc::clone(&device_a);
        let cloud = cloud.handle();
        thread::spawn(move || sync_now_with_backend(&state, &cloud))
    };
    device_a.merge_window_gate.wait_until_arrived();

    // The user (or auto-lock) locks while the window runs.
    device_a.lock_vault();
    device_a.merge_window_gate.open();

    let result = syncer.join().unwrap();
    assert!(
        matches!(result, Err(VaultError::VaultLocked)),
        "unexpected result: {result:?}"
    );
    assert!(!device_a.is_unlocked());

    // The lock stands; the vault still opens with the OLD password and the
    // merge that committed inside the window is consistent on disk.
    assert!(crate::unlock_vault(&device_a, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap());
    let db = crate::service::vault::get_db(&device_a).unwrap();
    assert!(
        database::integrity::verify_integrity(&db, &device_a.session.get_mac_key().unwrap())
            .unwrap()
    );
}

/// Locking while the change-password window runs: the re-seal commits (Ok)
/// but the publish is skipped — the session stays Locked and the observable
/// "password was changed" semantics are exact: the old password no longer
/// works, the new password unlocks the vault.
#[test]
fn lock_during_change_password_window_keeps_new_password_semantics() {
    let (device_a, _dir) = test_state();

    device_a.reseal_window_gate.arm();
    let changer = {
        let state = Arc::clone(&device_a);
        thread::spawn(move || {
            change_password(
                &state,
                Zeroizing::new(TEST_PASSWORD.to_string()),
                Zeroizing::new(NEW_PASSWORD.to_string()),
                None,
            )
        })
    };
    device_a.reseal_window_gate.wait_until_arrived();

    device_a.lock_vault();
    device_a.reseal_window_gate.open();

    // The disk change was committed → reported as Ok (the lock screen takes
    // over), but the session was NOT resurrected.
    changer.join().unwrap().unwrap();
    assert!(!device_a.is_unlocked());

    // Old password unusable, new password unlocks.
    assert!(!crate::unlock_vault(&device_a, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap());
    assert!(crate::unlock_vault(&device_a, Zeroizing::new(NEW_PASSWORD.to_string())).unwrap());
    let db = crate::service::vault::get_db(&device_a).unwrap();
    assert!(
        database::integrity::verify_integrity(&db, &device_a.session.get_mac_key().unwrap())
            .unwrap()
    );
}

// ---------------------------------------------------------------------------
// Case 6 (SEC-M1): unlock waits on the D8 window and re-checks the
// verification fingerprint — a re-seal finishing in between is rejected
// with VAULT_STATE_CHANGED instead of publishing stale keys.
// ---------------------------------------------------------------------------

/// Arm the reseal gate, start `change_password(current → new)` and wait
/// until it has drained the session and parked inside its D8 window (the
/// gate seam sits right after the drain, before the re-seal transaction).
fn park_change_password(
    state: &Arc<AppState>,
    current: &str,
    new: &str,
) -> thread::JoinHandle<Result<(), VaultError>> {
    state.reseal_window_gate.arm();
    let changer_state = Arc::clone(state);
    let current = Zeroizing::new(current.to_string());
    let new = Zeroizing::new(new.to_string());
    let changer = thread::spawn(move || change_password(&changer_state, current, new, None));
    state.reseal_window_gate.wait_until_arrived();
    changer
}

/// Join an unlock thread result and require the SEC-M1 window rejection:
/// `VAULT_STATE_CHANGED` (one error site shared by the password and
/// biometric paths).
fn assert_vault_state_changed<T: std::fmt::Debug>(result: Result<T, VaultError>) {
    match result {
        Err(VaultError::InvalidInput { code, message }) => {
            assert_eq!(code, "VAULT_STATE_CHANGED");
            assert!(message.contains("retry unlock"), "{message}");
        }
        other => panic!("expected VAULT_STATE_CHANGED, got {other:?}"),
    }
}

/// Write through an existing handle while the window is parked: the drained
/// session refuses new leases with VaultLocked.
fn assert_write_rejected_during_window(state: &Arc<AppState>) {
    let write = crate::create_entry(
        state,
        crate::CreateEntryRequest {
            title: "during-window".to_string(),
            url: None,
            username: "user".to_string(),
            password: Zeroizing::new("pw".to_string()),
            notes: None,
            tags: vec![],
            group_id: None,
        },
    );
    assert!(matches!(write, Err(VaultError::VaultLocked)), "{write:?}");
}

/// Full AEAD read-back after the re-seal: the bulk read must return exactly
/// the pre-window rows (count match + plaintext password verified per row)
/// — no orphaned or half-re-sealed rows — and the live service view and
/// session must agree.
fn assert_rows_read_back(state: &Arc<AppState>, ids: &[String], before: &[String]) {
    let db = crate::service::vault::get_db(state).unwrap();
    let enc = state.session.get_enc_key().unwrap();
    let entries = database::list_all_entries_bulk(&db, &enc, None).unwrap();
    assert_eq!(entries.len(), ids.len());
    for id in ids {
        let entry = database::load_entry(&db, &enc, id, false)
            .unwrap()
            .expect("pre-window entry must survive the re-seal");
        let sealed: pwdvault_infrastructure::crypto::EncryptedData =
            bc_deserialize(&entry.encrypted_password).unwrap();
        let plain = pwdvault_infrastructure::crypto::decrypt(&enc, &sealed).unwrap();
        assert_eq!(
            String::from_utf8(plain).unwrap(),
            format!("secret-{}", entry.title)
        );
    }
    assert_eq!(live_titles(state), before);
    assert!(state.is_unlocked());
}

/// The window's verification replacement strictly follows `gate.open()`;
/// the unlock's capture strictly precedes it (UNLOCK_SETTLE_MS). Both sides
/// of the ordering are therefore deterministic.
#[test]
fn unlock_vs_change_password() {
    let (device_a, _dir) = test_state();

    let changer = park_change_password(&device_a, TEST_PASSWORD, NEW_PASSWORD);
    let unlocker = {
        let state = Arc::clone(&device_a);
        thread::spawn(move || {
            crate::unlock_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string()))
        })
    };
    thread::sleep(Duration::from_millis(UNLOCK_SETTLE_MS));
    device_a.reseal_window_gate.open();
    changer.join().unwrap().unwrap();

    // The raced unlock (old password, pre-change expectation) must be
    // rejected by the window re-check — never published.
    assert_vault_state_changed(unlocker.join().unwrap());

    // No stale publish: the new password owns the vault, the old is dead.
    device_a.lock_vault();
    assert!(!crate::unlock_vault(&device_a, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap());
    assert!(crate::unlock_vault(&device_a, Zeroizing::new(NEW_PASSWORD.to_string())).unwrap());
    let db = crate::service::vault::get_db(&device_a).unwrap();
    assert!(
        database::integrity::verify_integrity(&db, &device_a.session.get_mac_key().unwrap())
            .unwrap()
    );
}

/// While the re-seal window parks: (a) a raced password unlock is rejected
/// with VAULT_STATE_CHANGED, (b) a write through an existing handle is
/// rejected with VaultLocked (the session is drained — no publish path
/// exists inside the window at all). After the change, every row reads back
/// under the NEW keys with the exact pre-window count and content: the
/// orphan-row hazard (stale-key rows surviving the re-seal) is unreachable
/// by construction, and this test pins that invariant.
#[test]
fn no_orphan_row_invariant() {
    let (device_a, _dir) = test_state();
    let mut ids = Vec::new();
    for title in ["alpha", "beta", "gamma"] {
        ids.push(create_entry_titled(&device_a, title));
    }
    let before = live_titles(&device_a);

    let changer = park_change_password(&device_a, TEST_PASSWORD, NEW_PASSWORD);
    let unlocker = {
        let state = Arc::clone(&device_a);
        thread::spawn(move || {
            crate::unlock_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string()))
        })
    };
    // (b) write through an existing handle while parked: drained session.
    assert_write_rejected_during_window(&device_a);
    thread::sleep(Duration::from_millis(UNLOCK_SETTLE_MS));
    device_a.reseal_window_gate.open();
    changer.join().unwrap().unwrap();

    // (a) the raced unlock was rejected (see `unlock_vs_change_password`).
    assert_vault_state_changed(unlocker.join().unwrap());

    // (c) full AEAD read-back: exactly the pre-window rows, all decryptable
    // under the NEW enc key, no orphans and no "during-window" row.
    assert_rows_read_back(&device_a, &ids, &before);
}

/// Same interlock for the Touch ID unlock path (SEC-M1 T3): the expectation
/// is captured before the credential-store read, and a re-seal completing
/// while the "prompt" is answered makes `complete_unlock` reject the stale
/// keys. Uses the security fixtures (weak KDF, memory credential store),
/// promoted to `pub(crate)` for this suite.
#[test]
fn biometric_unlock_vs_window() {
    use crate::service::security::tests::{
        create_test_vault, NEW_PASSWORD as BIO_NEW_PASSWORD, TEST_PASSWORD as BIO_TEST_PASSWORD,
    };

    let vault = create_test_vault(2, 1);
    assert!(
        crate::unlock_vault(&vault.state, Zeroizing::new(BIO_TEST_PASSWORD.to_string())).unwrap()
    );
    crate::enable_biometric(
        &vault.state,
        Zeroizing::new(BIO_TEST_PASSWORD.to_string()),
        vault.store.as_ref(),
    )
    .unwrap();

    let changer = park_change_password(&vault.state, BIO_TEST_PASSWORD, BIO_NEW_PASSWORD);
    let bio_unlocker = {
        let state = Arc::clone(&vault.state);
        let store = Arc::clone(&vault.store);
        thread::spawn(move || crate::unlock_biometric(&state, store.as_ref()))
    };
    thread::sleep(Duration::from_millis(UNLOCK_SETTLE_MS));
    vault.state.reseal_window_gate.open();
    changer.join().unwrap().unwrap();

    assert_vault_state_changed(bio_unlocker.join().unwrap());
    // A state-change rejection is transparent: no failed attempt recorded.
    assert_eq!(*vault.state.failed_unlock_attempts.lock().unwrap(), 0);

    // The disk belongs to the new password; the re-wrapped bio blob still
    // opens the vault with the SAME keychain item.
    vault.state.lock_vault();
    assert!(
        !crate::unlock_vault(&vault.state, Zeroizing::new(BIO_TEST_PASSWORD.to_string())).unwrap()
    );
    crate::unlock_biometric(&vault.state, vault.store.as_ref()).unwrap();
    assert!(vault.state.is_unlocked());
    assert!(vault.state.session.cached_wrap_key().is_some());
}

// ---------------------------------------------------------------------------
// Case 5 (M5): history rotation cap + failed-delete backfill
// ---------------------------------------------------------------------------

/// Mock wrapper recording history `upload_unique`/`delete` traffic and able
/// to fail EXACTLY one delete — the M5 injection point (the mock's `delete`
/// used to be a pass-through). Only `rotate_history` uses those two trait
/// methods, so the counters track the cloud history directory exactly.
struct HistoryProbeBackend {
    inner: MockCloudBackend,
    fail_next_delete: AtomicBool,
    history_uploads: Mutex<Vec<String>>,
    history_deletes: Mutex<Vec<String>>,
    failed_delete_target: Mutex<Option<String>>,
}

impl HistoryProbeBackend {
    fn new() -> Self {
        Self {
            inner: MockCloudBackend::new(),
            fail_next_delete: AtomicBool::new(false),
            history_uploads: Mutex::new(Vec::new()),
            history_deletes: Mutex::new(Vec::new()),
            failed_delete_target: Mutex::new(None),
        }
    }

    /// Arm the one-shot delete failure.
    fn fail_next_delete(&self) {
        self.fail_next_delete.store(true, Ordering::SeqCst);
    }

    /// Live cloud history files = uploads − successful deletes.
    fn history_live(&self) -> usize {
        let uploads = self.history_uploads.lock().unwrap().len();
        let deletes = self.history_deletes.lock().unwrap().len();
        uploads - deletes
    }

    fn failed_delete_target(&self) -> Option<String> {
        self.failed_delete_target.lock().unwrap().clone()
    }
}

impl CloudBackend for HistoryProbeBackend {
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
        self.inner.upload(path, body, precondition)
    }

    fn upload_unique(&self, path: &str, body: &[u8]) -> Result<(), BackendError> {
        self.history_uploads.lock().unwrap().push(path.to_string());
        self.inner.upload_unique(path, body)
    }

    fn delete(&self, path: &str) -> Result<(), BackendError> {
        if self.fail_next_delete.swap(false, Ordering::SeqCst) {
            *self.failed_delete_target.lock().unwrap() = Some(path.to_string());
            return Err(BackendError::Network("injected delete failure".to_string()));
        }
        self.history_deletes.lock().unwrap().push(path.to_string());
        self.inner.delete(path)
    }
}

/// Publishing more than HISTORY_KEEP revisions caps the cloud history at
/// the limit; a failed prune keeps the name (retained on the rotation
/// list, exceeding the cap by one) and the NEXT successful publish
/// backfills the deletion.
#[test]
fn rotate_history_caps_cloud_history_and_backfills_failed_delete() {
    let (device_a, _dir) = test_state();
    let probe = HistoryProbeBackend::new();

    sync_connect_with_backend(
        &device_a,
        &probe,
        test_config(),
        Zeroizing::new(CONTAINER_PASSWORD.to_string()),
        None,
    )
    .unwrap();
    // The bootstrap publish carries no history.
    assert_eq!(probe.history_live(), 0);

    // KEEP-1 clean cycles: the rotation list fills up without pruning...
    for index in 0..HISTORY_KEEP - 1 {
        create_entry_titled(&device_a, &format!("hist-{index}"));
        sync_now_with_backend(&device_a, &probe).unwrap();
    }
    assert_eq!(probe.history_live(), HISTORY_KEEP - 1);

    // ...and the KEEP-th publish lands exactly ON the cap (prune runs only
    // ABOVE it — the cap itself is respected).
    create_entry_titled(&device_a, "hist-cap");
    sync_now_with_backend(&device_a, &probe).unwrap();
    assert_eq!(probe.history_live(), HISTORY_KEEP);

    // The next publish exceeds the cap; its prune is the first delete →
    // inject the failure there. The name must be RETAINED (still on the
    // cloud and on the rotation list → live count = cap + 1).
    probe.fail_next_delete();
    create_entry_titled(&device_a, "hist-over");
    sync_now_with_backend(&device_a, &probe).unwrap();
    let failed_name = probe.failed_delete_target().expect("prune was attempted");
    assert_eq!(probe.history_live(), HISTORY_KEEP + 1);

    // The next successful publish backfills: deletes the retained name and
    // settles the cloud history back at the cap.
    create_entry_titled(&device_a, "hist-after");
    sync_now_with_backend(&device_a, &probe).unwrap();
    assert_eq!(probe.history_live(), HISTORY_KEEP);
    assert!(
        probe.inner.get_file(&failed_name).is_none(),
        "retained history name must be pruned by the next publish"
    );
}
