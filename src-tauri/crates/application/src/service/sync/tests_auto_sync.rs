//! v1.6.0 (D6): the timed auto-sync scheduler — the pure due-gate state
//! machine, the tick entry point's skip/run semantics (locked, disabled,
//! busy, not-due), marker refresh on success AND failure, the mock-backend
//! full cycle, and the manual `sync_now` blocking-lock contract.

use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::backend::MockCloudBackend;
use super::engine::{
    auto_sync_due, run_sync_cycle_if_due, sync_connect_with_backend, sync_now,
    sync_now_with_backend, sync_now_with_backend_and_trigger, SyncTrigger,
};
use super::tests_engine::{test_config, test_state};

fn instant_ago(secs: u64) -> Option<Instant> {
    Instant::now().checked_sub(Duration::from_secs(secs))
}

fn set_interval(state: &Arc<crate::AppState>, minutes: u32) {
    *state
        .auto_sync_interval_min
        .lock()
        .expect("auto sync interval lock poisoned") = minutes;
}

fn last_finished(state: &Arc<crate::AppState>) -> Option<Instant> {
    *state
        .last_sync_finished
        .lock()
        .expect("last sync finished lock poisoned")
}

/// One connected, unlocked device primed for an immediate scheduler tick:
/// the connect primes `last_sync_finished`, so the tests reset it here.
fn connected_and_due(state: &Arc<crate::AppState>) -> MockCloudBackend {
    let cloud = MockCloudBackend::new();
    // The WebDAV password must be in the non-interactive store for the
    // tick's `open_backend` to construct the real WebDAV backend.
    sync_connect_with_backend(
        state,
        &cloud.handle(),
        test_config(),
        Zeroizing::new("container-passphrase".to_string()),
        Some(Zeroizing::new("webdav-pass".to_string())),
    )
    .unwrap();
    set_interval(state, 5);
    *state.last_sync_finished.lock().unwrap() = instant_ago(600);
    cloud
}

// ---------------------------------------------------------------------------
// The pure gate
// ---------------------------------------------------------------------------

#[test]
fn gate_requires_unlock_and_nonzero_interval() {
    let now = Instant::now();
    // Locked (or locked-and-enabled) never fires.
    assert!(!auto_sync_due(5, false, None, now));
    assert!(!auto_sync_due(5, false, instant_ago(600), now));
    // Unlocked but disabled (the default) never fires.
    assert!(!auto_sync_due(0, true, None, now));
}

#[test]
fn gate_fires_on_never_synced_and_after_the_interval() {
    // No finished cycle this process: due on the first eligible tick.
    assert!(auto_sync_due(5, true, None, Instant::now()));
    // Marker younger than the interval: not yet.
    let now = Instant::now();
    let fresh = now.checked_sub(Duration::from_secs(299)).unwrap();
    assert!(!auto_sync_due(5, true, Some(fresh), now));
    // At exactly the interval boundary: due (>= semantics).
    let now = Instant::now();
    let boundary = now.checked_sub(Duration::from_secs(300)).unwrap();
    assert!(auto_sync_due(5, true, Some(boundary), now));
    // Older than the interval: due.
    let now = Instant::now();
    let old = now.checked_sub(Duration::from_secs(3_600)).unwrap();
    assert!(auto_sync_due(15, true, Some(old), now));
}

// ---------------------------------------------------------------------------
// The tick entry point
// ---------------------------------------------------------------------------

/// A locked vault (or a disabled interval — the default) skips silently and
/// leaves the marker untouched.
#[test]
fn tick_skips_when_locked_or_disabled() {
    let (state, _dir) = test_state();
    // Disabled (interval 0 — the default): skipped even though unlocked.
    assert!(!run_sync_cycle_if_due(&state));
    assert_eq!(last_finished(&state), None);

    // Locked: skipped even when enabled with no marker.
    set_interval(&state, 15);
    state.lock_vault();
    assert!(!run_sync_cycle_if_due(&state));
    assert_eq!(last_finished(&state), None);
}

/// A busy cycle mutex (manual sync or another automatic cycle in flight)
/// means this tick is skipped — never queued.
#[test]
fn tick_skips_when_a_cycle_is_in_flight() {
    let (state, _dir) = test_state();
    set_interval(&state, 5);
    // Hold the cycle lock as a stand-in for a running cycle.
    let _cycle_guard = state.sync_cycle.lock().unwrap();
    assert!(!run_sync_cycle_if_due(&state));
    assert_eq!(
        last_finished(&state),
        None,
        "a skipped tick must not touch the marker"
    );
}

/// Not-due (marker fresh) skips.
#[test]
fn tick_skips_when_not_due() {
    let (state, _dir) = test_state();
    set_interval(&state, 15);
    *state.last_sync_finished.lock().unwrap() = Some(Instant::now());
    assert!(!run_sync_cycle_if_due(&state));
}

/// Due with NO sync configured: the cycle runs (true) and FAILS (not
/// configured), the failure is logged — and the marker is refreshed anyway
/// (a failed attempt consumed this scheduler slot; the next attempt comes
/// after the interval, not on the next 30s tick).
#[test]
fn failed_cycle_still_consumes_the_scheduler_slot() {
    let (state, _dir) = test_state();
    set_interval(&state, 5);
    assert!(run_sync_cycle_if_due(&state));
    assert!(
        last_finished(&state).is_some(),
        "failure must refresh the marker"
    );
    // Marker fresh → the immediately-following tick skips.
    assert!(!run_sync_cycle_if_due(&state));
}

/// A due tick over a CONFIGURED vault: connect, arm the scheduler with a
/// stale marker, tick → the cycle runs and the marker refreshes on the
/// outcome (success or failure), so the immediately-following tick skips.
/// The cycle itself FAILS offline — the tick resolves its backend through
/// `open_backend`, which builds the real WebDAV client against the config
/// URL (`dav.example.com` never resolves) — and v1.8.3 F4 makes that
/// visible: the failure is persisted onto the status line instead of
/// silently leaving the connect-era "ok" (the exact-message pin lives in
/// tests_sync_failure; the network error text is platform-dependent here).
#[test]
fn due_tick_runs_a_cycle_and_refreshes_the_marker() {
    let (state, _dir) = test_state();
    let cloud = MockCloudBackend::new();
    // The WebDAV password must be in the non-interactive store for the
    // tick's `open_backend` to construct the real WebDAV backend.
    sync_connect_with_backend(
        &state,
        &cloud.handle(),
        test_config(),
        Zeroizing::new("container-passphrase".to_string()),
        Some(Zeroizing::new("webdav-pass".to_string())),
    )
    .unwrap();

    set_interval(&state, 5);
    *state.last_sync_finished.lock().unwrap() = instant_ago(600);

    assert!(run_sync_cycle_if_due(&state));
    let ran_at = last_finished(&state).expect("marker refreshed after the cycle");
    assert!(ran_at.elapsed() < Duration::from_secs(5));
    // F4: the failed cycle is no longer invisible on the status line.
    let status = crate::sync_status(&state).unwrap();
    assert_ne!(
        status.last_result.as_deref(),
        Some("ok"),
        "the offline cycle failure must surface on the status line"
    );

    // Immediately after: not due anymore.
    assert!(!run_sync_cycle_if_due(&state));
}

// ---------------------------------------------------------------------------
// v1.8.3 F1/R3: presence semantics of a cycle's merge-window touch
// ---------------------------------------------------------------------------

/// A background auto-sync cycle is NOT user presence: it must leave the
/// auto-lock state EXACTLY as it found it (snapshot-restore republish), so
/// an unattended desktop still locks on schedule while auto-sync keeps
/// succeeding. Probed through the public session API (`should_auto_lock` /
/// `auto_lock_deadline`), the cross-module equivalent of session.rs's
/// `remote_touch_grants_only_grace`; the cycle runs over the injected mock
/// backend via the `pub(super)` trigger seam because the scheduler path
/// resolves its backend through `open_backend` (a real WebDAV client
/// against the config URL) and cannot succeed offline.
#[test]
fn auto_sync_cycle_extends_only_remote_grace() {
    let (state, _dir) = test_state();
    let cloud = connected_and_due(&state);

    // Timeout 0 = the local window has expired: before the fix the cycle's
    // full presence refresh kept auto-lock alive forever.
    assert!(state.session.should_auto_lock(0));

    // Settle the connect-era activity so the deadline comparisons below
    // have a measurable gap to work with.
    std::thread::sleep(Duration::from_millis(10));
    let deadline_before = state.session.auto_lock_deadline(600).unwrap();

    assert!(sync_now_with_backend_and_trigger(
        &state,
        &cloud.handle(),
        SyncTrigger::AutoCycle
    )
    .is_ok());

    // The cycle itself is presence-transparent: the full-window deadline
    // (timeout 600) is untouched — the snapshot-restore republish undid the
    // drain, and the AutoCycle touch only took the remote grace slot.
    assert_eq!(
        state.session.auto_lock_deadline(600).unwrap(),
        deadline_before,
        "an auto-sync cycle must not refresh the full auto-lock window"
    );

    // The grace slot is taken: right after the cycle auto-lock is deferred
    // by the BOUNDED remote grace (not suppressed — it lapses ≤120s later).
    assert!(
        !state.session.should_auto_lock(0),
        "an auto-sync cycle must take the remote grace, not act as user presence"
    );
    let now = Instant::now();
    let grace_deadline = state.session.auto_lock_deadline(0).unwrap();
    assert!(
        grace_deadline > now + Duration::from_secs(115),
        "the AutoCycle touch must yield the ~120s grace deadline"
    );
    assert!(
        grace_deadline <= now + Duration::from_secs(121),
        "the AutoCycle touch must not exceed one grace window"
    );
}

/// Anti-regression twin: a MANUAL cycle is in-person desktop activity and
/// refreshes the full auto-lock window (the republish restored the
/// cycle-start presence; the Manual touch then moves `last_activity` to
/// now, exactly like the pre-F1 behavior for user-initiated syncs).
#[test]
fn manual_sync_extends_full_window() {
    let (state, _dir) = test_state();
    let cloud = connected_and_due(&state);

    std::thread::sleep(Duration::from_millis(10));
    let deadline_before = state.session.auto_lock_deadline(600).unwrap();
    std::thread::sleep(Duration::from_millis(10));

    sync_now_with_backend(&state, &cloud.handle()).unwrap();

    assert!(
        state.session.auto_lock_deadline(600).unwrap() > deadline_before,
        "a manual sync is user presence — it must extend the full auto-lock window"
    );
}

/// The MANUAL contract (D6 lock split): `sync_now` BLOCKS on the cycle
/// mutex (a user action must complete, never be skipped) and refreshes the
/// marker on completion — even when the cycle itself fails.
#[test]
fn manual_sync_now_waits_for_a_busy_cycle_and_refreshes_the_marker() {
    let (state, _dir) = test_state();
    state.lock_vault(); // locked: sync_now errors quickly once it gets the lock

    let guard = state.sync_cycle.lock().unwrap();
    let blocker_state = state.clone();
    let worker = std::thread::spawn(move || sync_now(&blocker_state));

    // While the lock is held, the manual sync must still be waiting.
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        last_finished(&state),
        None,
        "sync_now must not have run yet"
    );
    drop(guard);

    let result = worker.join().unwrap();
    assert!(matches!(result, Err(crate::VaultError::VaultLocked)));
    assert!(
        last_finished(&state).is_some(),
        "the completed manual attempt refreshes the marker even on failure"
    );
}
