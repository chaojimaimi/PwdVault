//! v1.6.0 (D6): the timed auto-sync scheduler — the pure due-gate state
//! machine, the tick entry point's skip/run semantics (locked, disabled,
//! busy, not-due), marker refresh on success AND failure, the mock-backend
//! full cycle, and the manual `sync_now` blocking-lock contract.

use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::backend::MockCloudBackend;
use super::engine::{auto_sync_due, run_sync_cycle_if_due, sync_connect_with_backend, sync_now};
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

/// Full SUCCESS path over the mock backend: connect, arm the scheduler with
/// a stale marker, tick → cycle runs, "ok" lands in the status, count 0,
/// marker refreshed.
#[test]
fn due_tick_runs_a_full_sync_cycle() {
    let (state, _dir) = test_state();
    let cloud = MockCloudBackend::new();
    // The WebDAV password must be in the non-interactive store for the
    // tick's `open_backend` to construct the (mock-routed) backend.
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
    let status = crate::sync_status(&state).unwrap();
    assert_eq!(status.last_result.as_deref(), Some("ok"));
    assert_eq!(status.conflict_count, 0);
    let ran_at = last_finished(&state).expect("marker refreshed after success");
    assert!(ran_at.elapsed() < Duration::from_secs(5));

    // Immediately after: not due anymore.
    assert!(!run_sync_cycle_if_due(&state));
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
