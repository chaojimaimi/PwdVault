//! Post-unlock side effects shared by both adapters (WP3, v1.5.0).
//!
//! The Tauri IPC unlock commands and the Native Messaging dispatcher unlock
//! arm both call [`sweep_trash_and_emit`] right after the application layer
//! published the session keys. The sweep itself lives in the application
//! layer (`service::run_trash_auto_purge`, pure function — it cannot emit);
//! only the adapter owns the `tauri::AppHandle` needed to surface the result.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tauri::Emitter;

use pwdvault_application::AppState;

/// Process-lifetime consecutive-failure counter for the trash auto-purge
/// sweep (P2-6). A `static` rather than AppState-owned because the Tauri
/// unlock commands and the NM dispatcher both funnel through the single
/// [`sweep_trash_and_emit`] helper, so the once-per-run notification
/// semantics is intentionally process-wide.
static PURGE_FAILURE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Decision layer (P2-6): advance the consecutive-failure counter and return
/// `true` EXACTLY when the count transitions to 2 — the 1st failure stays
/// log-only (a single transient failure should not disturb the user), the 2nd
/// consecutive failure surfaces the event, and every later consecutive
/// failure stays silent again (no nagging within one run). Comparing the
/// PREVIOUS value (1 ⇒ the incremented count is 2) keeps the arithmetic
/// overflow-free; the counter only ever wraps after 2^32 consecutive
/// failures without a success, which is unreachable at one sweep per unlock.
pub(crate) fn record_purge_failure(counter: &AtomicU32) -> bool {
    counter.fetch_add(1, Ordering::Relaxed) == 1
}

/// Decision layer (P2-6): a successful sweep (any count, including 0) resets
/// the consecutive-failure counter so a recovered transient failure re-arms
/// the notification for future failures.
pub(crate) fn note_purge_success(counter: &AtomicU32) {
    counter.store(0, Ordering::Relaxed);
}

/// Run ONE bounded trash auto-purge batch after a successful unlock and emit
/// `trash-auto-purged(count)` so the webview can toast the outcome. A zero
/// count (feature off or nothing expired) is NOT emitted.
///
/// Timing contract: this runs AFTER `complete_unlock` published the keys —
/// outside any D8 exclusive window — so the unlock path is only ever delayed
/// by the ≤500-row batch cap (`MAX_TRASH_SWEEP_BATCH`). Failures are logged
/// and swallowed: the unlock itself already succeeded, and a failed sweep
/// must never surface as a failed unlock (the next unlock retries).
pub(crate) fn sweep_trash_and_emit(app: &tauri::AppHandle, state: &Arc<AppState>) {
    // The tauri-app crate has no chrono dependency (commands.rs civil_from_days
    // precedent); unix seconds from the clock are all the sweep needs.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    match pwdvault_application::service::run_trash_auto_purge(state, now) {
        Ok(0) => note_purge_success(&PURGE_FAILURE_COUNT),
        Ok(count) => {
            note_purge_success(&PURGE_FAILURE_COUNT);
            tracing::info!("trash auto-purge removed {count} expired item(s) after unlock");
            if let Err(error) = app.emit("trash-auto-purged", count) {
                tracing::error!("could not surface the trash auto-purge result: {error}");
            }
        }
        Err(error) => {
            tracing::warn!(
                "trash auto-purge after unlock failed: {}",
                error.public_message()
            );
            // P2-6: the 2nd CONSECUTIVE sweep failure surfaces to the webview
            // via `trash-purge-failed` (sanitized public_message). The counter
            // is only advanced when an emit surface exists: the NM dispatcher
            // gates the whole sweep behind `Some(app_handle)` before calling
            // this helper, so this arm always holds a live handle — a failure
            // is never recorded when it could never be surfaced.
            if record_purge_failure(&PURGE_FAILURE_COUNT) {
                if let Err(emit_error) = app.emit("trash-purge-failed", error.public_message()) {
                    // Notifying about a failure must never become a new
                    // failure path — a dead webview stays log-only.
                    tracing::error!("could not surface the trash purge failure: {emit_error}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P2-6 decision sequence: the 1st failure stays log-only, the 2nd
    /// consecutive failure fires, the 3rd stays silent (once-per-run), a
    /// success resets, and the sequence re-arms exactly the same way.
    #[test]
    fn purge_failure_tracker_fires_exactly_on_second_consecutive_failure() {
        let counter = AtomicU32::new(0);
        assert!(!record_purge_failure(&counter));
        assert!(record_purge_failure(&counter));
        assert!(!record_purge_failure(&counter));
        note_purge_success(&counter);
        assert!(!record_purge_failure(&counter));
        assert!(record_purge_failure(&counter));
    }

    /// A reset works from an arbitrary accumulated count, not only right
    /// after the notification fired: four consecutive failures (two past the
    /// fired state), then a success, put the tracker back to "one failure
    /// away" from firing again.
    #[test]
    fn note_purge_success_resets_from_any_count() {
        let counter = AtomicU32::new(0);
        assert!(!record_purge_failure(&counter)); // count 1
        assert!(record_purge_failure(&counter)); // count 2 — fires
        assert!(!record_purge_failure(&counter)); // count 3
        assert!(!record_purge_failure(&counter)); // count 4 — still silent
        note_purge_success(&counter);
        assert!(!record_purge_failure(&counter)); // count 1 again
        assert!(record_purge_failure(&counter)); // count 2 — fires again
    }

    /// Wiring pin (v1.8.4 review fold): the decision layer above has unit
    /// tests, but the ADAPTER wiring in `sweep_trash_and_emit` needs a live
    /// `AppHandle` and is untestable in-process — the Rust suite would stay
    /// green if the emit, the counter advance, or the Ok-arm resets were
    /// deleted. This source contract pins those facts (same culture as the
    /// repo's readFileSync guards in the extension tests).
    #[test]
    fn sweep_wiring_source_contract() {
        // Scope to the adapter wiring BEFORE the test module: include_str!
        // reads this very file, so the test's own assert strings would
        // otherwise collide with the counted sites (the v1.8.1
        // source-pair-guard self-collision lesson).
        let wiring = include_str!("unlock_effects.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default();
        // The Err arm advances the process-wide tracker...
        assert!(
            wiring.contains("record_purge_failure(&PURGE_FAILURE_COUNT)"),
            "the Err arm must feed the shared tracker"
        );
        // ...and emits the SANITIZED payload under the exact event name the
        // webview listener expects (a {:?} debug of the error would leak
        // internals into the toast).
        assert!(
            wiring.contains("app.emit(\"trash-purge-failed\", error.public_message())"),
            "the event name + public_message payload shape is load-bearing"
        );
        // Both Ok arms reset the tracker — dropping either re-arm breaks the
        // once-per-run semantics silently.
        assert_eq!(
            wiring
                .matches("note_purge_success(&PURGE_FAILURE_COUNT)")
                .count(),
            2,
            "Ok(0) and Ok(count) arms must both reset the tracker"
        );
    }
}
