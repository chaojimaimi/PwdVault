//! Explicit `LAContext` biometric gate for legacy-keychain bio items.
//!
//! Root cause this works around: `SecAccessControl` (Touch ID ACL) is only
//! honoured by the DATA-PROTECTION keychain. The legacy file-based login
//! keychain rejects `kSecAttrAccessControl` with errSecParam (-50), and the
//! data-protection keychain itself needs a code-signing entitlement
//! (errSecMissingEntitlement / -34018) that unsigned local builds lack. An
//! item stored on such a machine therefore carries NO ACL, and every read
//! is gated here by an explicit `LAContext` evaluation instead — the
//! KeePassXC-style two-step model: fetch the blob, then prove user presence.
//!
//! Only the bio store uses this gate. The sync credential store's items are
//! non-interactive by design and never route through this module.

use objc2::msg_send;
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2::ClassType;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;
use std::time::Instant;

use super::SecretStoreError;

/// Reason shown in the Touch ID dialog for legacy-gate items.
const BIOMETRIC_PROMPT_REASON: &str = "unlock your PwdVault vault";

/// LAError codes (LAError.h) with a dedicated `SecretStoreError` variant.
/// Values are part of the stable Apple ABI (NSInteger).
const LA_ERROR_AUTHENTICATION_FAILED: isize = -1;
const LA_ERROR_USER_CANCEL: isize = -2;
const LA_ERROR_BIOMETRY_LOCKOUT: isize = -8;
/// v1.8.5/v1.8.8: AppCancel is exactly what the explicit invalidate call on
/// the cancel path surfaces — the terminated evaluation's reply block
/// reports LAErrorAppCancel, so it MUST land in `UserCancelled` (F1 and F2
/// are mutually necessary).
const LA_ERROR_APP_CANCEL: isize = -9;

/// Process-level cancel request for an in-flight Touch ID prompt (v1.8.5).
/// The `LAContext` is function-local and `!Send`, so it can never be moved to
/// a cancellation point — the wait loop polls this flag instead, and on a
/// request past the raise grace it returns and runs the explicit invalidate
/// call, which is what dismisses the dialog (v1.8.8 falsification: dropping
/// the Rust-side reference alone does NOT — LocalAuthentication retains the
/// context for the whole evaluation, so the panel outlives our reference;
/// 2026-11-13 evidence: seven honored cancel-flag writes and the dialog
/// still died only by user-pressed cancel 2m26s later).
/// `Relaxed`: a single flag with no dependent memory, one prompt per process
/// (same shape as the v1.8.4 purge-failure tracker).
static BIOMETRIC_CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Ask the in-flight Touch ID gate (if any) to dismiss its dialog. No-op
/// when no evaluation is pending — the flag is reset unconditionally at the
/// next gate entry. Exposed cross-platform via [`super`]'s cfg pair
/// (`cancel_pending_biometric_prompt`).
pub(super) fn request_cancel() {
    BIOMETRIC_CANCEL_REQUESTED.store(true, Ordering::Relaxed);
}

/// Map an LAError code from the evaluatePolicy reply to a
/// [`SecretStoreError`]. UserCancel and AppCancel keep the dedicated
/// `UserCancelled` variant (AppCancel is what the explicit invalidate call
/// on the cancel path surfaces) and Lockout keeps `LockedOut`, so the service
/// layer can keep them OUT of the unlock-failure rate limit; a plain
/// biometric mismatch and everything else land in `Unavailable`.
fn map_la_error(code: isize) -> SecretStoreError {
    match code {
        LA_ERROR_USER_CANCEL | LA_ERROR_APP_CANCEL => SecretStoreError::UserCancelled,
        LA_ERROR_BIOMETRY_LOCKOUT => SecretStoreError::LockedOut,
        LA_ERROR_AUTHENTICATION_FAILED => SecretStoreError::Unavailable(
            "Touch ID did not match — use your master password".to_string(),
        ),
        other => {
            SecretStoreError::Unavailable(format!("biometric evaluation failed (LAError {other})"))
        }
    }
}

/// Block until the user answers an explicit Touch ID evaluation — or until
/// a window-lifecycle cancel request (v1.8.5: minimize/hide via
/// [`super::cancel_pending_biometric_prompt`], honored past the raise
/// grace) makes the wait return and run the explicit invalidate call —
/// Apple's documented termination API, and the thing that actually makes
/// the system panel go away (v1.8.8: dropping the context does not); the
/// late reply's `let _ = tx.send` into the closed channel is a safe
/// no-op.
///
/// `LAContext.evaluatePolicy:localizedReason:reply:` is ASYNCHRONOUS — it
/// returns before the dialog completes and invokes the reply block on a
/// private framework queue. The channel carries the outcome back so this
/// function (and therefore `SecretStore::get`) blocks until the user has
/// answered, matching the store's prompt-on-read contract.
///
/// NOTE (v1.8.5 scope): only THIS process's legacy-gate dialog is
/// cancellable. The data-protection mode (signed builds) prompt is a
/// SecItem ACL system dialog owned by the OS and cannot be cancelled
/// programmatically — current release builds all use the legacy mode, so
/// the window minimize/hide cancel is effective there.
pub(super) fn gate_with_biometrics() -> Result<(), SecretStoreError> {
    // Reset unconditionally: a stale cancel request from the previous
    // episode must not kill the next prompt. The residual reset-to-raise
    // window is closed twice over (v1.8.8): the raise grace discards any
    // cancel request observed within the first 500ms after the dialog
    // appears — swallowing both a stale flag from the previous episode and
    // the panel's own resign side-effect at ~50ms — and the v1.8.2 focus
    // gate keeps the auto-prompt from being raised while the window is
    // minimized or hidden in the first place. The cancel-request trigger
    // sources (resign-active, occlusion, close-to-tray) therefore only
    // take effect past the grace: against a genuinely stale prompt or a
    // genuine user switch.
    BIOMETRIC_CANCEL_REQUESTED.store(false, Ordering::Relaxed);
    // SAFETY: `new` on LAContext is the standard NSObject initializer.
    // The context is kept alive for the whole evaluation. v1.8.8
    // falsification: dropping it does NOT cancel the pending evaluation —
    // LocalAuthentication retains the context while an evaluation is in
    // flight, so the object (and the system panel) outlives our reference
    // (2026-11-13: the dialog survived 2m26s past the drop, ended only by
    // user-pressed cancel, zero LAErrorAppCancel). The explicit invalidate
    // call on the Err path below is the dismissal mechanism; this Retained
    // merely keeps the context valid until that point.
    let context: Retained<LAContext> = unsafe { msg_send![LAContext::class(), new] };
    let reason = NSString::from_str(BIOMETRIC_PROMPT_REASON);

    // The reply fires exactly once. `Sender::send` takes &self, so the
    // closure is a valid `Fn` block, and `Sender` is `Send` as the binding
    // requires — the framework invokes the reply on its own queue. After a
    // cancel-driven early return the channel's receiver is gone; `send`
    // then returns Err, which `let _ =` ignores — the late reply is safely
    // discarded instead of panicking.
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), isize>>();
    let reply = block2::RcBlock::new(move |success: Bool, error: *mut NSError| {
        let outcome = if success.is_true() {
            Ok(())
        } else if error.is_null() {
            Err(LA_ERROR_AUTHENTICATION_FAILED)
        } else {
            // SAFETY: non-null NSError, valid for the duration of the call.
            let code: isize = unsafe { (*error).code() };
            Err(code)
        };
        let _ = tx.send(outcome);
    });

    // SAFETY: standard ObjC call. The framework retains its own copy of the
    // block for the asynchronous reply; ours is released only AFTER the
    // reply has fired, on the creating thread (RcBlock is not Send).
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
            &reason,
            &reply,
        );
    }

    // The raise moment: the panel renders ~50ms after this call and strips
    // the app's active status at that point (2026-11-13 log evidence), so
    // the grace window is anchored here, not at gate entry.
    let raised_at = Instant::now();

    let wait_result = recv_reply_with_cancel(
        rx,
        &BIOMETRIC_CANCEL_REQUESTED,
        CANCEL_POLL_TICK,
        raised_at,
        CANCEL_GRACE_AFTER_RAISE,
    );
    if wait_result.is_err() {
        // FALSIFIED-PREMISE FIX (v1.8.8): dropping the Rust-side Retained does
        // NOT cancel an in-flight evaluation — LocalAuthentication retains the
        // context for the whole evaluation, so the object (and the system
        // panel) outlives our reference (empirically falsified 2026-11-13: the
        // v1.8.7 poll honored seven cancel-flag writes, the dialog still died
        // only by user-pressed cancel 2m26s later, zero LAErrorAppCancel).
        // invalidate() is Apple's documented termination API ("stops any
        // existing authentication interaction"): it cancels the evaluation —
        // the reply fires LAErrorAppCancel into the closed channel, harmless —
        // and dismisses the panel. Same thread as creation/evaluatePolicy by
        // the Retained !Send structural guarantee.
        unsafe { context.invalidate() }
    }
    match wait_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(code)) => Err(map_la_error(code)),
        // Store-level outcome from the helper itself: `UserCancelled` when a
        // window-lifecycle cancel request won the race past the raise grace,
        // or the fail-closed `Unavailable` when the framework somehow ends
        // the evaluation without invoking the reply (the Sender is owned by
        // the reply block). The Err paths ran the explicit invalidate call
        // above — THAT is what dismisses the on-screen dialog; the drop of
        // `context` on return only releases our own reference (v1.8.8).
        Err(err) => Err(err),
    }
}

/// How often the reply wait re-checks the cancel flag. Cancels surface with
/// an upper bound of one tick (≤200ms) — imperceptible next to the dialog.
const CANCEL_POLL_TICK: Duration = Duration::from_millis(200);

/// How long after the dialog was raised a cancel request is treated as the
/// auth panel's own raise side-effect and discarded (v1.8.8). Measured
/// 2026-11-13: the panel strips the app's active status ~49ms after
/// appearing (single machine, single data point), so 500ms is a 10x margin.
/// Blind window: a genuine app switch inside the first 0.5s after the raise
/// (the rare sub-second cmd-tab) or a close-to-tray inside the grace is
/// swallowed — the recovery path is simply switching or minimizing again,
/// which lands past the grace and dismisses the dialog as usual.
const CANCEL_GRACE_AFTER_RAISE: Duration = Duration::from_millis(500);

/// Poll `rx` for the evaluation reply while watching `cancel`, so the
/// caller can abandon the wait when the window lifecycle says the prompt
/// must go away — the caller then runs the explicit invalidate call that
/// dismisses the dialog (v1.8.8: abandoning the wait alone does not).
///
/// Pure and injectable (`tick`, `raised_at`, `grace`) for unit testing —
/// the gate passes [`CANCEL_POLL_TICK`] and [`CANCEL_GRACE_AFTER_RAISE`],
/// with `raised_at` captured right after the evaluatePolicy call.
///
/// Semantics:
/// - A reply delivered before the flag is observed ALWAYS wins: a cancel
///   request that races with a completed evaluation must not discard the
///   user's answer (the flag is reset at the next gate entry).
/// - A cancel request observed within the raise grace window (`raised_at`
///   through `raised_at` + `grace`) is DISCARDED and the flag cleared:
///   within that window it is the auth panel's own raise side-effect (the
///   panel strips the app's active status ~50ms after the dialog appears —
///   2026-11-13 log evidence), not a user action. Clearing it keeps it
///   from poisoning later ticks; genuine switches land seconds later and
///   are honored.
/// - Cancel observed on a poll tick past the grace → `Err(UserCancelled)`,
///   at most one tick after the request.
/// - Sender dropped without any reply → fail closed with the verbatim
///   pre-cancel `Unavailable` message (no wire drift).
fn recv_reply_with_cancel<T>(
    rx: Receiver<T>,
    cancel: &AtomicBool,
    tick: Duration,
    raised_at: Instant,
    grace: Duration,
) -> Result<T, SecretStoreError> {
    loop {
        match rx.recv_timeout(tick) {
            Ok(reply) => return Ok(reply),
            Err(RecvTimeoutError::Timeout) => {
                if cancel.load(Ordering::Relaxed) {
                    if raised_at.elapsed() >= grace {
                        return Err(SecretStoreError::UserCancelled);
                    }
                    // Within the raise grace window a cancel request is the auth
                    // panel's own raise side-effect (it strips the app's active status
                    // ~50ms after the dialog appears — 2026-11-13 log evidence), not a
                    // user action. Discard it (clear the flag) so it cannot poison
                    // later ticks; genuine switches land seconds later and are honored.
                    cancel.store(false, Ordering::Relaxed);
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(SecretStoreError::Unavailable(
                    "biometric evaluation returned without a reply".to_string(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LAError → SecretStoreError mapping: dedicated variants for cancel and
    /// lockout (the service layer keeps those out of the rate limit), a
    /// user-actionable message for a failed match, `Unavailable` otherwise.
    #[test]
    fn la_error_codes_map_to_store_errors() {
        assert!(matches!(
            map_la_error(LA_ERROR_USER_CANCEL),
            SecretStoreError::UserCancelled
        ));
        // v1.8.5/v1.8.8: AppCancel is what the explicit invalidate call on
        // the cancel path surfaces — it must land in the
        // silent/rate-limit-exempt `UserCancelled` variant, not
        // `Unavailable` (which would leak a red banner on every
        // window-minimize dismissal).
        assert!(matches!(
            map_la_error(LA_ERROR_APP_CANCEL),
            SecretStoreError::UserCancelled
        ));
        assert!(matches!(
            map_la_error(LA_ERROR_BIOMETRY_LOCKOUT),
            SecretStoreError::LockedOut
        ));
        match map_la_error(LA_ERROR_AUTHENTICATION_FAILED) {
            SecretStoreError::Unavailable(msg) => {
                assert!(msg.contains("Touch ID did not match"));
            }
            other => panic!("mismatch must map to Unavailable, got {other:?}"),
        }
        // SystemCancel (-4), NotInteractive (-100), ... still land in
        // `Unavailable`; AppCancel (-9) no longer does (mapped above).
        assert!(matches!(map_la_error(-4), SecretStoreError::Unavailable(_)));
        assert!(matches!(
            map_la_error(-100),
            SecretStoreError::Unavailable(_)
        ));
    }

    // --- recv_reply_with_cancel (pure helper, injected tick) ---------------
    // The gate function itself needs objc + the system dialog and is not
    // unit-testable — real-device coverage is QA T62.

    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Instant;

    /// ① Cancel requested while waiting (no reply ever sent) →
    /// `Err(UserCancelled)`, surfacing at the first poll after the request
    /// (steady-state bound: request delay + 1 tick + ε; the generous slack
    /// is CI scheduler margin, the real assertion is the variant). The
    /// setter delay sits OUTSIDE the injected grace so the request is a
    /// genuine past-the-grace cancel, not a raise side-effect.
    #[test]
    fn cancel_request_mid_wait_returns_user_cancelled_promptly() {
        let cancel = Arc::new(AtomicBool::new(false));
        let setter_cancel = Arc::clone(&cancel);
        let (tx, rx) = mpsc::channel::<Result<(), isize>>();
        // The sender stays alive for the whole wait: only the cancel flag
        // may end it.
        let setter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            setter_cancel.store(true, Ordering::Relaxed);
        });
        let raised_at = Instant::now();
        let start = Instant::now();
        let result = recv_reply_with_cancel(
            rx,
            &cancel,
            Duration::from_millis(20),
            raised_at,
            Duration::from_millis(10),
        );
        let elapsed = start.elapsed();
        setter.join().expect("cancel setter thread panicked");
        drop(tx);
        assert!(
            matches!(result, Err(SecretStoreError::UserCancelled)),
            "cancel request must surface as UserCancelled, got {result:?}"
        );
        assert!(
            elapsed < Duration::from_millis(1000),
            "cancel must surface promptly (≈30ms + one 20ms tick), took {elapsed:?}"
        );
    }

    /// ② Reply already delivered before the cancel request → the completed
    /// evaluation wins: a cancel must not discard the user's answer.
    #[test]
    fn delivered_reply_wins_over_a_cancel_request() {
        let (tx, rx) = mpsc::channel::<Result<(), isize>>();
        tx.send(Ok(())).expect("reply send");
        // Flag requested before the wait even starts — the queued reply is
        // still picked up first because each poll tries the channel before
        // consulting the flag.
        let cancel = AtomicBool::new(true);
        let result = recv_reply_with_cancel(
            rx,
            &cancel,
            Duration::from_millis(20),
            Instant::now(),
            Duration::from_millis(0),
        );
        assert!(
            matches!(result, Ok(Ok(()))),
            "an already-delivered reply must win over the cancel flag, got {result:?}"
        );
    }

    /// ③ Sender dropped without any reply → fail closed with the VERBATIM
    /// pre-cancel `Unavailable` message (no wire drift).
    #[test]
    fn disconnected_sender_maps_to_verbatim_unavailable_message() {
        let cancel = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel::<Result<(), isize>>();
        drop(tx);
        let result = recv_reply_with_cancel(
            rx,
            &cancel,
            Duration::from_millis(20),
            Instant::now(),
            Duration::from_millis(0),
        );
        match result {
            Err(SecretStoreError::Unavailable(msg)) => {
                assert_eq!(msg, "biometric evaluation returned without a reply");
            }
            other => panic!("disconnected must map to Unavailable, got {other:?}"),
        }
    }

    /// ④ A cancel request inside the raise grace is discarded (it is the
    /// auth panel's own raise side-effect), and a later request past the
    /// grace wins: the wait must survive the swallowed first request and
    /// still honor the second (elapsed ≥ the second setter delay proves
    /// the first one did not kill the wait).
    #[test]
    fn cancel_within_grace_is_discarded_then_later_cancel_wins() {
        let cancel = Arc::new(AtomicBool::new(false));
        let setter_cancel = Arc::clone(&cancel);
        let (tx, rx) = mpsc::channel::<Result<(), isize>>();
        let setter = std::thread::spawn(move || {
            // First request: well inside the 100ms grace — must be discarded.
            std::thread::sleep(Duration::from_millis(5));
            setter_cancel.store(true, Ordering::Relaxed);
            // Second request: past the grace — must win.
            std::thread::sleep(Duration::from_millis(145));
            setter_cancel.store(true, Ordering::Relaxed);
        });
        let raised_at = Instant::now();
        let start = Instant::now();
        let result = recv_reply_with_cancel(
            rx,
            &cancel,
            Duration::from_millis(10),
            raised_at,
            Duration::from_millis(100),
        );
        let elapsed = start.elapsed();
        setter.join().expect("cancel setter thread panicked");
        drop(tx);
        assert!(
            matches!(result, Err(SecretStoreError::UserCancelled)),
            "the second (past-the-grace) cancel request must win, got {result:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(130),
            "the first (in-grace) request must NOT end the wait — it must \
             survive until the second request lands (~150ms), took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(1000),
            "cancel must still surface promptly, took {elapsed:?}"
        );
    }

    /// ⑤ A cancel request landing past the raise grace is honored promptly
    /// (first poll after the request — the grace must not delay genuine
    /// cancels).
    #[test]
    fn cancel_after_grace_is_honored_promptly() {
        let cancel = Arc::new(AtomicBool::new(false));
        let setter_cancel = Arc::clone(&cancel);
        let (tx, rx) = mpsc::channel::<Result<(), isize>>();
        let setter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            setter_cancel.store(true, Ordering::Relaxed);
        });
        let raised_at = Instant::now();
        let start = Instant::now();
        let result = recv_reply_with_cancel(
            rx,
            &cancel,
            Duration::from_millis(10),
            raised_at,
            Duration::from_millis(100),
        );
        let elapsed = start.elapsed();
        setter.join().expect("cancel setter thread panicked");
        drop(tx);
        assert!(
            matches!(result, Err(SecretStoreError::UserCancelled)),
            "a past-the-grace cancel request must surface as UserCancelled, \
             got {result:?}"
        );
        assert!(
            elapsed < Duration::from_millis(1000),
            "cancel must surface promptly (≈150ms + one 10ms tick), took {elapsed:?}"
        );
    }

    // --- source contract (⑦) -----------------------------------------------
    // The dismissal mechanism is the explicit invalidate call in the gate's
    // Err path — pinned in SOURCE (include_str self-scan of the pre-test
    // region, v1.8.8): deleting the call counts 0 (red), a comment colliding
    // with the full call form counts 2 (red), so comments must refer to it
    // in prose only.

    /// ⑦ The gate source must carry the explicit invalidate call exactly
    /// once, in its full call form. A bare prose mention would hollow the
    /// anchor (v1.8.1 lesson), so the anchor is the full call form with an
    /// exact count: 0 = the dismissal mechanism was removed; ≥2 = a comment
    /// duplicated the call form.
    #[test]
    fn invalidate_call_is_pinned_in_gate_source() {
        let src = include_str!("biometric_gate.rs");
        let prefix = src.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            prefix.matches("unsafe { context.invalidate() }").count(),
            1,
            "the explicit invalidate call (full call form) must appear \
             exactly once in the pre-test source: 0 = the dismissal \
             mechanism was removed, 2+ = a comment collided with the call \
             form (comments must refer to it in prose)"
        );
    }
}
