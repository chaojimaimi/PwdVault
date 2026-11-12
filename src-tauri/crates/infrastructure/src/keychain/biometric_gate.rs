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

use super::SecretStoreError;

/// Reason shown in the Touch ID dialog for legacy-gate items.
const BIOMETRIC_PROMPT_REASON: &str = "unlock your PwdVault vault";

/// LAError codes (LAError.h) with a dedicated `SecretStoreError` variant.
/// Values are part of the stable Apple ABI (NSInteger).
const LA_ERROR_AUTHENTICATION_FAILED: isize = -1;
const LA_ERROR_USER_CANCEL: isize = -2;
const LA_ERROR_BIOMETRY_LOCKOUT: isize = -8;
/// v1.8.5: AppCancel is exactly what the drop-invalidate cancel path below
/// surfaces — the cancelled evaluation's reply block reports LAErrorAppCancel,
/// so it MUST land in `UserCancelled` (F1 and F2 are mutually necessary).
const LA_ERROR_APP_CANCEL: isize = -9;

/// Process-level cancel request for an in-flight Touch ID prompt (v1.8.5).
/// The `LAContext` is function-local and `!Send`, so it can never be moved to
/// a cancellation point — the only way to dismiss the dialog is to drop the
/// context (drop = invalidate), which this flag lets the wait loop do.
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
/// `UserCancelled` variant (AppCancel is what the v1.8.5 drop-invalidate
/// cancel path surfaces) and Lockout keeps `LockedOut`, so the service
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
/// [`super::cancel_pending_biometric_prompt`]) dismisses the dialog by
/// dropping the context (drop = invalidate = the system panel goes away;
/// the late reply's `let _ = tx.send` into the closed channel is a safe
/// no-op).
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
    // episode must not kill the next prompt. The theoretical loss window
    // between this reset and `evaluatePolicy` is structurally closed by the
    // v1.8.2 focus gate — a new prompt cannot be in flight while the window
    // is minimized/hidden (the auto-prompt requires windowFocused, the
    // manual button requires a foreground window), which is exactly the
    // state that issues cancel requests.
    BIOMETRIC_CANCEL_REQUESTED.store(false, Ordering::Relaxed);
    // SAFETY: `new` on LAContext is the standard NSObject initializer.
    // The context is kept alive for the whole evaluation: dropping it
    // invalidates the context and would cancel the pending evaluation
    // (LAErrorAppCancel). On the cancel path the early return below drops
    // it on purpose — that invalidation IS the dismissal mechanism.
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

    match recv_reply_with_cancel(rx, &BIOMETRIC_CANCEL_REQUESTED, CANCEL_POLL_TICK) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(code)) => Err(map_la_error(code)),
        // Store-level outcome from the helper itself: `UserCancelled` when a
        // window-lifecycle cancel request won the race, or the fail-closed
        // `Unavailable` when the framework somehow ends the evaluation
        // without invoking the reply (the Sender is owned by the reply
        // block). Returning drops `context` — on the cancel path that
        // invalidation is what dismisses the on-screen dialog.
        Err(err) => Err(err),
    }
}

/// How often the reply wait re-checks the cancel flag. Cancels surface with
/// an upper bound of one tick (≤200ms) — imperceptible next to the dialog.
const CANCEL_POLL_TICK: Duration = Duration::from_millis(200);

/// Poll `rx` for the evaluation reply while watching `cancel`, so the
/// caller can abandon the wait (and drop its `LAContext`, dismissing the
/// dialog) when the window lifecycle says the prompt must go away.
///
/// Pure and injectable (`tick`) for unit testing — the gate passes
/// [`CANCEL_POLL_TICK`].
///
/// Semantics:
/// - A reply delivered before the flag is observed ALWAYS wins: a cancel
///   request that races with a completed evaluation must not discard the
///   user's answer (the flag is reset at the next gate entry).
/// - Cancel observed on a poll tick → `Err(UserCancelled)`, at most one
///   tick after the request.
/// - Sender dropped without any reply → fail closed with the verbatim
///   pre-cancel `Unavailable` message (no wire drift).
fn recv_reply_with_cancel<T>(
    rx: Receiver<T>,
    cancel: &AtomicBool,
    tick: Duration,
) -> Result<T, SecretStoreError> {
    loop {
        match rx.recv_timeout(tick) {
            Ok(reply) => return Ok(reply),
            Err(RecvTimeoutError::Timeout) => {
                if cancel.load(Ordering::Relaxed) {
                    return Err(SecretStoreError::UserCancelled);
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
        // v1.8.5: AppCancel is what the drop-invalidate cancel path
        // surfaces — it must land in the silent/rate-limit-exempt
        // `UserCancelled` variant, not `Unavailable` (which would leak a
        // red banner on every window-minimize dismissal).
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
    /// is CI scheduler margin, the real assertion is the variant).
    #[test]
    fn cancel_request_mid_wait_returns_user_cancelled_promptly() {
        let cancel = Arc::new(AtomicBool::new(false));
        let setter_cancel = Arc::clone(&cancel);
        let (tx, rx) = mpsc::channel::<Result<(), isize>>();
        // The sender stays alive for the whole wait: only the cancel flag
        // may end it.
        let setter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            setter_cancel.store(true, Ordering::Relaxed);
        });
        let start = Instant::now();
        let result = recv_reply_with_cancel(rx, &cancel, Duration::from_millis(20));
        let elapsed = start.elapsed();
        setter.join().expect("cancel setter thread panicked");
        drop(tx);
        assert!(
            matches!(result, Err(SecretStoreError::UserCancelled)),
            "cancel request must surface as UserCancelled, got {result:?}"
        );
        assert!(
            elapsed < Duration::from_millis(1000),
            "cancel must surface promptly (≈5ms + one 20ms tick), took {elapsed:?}"
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
        let result = recv_reply_with_cancel(rx, &cancel, Duration::from_millis(20));
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
        let result = recv_reply_with_cancel(rx, &cancel, Duration::from_millis(20));
        match result {
            Err(SecretStoreError::Unavailable(msg)) => {
                assert_eq!(msg, "biometric evaluation returned without a reply");
            }
            other => panic!("disconnected must map to Unavailable, got {other:?}"),
        }
    }
}
