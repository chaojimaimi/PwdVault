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

use super::SecretStoreError;

/// Reason shown in the Touch ID dialog for legacy-gate items.
const BIOMETRIC_PROMPT_REASON: &str = "unlock your PwdVault vault";

/// LAError codes (LAError.h) with a dedicated `SecretStoreError` variant.
/// Values are part of the stable Apple ABI (NSInteger).
const LA_ERROR_AUTHENTICATION_FAILED: isize = -1;
const LA_ERROR_USER_CANCEL: isize = -2;
const LA_ERROR_BIOMETRY_LOCKOUT: isize = -8;

/// Map an LAError code from the evaluatePolicy reply to a
/// [`SecretStoreError`]. UserCancel and Lockout keep their dedicated
/// variants so the service layer can keep them OUT of the unlock-failure
/// rate limit; a plain biometric mismatch and everything else land in
/// `Unavailable`.
fn map_la_error(code: isize) -> SecretStoreError {
    match code {
        LA_ERROR_USER_CANCEL => SecretStoreError::UserCancelled,
        LA_ERROR_BIOMETRY_LOCKOUT => SecretStoreError::LockedOut,
        LA_ERROR_AUTHENTICATION_FAILED => SecretStoreError::Unavailable(
            "Touch ID did not match — use your master password".to_string(),
        ),
        other => SecretStoreError::Unavailable(format!(
            "biometric evaluation failed (LAError {other})"
        )),
    }
}

/// Block until the user answers an explicit Touch ID evaluation.
///
/// `LAContext.evaluatePolicy:localizedReason:reply:` is ASYNCHRONOUS — it
/// returns before the dialog completes and invokes the reply block on a
/// private framework queue. The channel carries the outcome back so this
/// function (and therefore `SecretStore::get`) blocks until the user has
/// answered, matching the store's prompt-on-read contract.
pub(super) fn gate_with_biometrics() -> Result<(), SecretStoreError> {
    // SAFETY: `new` on LAContext is the standard NSObject initializer.
    // The context is kept alive for the whole evaluation: dropping it
    // invalidates the context and would cancel the pending evaluation
    // (LAErrorAppCancel).
    let context: Retained<LAContext> = unsafe { msg_send![LAContext::class(), new] };
    let reason = NSString::from_str(BIOMETRIC_PROMPT_REASON);

    // The reply fires exactly once. `Sender::send` takes &self, so the
    // closure is a valid `Fn` block, and `Sender` is `Send` as the binding
    // requires — the framework invokes the reply on its own queue.
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

    match rx.recv() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(code)) => Err(map_la_error(code)),
        // Fail closed if the framework somehow ends the evaluation without
        // invoking the reply (the Sender is owned by the reply block).
        Err(_) => Err(SecretStoreError::Unavailable(
            "biometric evaluation returned without a reply".to_string(),
        )),
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
        // SystemCancel (-4), AppCancel (-9), NotInteractive (-100), ...
        assert!(matches!(
            map_la_error(-4),
            SecretStoreError::Unavailable(_)
        ));
        assert!(matches!(
            map_la_error(-100),
            SecretStoreError::Unavailable(_)
        ));
    }
}
