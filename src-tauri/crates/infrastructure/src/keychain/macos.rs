//! macOS SecItem implementation of the secret stores (see the `keychain`
//! module docs). The bio store (`MacSecretStore`) writes items in one of two
//! modes tagged by a leading byte; the sync store (`MacSyncSecretStore`) is
//! the non-interactive variant for cloud-sync credentials.

use super::{SecretStore, SecretStoreError, SERVICE};
use super::biometric_gate::gate_with_biometrics;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error as SfError;
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlUserPresence,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
};
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass,
    kSecClassGenericPassword, kSecReturnData, kSecUseDataProtectionKeychain, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

// The accessibility attribute KEY is ABI-stable (SecBase.h) but not
// re-exported by security-framework-sys (only the VALUE constants are).
// Declare the symbol directly, exactly like the sys crate does.
extern "C" {
    static kSecAttrAccessible: core_foundation::string::CFStringRef;
}

/// Stable SecBase.h status codes that security-framework-sys does not
/// re-export. Values are part of the Apple ABI (OSStatus = i32).
const ERR_SEC_ITEM_NOT_FOUND: i32 = errSecItemNotFound; // -25300 (re-exported by sys)
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_LOCKED: i32 = -25293;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
/// errSecMissingEntitlement: the DATA-PROTECTION keychain requires a
/// code-signed app (application-identifier entitlement). Unsigned local
/// builds (and any build without that entitlement) fail every SecItem
/// call against it with this code.
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;
/// errSecParam: the parameter dictionary was rejected. The legacy
/// file-based login keychain returns this for `kSecAttrAccessControl` —
/// Touch ID ACLs are a data-protection-keychain feature only, which is
/// exactly why the bio store's two modes exist.
const ERR_SEC_PARAM: i32 = -50;

/// Run a SecItem operation against the data-protection keychain first and
/// fall back to the legacy login keychain when the entitlement is missing
/// (-34018): the legacy keychain has no signing requirement, so unsigned
/// local builds keep working. With `fallback_on_not_found` (reads), a
/// NotFound in the data-protection keychain also retries the legacy one —
/// an item may have been written by either mode.
fn with_keychain_fallback<T>(
    fallback_on_not_found: bool,
    mut op: impl FnMut(bool) -> Result<T, SfError>,
) -> Result<T, SecretStoreError> {
    match op(true) {
        Ok(value) => Ok(value),
        Err(e)
            if e.code() == ERR_SEC_MISSING_ENTITLEMENT
                || (fallback_on_not_found && e.code() == ERR_SEC_ITEM_NOT_FOUND) =>
        {
            op(false).map_err(map_error)
        }
        Err(e) => Err(map_error(e)),
    }
}

/// macOS Keychain store for the biometric wrap key. `get` always blocks
/// on a Touch ID gate: either the system prompt (data-protection ACL
/// item) or an explicit `LAContext` evaluation (legacy-gate item, see
/// [`biometric_gate`]). Writes and deletes never prompt.
pub struct MacSecretStore;

/// macOS Keychain store for cloud-sync credentials (P3.2): identical to
/// [`MacSecretStore`] except that `set` attaches NO `SecAccessControl`,
/// so reads are non-interactive — a background `sync_now` must never pop
/// a Touch ID prompt. Kept as a separate struct (not a mode flag) so the
/// two credential namespaces cannot be crossed by accident.
pub struct MacSyncSecretStore;

/// Get one of the `kSec*` CFString constants as a retained CFType key.
/// SAFETY at call sites: the extern static holds a valid CFStringRef.
macro_rules! sec_key {
    ($name:ident) => {
        unsafe { CFString::wrap_under_get_rule($name).as_CFType() }
    };
}

/// Base (key, value) pairs shared by every SecItem dictionary: a generic
/// password item of our service. `use_data_protection` selects the
/// data-protection keychain (preferred, requires signed entitlements) or
/// the legacy login keychain (fallback for unsigned builds).
fn base_pairs(account: &str, use_data_protection: bool) -> Vec<(CFType, CFType)> {
    let mut pairs = vec![
        (sec_key!(kSecClass), sec_key!(kSecClassGenericPassword)),
        (sec_key!(kSecAttrService), CFString::new(SERVICE).as_CFType()),
        (
            sec_key!(kSecAttrAccount),
            CFString::new(account).as_CFType(),
        ),
    ];
    if use_data_protection {
        pairs.push((
            sec_key!(kSecUseDataProtectionKeychain),
            CFBoolean::true_value().as_CFType(),
        ));
    }
    pairs
}

/// Build an untyped SecItem dictionary from base pairs plus extras.
fn item_dictionary(
    extra: Vec<(CFType, CFType)>,
    account: &str,
    use_data_protection: bool,
) -> CFDictionary {
    let mut pairs = base_pairs(account, use_data_protection);
    pairs.extend(extra);
    CFDictionary::from_CFType_pairs(&pairs).into_untyped()
}

fn map_error(err: SfError) -> SecretStoreError {
    match err.code() {
        ERR_SEC_ITEM_NOT_FOUND => SecretStoreError::NotFound,
        ERR_SEC_USER_CANCELED => SecretStoreError::UserCancelled,
        ERR_SEC_AUTH_LOCKED => SecretStoreError::LockedOut,
        ERR_SEC_DUPLICATE_ITEM => SecretStoreError::Unavailable(
            "keychain item already exists (stale duplicate)".to_string(),
        ),
        other => SecretStoreError::Unavailable(format!("Security framework error {other}")),
    }
}

/// Which storage mode a bio-store item was written in. The mode is
/// recorded as a one-byte TAG PREFIX in front of the wrap key so a read
/// can tell whether the OS already gated the fetch ([`BioMode::DpAcl`])
/// or the process must run its own `LAContext` evaluation
/// ([`BioMode::LegacyGate`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BioMode {
    /// Data-protection keychain + biometric `SecAccessControl`: the
    /// `SecItemCopyMatching` call itself blocks on the system prompt.
    DpAcl,
    /// Legacy login keychain with NO access control: the legacy keychain
    /// cannot carry an ACL (errSecParam), so reads are gated by the
    /// explicit `LAContext` evaluation in `biometric_gate`.
    LegacyGate,
}

const TAG_DP_ACL: u8 = 0x01;
const TAG_LEGACY_GATE: u8 = 0x02;

fn tag_of(mode: BioMode) -> u8 {
    match mode {
        BioMode::DpAcl => TAG_DP_ACL,
        BioMode::LegacyGate => TAG_LEGACY_GATE,
    }
}

/// Split a stored item into its mode and payload. Anything but the two
/// known tags — including an EMPTY item — fails closed: secret material
/// must never be returned without a gate deciding it was satisfied.
fn split_mode(bytes: &[u8]) -> Result<(BioMode, &[u8]), SecretStoreError> {
    match bytes {
        [TAG_DP_ACL, payload @ ..] => Ok((BioMode::DpAcl, payload)),
        [TAG_LEGACY_GATE, payload @ ..] => Ok((BioMode::LegacyGate, payload)),
        _ => Err(SecretStoreError::Unavailable(
            "unknown keychain item format".to_string(),
        )),
    }
}

/// Payload exactly as stored on disk: tag byte + wrap key.
fn with_mode_prefix(mode: BioMode, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 1);
    out.push(tag_of(mode));
    out.extend_from_slice(value);
    out
}

/// Delete the item; `Ok(())` when absent is decided by the caller.
fn delete_item(account: &str, use_data_protection: bool) -> Result<(), SfError> {
    let query = item_dictionary(Vec::new(), account, use_data_protection);
    // SAFETY: query is a valid CFDictionary of SecItem search keys.
    let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
    if status == 0 {
        Ok(())
    } else {
        Err(SfError::from_code(status))
    }
}

/// SecItemAdd of a fully-formed query; `Ok(())` on errSecSuccess.
fn add_item(query: CFDictionary) -> Result<(), SfError> {
    // SAFETY: query is a valid SecItemAdd parameter dictionary.
    let status = unsafe { SecItemAdd(query.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status == 0 {
        Ok(())
    } else {
        Err(SfError::from_code(status))
    }
}

/// Idempotent upsert within ONE keychain: drop any previous item first
/// (a missing previous item is the common first-enable path, not an
/// error), then add the item with `extras`.
fn upsert_in_keychain(
    account: &str,
    use_dp: bool,
    extras: Vec<(CFType, CFType)>,
) -> Result<(), SfError> {
    match delete_item(account, use_dp) {
        Ok(()) => {}
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {}
        Err(e) => return Err(e),
    }
    add_item(item_dictionary(extras, account, use_dp))
}

/// SecItemCopyMatching with `kSecReturnData=true` in one keychain mode.
/// For a `DpAcl` item this call blocks on the system Touch ID prompt.
fn copy_item_data(account: &str, use_dp: bool) -> Result<Vec<u8>, SfError> {
    let query = item_dictionary(
        vec![(sec_key!(kSecReturnData), CFBoolean::true_value().as_CFType())],
        account,
        use_dp,
    );
    let mut result = std::ptr::null();
    // SAFETY: query is a valid SecItemCopyMatching parameter dictionary;
    // on success `result` is a CFDataRef we own.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status != 0 {
        return Err(SfError::from_code(status));
    }
    // SAFETY: with kSecReturnData=true the result is a CFData.
    let data = unsafe { CFData::wrap_under_create_rule(result.cast()) };
    Ok(data.bytes().to_vec())
}

/// Mode 1 write: DATA-PROTECTION keychain + biometric SecAccessControl.
fn add_dp_acl_item(account: &str, value: &[u8]) -> Result<(), SfError> {
    // ACL: require user presence via the CURRENT set of enrolled
    // biometrics, protected WhenUnlocked + ThisDeviceOnly. When
    // kSecAttrAccessControl is present, kSecAttrAccessible must NOT also
    // be set (mutually exclusive per Apple docs) — the protection passed
    // to create_with_protection IS the accessibility value.
    let acl = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlUserPresence | kSecAccessControlBiometryCurrentSet,
    )?;
    upsert_in_keychain(
        account,
        true,
        vec![
            (
                sec_key!(kSecValueData),
                CFData::from_buffer(value).as_CFType(),
            ),
            (sec_key!(kSecAttrAccessControl), acl.as_CFType()),
        ],
    )
}

/// Mode 2 write: LEGACY keychain, plain item with NO SecAccessControl —
/// the ACL attribute is exactly what the legacy keychain rejects with
/// errSecParam. WhenUnlocked + ThisDeviceOnly keeps the protection
/// without introducing an ACL; the gate happens at read time instead.
fn add_legacy_gate_item(account: &str, value: &[u8]) -> Result<(), SfError> {
    upsert_in_keychain(
        account,
        false,
        vec![
            (
                sec_key!(kSecValueData),
                CFData::from_buffer(value).as_CFType(),
            ),
            (
                sec_key!(kSecAttrAccessible),
                sec_key!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
            ),
        ],
    )
}

impl SecretStore for MacSecretStore {
    fn available(&self) -> bool {
        use objc2::msg_send;
        use objc2::rc::Retained;
        use objc2::ClassType;
        use objc2_local_authentication::{LAContext, LAPolicy};

        // LAContext canEvaluatePolicy is a synchronous preflight — it
        // never pops UI and needs no completion block.
        // SAFETY: `new` on LAContext is the standard NSObject
        // initializer; canEvaluatePolicy:error: is a plain ObjC message.
        let context: Retained<LAContext> = unsafe { msg_send![LAContext::class(), new] };
        unsafe {
            context
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        }
        .is_ok()
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), SecretStoreError> {
        // Mode 1 (preferred): data-protection keychain + biometric ACL —
        // the OS gates every read itself. -34018 (no signing entitlement,
        // e.g. any unsigned local build) and -50 (ACL rejected by a
        // legacy-only environment) are the signals that this mode cannot
        // exist on this machine → fall back to mode 2.
        let dp_item = with_mode_prefix(BioMode::DpAcl, value);
        match add_dp_acl_item(account, &dp_item) {
            Ok(()) => return Ok(()),
            Err(e)
                if e.code() == ERR_SEC_MISSING_ENTITLEMENT || e.code() == ERR_SEC_PARAM => {}
            Err(e) => return Err(map_error(e)),
        }

        // Mode 2: legacy login keychain, NO access control — the legacy
        // keychain rejects `kSecAttrAccessControl` with errSecParam, so
        // the item is stored plain and reads are gated in-process by an
        // explicit LAContext evaluation (KeePassXC-style). No signing
        // requirement.
        let legacy_item = with_mode_prefix(BioMode::LegacyGate, value);
        add_legacy_gate_item(account, &legacy_item).map_err(map_error)
    }

    fn get(&self, account: &str) -> Result<Vec<u8>, SecretStoreError> {
        // Raw fetch first: the item may live in either keychain depending
        // on which mode wrote it (NotFound falls through to the legacy
        // keychain). Mode routing — and any biometric gate — happens
        // AFTER the raw bytes are in hand.
        let raw = with_keychain_fallback(true, |use_dp| copy_item_data(account, use_dp))?;
        let (mode, payload) = split_mode(&raw)?;
        match mode {
            // The SecItemCopyMatching above already popped the system
            // Touch ID prompt and blocked until the user answered.
            BioMode::DpAcl => Ok(payload.to_vec()),
            // No ACL on this item: run the explicit in-process gate.
            BioMode::LegacyGate => {
                gate_with_biometrics()?;
                Ok(payload.to_vec())
            }
        }
    }

    fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
        // Delete from BOTH keychains: the item may exist in either mode,
        // and a successful delete in one must not strand the other (e.g.
        // after a signing-status change flipped the write mode).
        // errSecMissingEntitlement on the DP side counts as "absent" —
        // an unsigned build can never have written there.
        let dp = delete_item(account, true);
        let legacy = delete_item(account, false);
        if dp.is_ok() || legacy.is_ok() {
            return Ok(());
        }
        let dp_err = dp.unwrap_err();
        let legacy_err = legacy.unwrap_err();
        let dp_absent = dp_err.code() == ERR_SEC_ITEM_NOT_FOUND
            || dp_err.code() == ERR_SEC_MISSING_ENTITLEMENT;
        let legacy_absent = legacy_err.code() == ERR_SEC_ITEM_NOT_FOUND;
        if dp_absent && legacy_absent {
            Err(SecretStoreError::NotFound)
        } else if legacy_absent {
            // Only the DP side reported something actionable.
            Err(map_error(dp_err))
        } else {
            // Legacy is the operative keychain on unsigned builds.
            Err(map_error(legacy_err))
        }
    }
}

impl SecretStore for MacSyncSecretStore {
    /// Sync credentials never require biometry — the store is usable
    /// whenever a keychain is, i.e. always for a running, unlocked user
    /// session.
    fn available(&self) -> bool {
        true
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), SecretStoreError> {
        with_keychain_fallback(false, |use_dp| {
            match delete_item(account, use_dp) {
                Ok(()) => {}
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {}
                Err(e) => return Err(e),
            }
            // NO kSecAttrAccessControl: a plain generic-password item reads
            // back without any user interaction (deliberate — see the struct
            // doc). WhenUnlocked + ThisDeviceOnly keeps the default
            // protection without introducing an ACL.
            let query = item_dictionary(
                vec![
                    (
                        sec_key!(kSecValueData),
                        CFData::from_buffer(value).as_CFType(),
                    ),
                    (
                        sec_key!(kSecAttrAccessible),
                        sec_key!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
                    ),
                ],
                account,
                use_dp,
            );
            // SAFETY: query is a valid SecItemAdd parameter dictionary.
            let status =
                unsafe { SecItemAdd(query.as_concrete_TypeRef(), std::ptr::null_mut()) };
            if status == 0 {
                Ok(())
            } else {
                Err(SfError::from_code(status))
            }
        })
    }

    fn get(&self, account: &str) -> Result<Vec<u8>, SecretStoreError> {
        // Same query shape as the bio store's get — but the item carries
        // no ACL, so this NEVER prompts.
        with_keychain_fallback(true, |use_dp| {
            let query = item_dictionary(
                vec![(
                    sec_key!(kSecReturnData),
                    CFBoolean::true_value().as_CFType(),
                )],
                account,
                use_dp,
            );
            let mut result = std::ptr::null();
            // SAFETY: query is a valid SecItemCopyMatching parameter
            // dictionary; on success `result` is a CFDataRef we own.
            let status =
                unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
            if status != 0 {
                return Err(SfError::from_code(status));
            }
            // SAFETY: with kSecReturnData=true the result is a CFData.
            let data = unsafe { CFData::wrap_under_create_rule(result.cast()) };
            Ok(data.bytes().to_vec())
        })
    }

    fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
        with_keychain_fallback(true, |use_dp| delete_item(account, use_dp))
    }
}


#[cfg(test)]
mod tests;
