//! OS secret storage for the biometric wrap key (Phase 1, P1.3) and for
//! cloud-sync credentials (P3.2) — two SEPARATE store instances.
//!
//! The Touch ID flow wraps the master key under a random 32-byte wrap key
//! that lives ONLY in the platform credential store — never on disk next to
//! the vault. On macOS the item is a Keychain generic password protected by
//! a `SecAccessControl` of `USER_PRESENCE | BIOMETRY_CURRENT_SET`, so reading
//! it back triggers a Touch ID prompt and re-enrolling fingerprints
//! invalidates it. Every SecItem operation prefers the data-protection
//! keychain and falls back to the legacy login keychain when the app lacks
//! the required entitlement (errSecMissingEntitlement / -34018, e.g. any
//! unsigned local build) — the legacy keychain enforces the same biometric
//! ACL without the signing requirement.
//!
//! Cloud-sync credentials (WebDAV password, P3.2) must NEVER trigger that
//! prompt — a background `sync_now` would block on Touch ID. They therefore
//! use a dedicated NON-INTERACTIVE store ([`platform_sync_default`]):
//! a plain Keychain item without access control on macOS (account prefix
//! `sync-`), or a 0600 JSON file elsewhere. The bio store and the sync store
//! are distinct instances with distinct account namespaces.
//!
//! Platform scope (D7): biometric unlock is macOS only. Every other platform
//! gets an [`UnavailableSecretStore`] stub whose `available()` is `false`, so
//! the service layer can gate the feature without cfg-spread. Tests use
//! [`MemorySecretStore`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Keychain service name shared by all PwdVault items.
pub const SERVICE: &str = "com.pwdvault.desktop";

/// Keychain account name of the biometric wrap key.
pub const BIO_WRAP_ACCOUNT: &str = "vault-bio-wrap";

/// Credential-store account name of the WebDAV password (P3.2, non-interactive store).
pub const SYNC_WEBDAV_PASSWORD_ACCOUNT: &str = "sync-webdav-password";

/// Credential-store account name of the Baidu access token (P3.4, reserved).
pub const SYNC_BAIDU_TOKEN_ACCOUNT: &str = "sync-baidu-token";

#[derive(Error, Debug)]
pub enum SecretStoreError {
    /// No item under the requested account.
    #[error("Secret store item not found")]
    NotFound,
    /// The user dismissed the biometric prompt.
    #[error("User cancelled authentication")]
    UserCancelled,
    /// Biometry is locked out after repeated failures.
    #[error("Biometric authentication is locked out")]
    LockedOut,
    /// Any other failure. The string is safe for logs (no secret material).
    #[error("Secret store unavailable: {0}")]
    Unavailable(String),
}

/// Platform credential store for small binary secrets.
pub trait SecretStore: Send + Sync {
    /// Whether biometric unlock can currently be offered (device support +
    /// enrolled biometry). Cheap, non-interactive.
    fn available(&self) -> bool;

    /// Create or overwrite the item (no biometric prompt on write).
    fn set(&self, account: &str, value: &[u8]) -> Result<(), SecretStoreError>;

    /// Read the item. On macOS this triggers the Touch ID prompt.
    fn get(&self, account: &str) -> Result<Vec<u8>, SecretStoreError>;

    /// Delete the item. Deleting a missing item is `NotFound`.
    fn delete(&self, account: &str) -> Result<(), SecretStoreError>;
}

/// The store the production binary should use on this platform.
pub fn platform_default() -> Arc<dyn SecretStore> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacSecretStore)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(UnavailableSecretStore)
    }
}

/// Default file location for the non-macOS sync credential store: next to
/// the vault database, inside the already-0700 app data directory.
#[cfg(not(target_os = "macos"))]
fn sync_secret_file_path() -> std::path::PathBuf {
    crate::paths::get_db_path()
        .parent()
        .map(|dir| dir.join("sync-secrets.json"))
        .unwrap_or_else(|| std::path::PathBuf::from("sync-secrets.json"))
}

/// The credential store for CLOUD-SYNC credentials (P3.2) — a dedicated,
/// non-interactive instance, deliberately NOT [`platform_default`]:
/// the bio store's items sit behind a Touch ID access control, so reusing it
/// would make a background `sync_now` block on a fingerprint prompt.
///
/// - macOS: plain data-protection Keychain item without `SecAccessControl`
///   (reads never prompt). Accounts use the `sync-` prefix to keep the
///   namespace disjoint from the bio wrap item.
/// - elsewhere: [`crate::secret_file_store::FileSecretStore`] (0600 JSON),
///   following the api-token file precedent.
pub fn platform_sync_default() -> Arc<dyn SecretStore> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacSyncSecretStore)
    }
    #[cfg(not(target_os = "macos"))]
    {
        use crate::secret_file_store::FileSecretStore;
        Arc::new(FileSecretStore::new(sync_secret_file_path()))
    }
}

/// In-memory double for tests. `available()` is always `true`; lookups are a
/// plain map so tests can simulate Keychain deletion with `remove`.
pub struct MemorySecretStore {
    items: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
        }
    }

    /// Test hook: remove an item like a Keychain deletion would.
    pub fn remove(&self, account: &str) -> bool {
        self.items
            .lock()
            .expect("memory secret store lock poisoned")
            .remove(account)
            .is_some()
    }
}

impl Default for MemorySecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for MemorySecretStore {
    fn available(&self) -> bool {
        true
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), SecretStoreError> {
        self.items
            .lock()
            .expect("memory secret store lock poisoned")
            .insert(account.to_string(), value.to_vec());
        Ok(())
    }

    fn get(&self, account: &str) -> Result<Vec<u8>, SecretStoreError> {
        self.items
            .lock()
            .expect("memory secret store lock poisoned")
            .get(account)
            .cloned()
            .ok_or(SecretStoreError::NotFound)
    }

    fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
        self.items
            .lock()
            .expect("memory secret store lock poisoned")
            .remove(account)
            .map(|_| ())
            .ok_or(SecretStoreError::NotFound)
    }
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use super::{SecretStore, SecretStoreError, SERVICE};
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

    /// Run a SecItem operation against the data-protection keychain first and
    /// fall back to the legacy login keychain when the entitlement is missing
    /// (-34018). The legacy keychain has no signing requirement (the
    /// KeePassXC-style path) and supports the same biometric access control,
    /// so unsigned local builds keep working. With `fallback_on_not_found`
    /// (reads), a NotFound in the data-protection keychain also retries the
    /// legacy one — an item may have been written by either mode.
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

    /// macOS Keychain store. Reading an item protected by the biometric
    /// access control pops the Touch ID prompt; writes and deletes do not.
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
            with_keychain_fallback(false, |use_dp| {
                // Idempotent upsert: drop any previous item first. A missing
                // previous item is the common first-enable path, not an error.
                match delete_item(account, use_dp) {
                    Ok(()) => {}
                    Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {}
                    Err(e) => return Err(e),
                }

                // ACL: require user presence via the CURRENT set of enrolled
                // biometrics, protected WhenUnlocked + ThisDeviceOnly. When
                // kSecAttrAccessControl is present, kSecAttrAccessible must NOT
                // also be set (mutually exclusive per Apple docs) — the
                // protection passed to create_with_protection IS the
                // accessibility value. The legacy login keychain supports the
                // same ACL flags.
                let acl = SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                    kSecAccessControlUserPresence | kSecAccessControlBiometryCurrentSet,
                )?;

                let query = item_dictionary(
                    vec![
                        (
                            sec_key!(kSecValueData),
                            CFData::from_buffer(value).as_CFType(),
                        ),
                        (sec_key!(kSecAttrAccessControl), acl.as_CFType()),
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
            // Try both keychains: the item may live in either mode depending
            // on how it was written (NotFound only if it is in neither).
            with_keychain_fallback(true, |use_dp| delete_item(account, use_dp))
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
    mod tests {
        use super::*;

        /// The real Keychain path is exercised by manual QA (Touch ID is a
        /// human interaction). Here we only assert that the error mapping
        /// classifies the well-known status codes.
        #[test]
        fn error_mapping_matches_apple_status_codes() {
            assert!(matches!(
                map_error(SfError::from_code(ERR_SEC_ITEM_NOT_FOUND)),
                SecretStoreError::NotFound
            ));
            assert!(matches!(
                map_error(SfError::from_code(ERR_SEC_USER_CANCELED)),
                SecretStoreError::UserCancelled
            ));
            assert!(matches!(
                map_error(SfError::from_code(ERR_SEC_AUTH_LOCKED)),
                SecretStoreError::LockedOut
            ));
            assert!(matches!(
                map_error(SfError::from_code(-99999)),
                SecretStoreError::Unavailable(_)
            ));
        }

        /// SecItem dictionaries must build without panicking (CF plumbing),
        /// in both keychain modes.
        #[test]
        fn query_dictionaries_build() {
            for use_dp in [true, false] {
                let _ = item_dictionary(Vec::new(), "vault-bio-wrap", use_dp);
                let _ = item_dictionary(
                    vec![(
                        sec_key!(kSecReturnData),
                        CFBoolean::true_value().as_CFType(),
                    )],
                    "vault-bio-wrap",
                    use_dp,
                );
            }
        }

        /// Unsigned local builds cannot use the data-protection keychain
        /// (errSecMissingEntitlement / -34018): every SecItem operation must
        /// transparently retry against the legacy login keychain.
        #[test]
        fn keychain_fallback_retries_legacy_on_missing_entitlement() {
            let mut attempted = Vec::new();
            let result = with_keychain_fallback(false, |use_dp| {
                attempted.push(use_dp);
                if use_dp {
                    Err(SfError::from_code(ERR_SEC_MISSING_ENTITLEMENT))
                } else {
                    Ok("legacy")
                }
            })
            .unwrap();
            assert_eq!(result, "legacy");
            assert_eq!(attempted, vec![true, false]);
        }

        /// Reads fall through to the legacy keychain on NotFound too — an
        /// item may have been written by either mode — and NotFound is only
        /// reported when both keychains miss.
        #[test]
        fn keychain_fallback_reads_fall_through_on_not_found() {
            let mut attempted = Vec::new();
            let result = with_keychain_fallback(true, |use_dp| {
                attempted.push(use_dp);
                Err::<Vec<u8>, _>(SfError::from_code(ERR_SEC_ITEM_NOT_FOUND))
            });
            assert!(matches!(result, Err(SecretStoreError::NotFound)));
            assert_eq!(attempted, vec![true, false]);
        }

        /// Unrelated errors (e.g. biometric lockout) must surface as-is
        /// without a legacy retry.
        #[test]
        fn keychain_fallback_preserves_unrelated_errors() {
            let mut attempted = Vec::new();
            let result = with_keychain_fallback(true, |use_dp| {
                attempted.push(use_dp);
                Err::<i32, _>(SfError::from_code(ERR_SEC_AUTH_LOCKED))
            });
            assert!(matches!(result, Err(SecretStoreError::LockedOut)));
            assert_eq!(attempted, vec![true]);
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::{MacSecretStore, MacSyncSecretStore};

// ---------------------------------------------------------------------------
// Non-macOS stub (D7)
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
/// Stub used on platforms without a supported credential store (D7).
pub struct UnavailableSecretStore;

#[cfg(not(target_os = "macos"))]
impl SecretStore for UnavailableSecretStore {
    fn available(&self) -> bool {
        false
    }

    fn set(&self, _account: &str, _value: &[u8]) -> Result<(), SecretStoreError> {
        Err(SecretStoreError::Unavailable(
            "unsupported platform".to_string(),
        ))
    }

    fn get(&self, _account: &str) -> Result<Vec<u8>, SecretStoreError> {
        Err(SecretStoreError::Unavailable(
            "unsupported platform".to_string(),
        ))
    }

    fn delete(&self, _account: &str) -> Result<(), SecretStoreError> {
        Err(SecretStoreError::Unavailable(
            "unsupported platform".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrip_and_not_found() {
        let store = MemorySecretStore::new();
        assert!(store.available());
        store.set(BIO_WRAP_ACCOUNT, &[1, 2, 3]).unwrap();
        assert_eq!(store.get(BIO_WRAP_ACCOUNT).unwrap(), vec![1, 2, 3]);
        // Overwrite is an upsert.
        store.set(BIO_WRAP_ACCOUNT, &[9]).unwrap();
        assert_eq!(store.get(BIO_WRAP_ACCOUNT).unwrap(), vec![9]);
        store.delete(BIO_WRAP_ACCOUNT).unwrap();
        assert!(matches!(
            store.get(BIO_WRAP_ACCOUNT),
            Err(SecretStoreError::NotFound)
        ));
        assert!(matches!(
            store.delete(BIO_WRAP_ACCOUNT),
            Err(SecretStoreError::NotFound)
        ));
        assert!(!store.remove(BIO_WRAP_ACCOUNT));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unavailable_stub_rejects_everything() {
        let store = UnavailableSecretStore;
        assert!(!store.available());
        assert!(matches!(
            store.set("a", &[1]),
            Err(SecretStoreError::Unavailable(_))
        ));
        assert!(matches!(
            store.get("a"),
            Err(SecretStoreError::Unavailable(_))
        ));
    }

}
