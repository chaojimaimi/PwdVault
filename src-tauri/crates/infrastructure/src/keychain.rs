//! OS secret storage for the biometric wrap key (Phase 1, P1.3).
//!
//! The Touch ID flow wraps the master key under a random 32-byte wrap key
//! that lives ONLY in the platform credential store — never on disk next to
//! the vault. On macOS that is the data-protection Keychain item protected by
//! a `SecAccessControl` of `USER_PRESENCE | BIOMETRY_CURRENT_SET`, so reading
//! the item back triggers a Touch ID prompt and re-enrolling fingerprints
//! invalidates it.
//!
//! Platform scope (D7): macOS only. Every other platform gets an
//! [`UnavailableSecretStore`] stub whose `available()` is `false`, so the
//! service layer can gate the feature without cfg-spread. Tests use
//! [`MemorySecretStore`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Keychain service name shared by all PwdVault items.
pub const SERVICE: &str = "com.pwdvault.desktop";

/// Keychain account name of the biometric wrap key.
pub const BIO_WRAP_ACCOUNT: &str = "vault-bio-wrap";

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
    };
    use security_framework_sys::base::errSecItemNotFound;
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecClass,
        kSecClassGenericPassword, kSecReturnData, kSecUseDataProtectionKeychain, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

    /// Stable SecBase.h status codes that security-framework-sys does not
    /// re-export. Values are part of the Apple ABI (OSStatus = i32).
    const ERR_SEC_ITEM_NOT_FOUND: i32 = errSecItemNotFound; // -25300 (re-exported by sys)
    const ERR_SEC_USER_CANCELED: i32 = -128;
    const ERR_SEC_AUTH_LOCKED: i32 = -25293;
    const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;

    /// macOS Keychain store. Reading an item protected by the biometric
    /// access control pops the Touch ID prompt; writes and deletes do not.
    pub struct MacSecretStore;

    /// Get one of the `kSec*` CFString constants as a retained CFType key.
    /// SAFETY at call sites: the extern static holds a valid CFStringRef.
    macro_rules! sec_key {
        ($name:ident) => {
            unsafe { CFString::wrap_under_get_rule($name).as_CFType() }
        };
    }

    /// Base (key, value) pairs shared by every SecItem dictionary: a generic
    /// password item of our service, restricted to the data-protection
    /// keychain (never the legacy login keychain).
    fn base_pairs(account: &str) -> Vec<(CFType, CFType)> {
        vec![
            (sec_key!(kSecClass), sec_key!(kSecClassGenericPassword)),
            (sec_key!(kSecAttrService), CFString::new(SERVICE).as_CFType()),
            (
                sec_key!(kSecAttrAccount),
                CFString::new(account).as_CFType(),
            ),
            (
                sec_key!(kSecUseDataProtectionKeychain),
                CFBoolean::true_value().as_CFType(),
            ),
        ]
    }

    /// Build an untyped SecItem dictionary from base pairs plus extras.
    fn item_dictionary(extra: Vec<(CFType, CFType)>, account: &str) -> CFDictionary {
        let mut pairs = base_pairs(account);
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

    impl MacSecretStore {
        /// Delete the item; `Ok(())` when absent is decided by the caller.
        fn delete_item(account: &str) -> Result<(), SfError> {
            let query = item_dictionary(Vec::new(), account);
            // SAFETY: query is a valid CFDictionary of SecItem search keys.
            let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
            if status == 0 {
                Ok(())
            } else {
                Err(SfError::from_code(status))
            }
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
            // Idempotent upsert: drop any previous item first. A missing
            // previous item is the common first-enable path, not an error.
            match Self::delete_item(account) {
                Ok(()) => {}
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {}
                Err(e) => return Err(map_error(e)),
            }

            // ACL: require user presence via the CURRENT set of enrolled
            // biometrics, protected WhenUnlocked + ThisDeviceOnly. When
            // kSecAttrAccessControl is present, kSecAttrAccessible must NOT
            // also be set (mutually exclusive per Apple docs) — the
            // protection passed to create_with_protection IS the
            // accessibility value.
            let acl = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                kSecAccessControlUserPresence | kSecAccessControlBiometryCurrentSet,
            )
            .map_err(map_error)?;

            let query = item_dictionary(
                vec![
                    (
                        sec_key!(kSecValueData),
                        CFData::from_buffer(value).as_CFType(),
                    ),
                    (sec_key!(kSecAttrAccessControl), acl.as_CFType()),
                ],
                account,
            );
            // SAFETY: query is a valid SecItemAdd parameter dictionary.
            let status = unsafe { SecItemAdd(query.as_concrete_TypeRef(), std::ptr::null_mut()) };
            if status == 0 {
                Ok(())
            } else {
                Err(map_error(SfError::from_code(status)))
            }
        }

        fn get(&self, account: &str) -> Result<Vec<u8>, SecretStoreError> {
            let query = item_dictionary(
                vec![(
                    sec_key!(kSecReturnData),
                    CFBoolean::true_value().as_CFType(),
                )],
                account,
            );
            let mut result = std::ptr::null();
            // SAFETY: query is a valid SecItemCopyMatching parameter
            // dictionary; on success `result` is a CFDataRef we own.
            let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
            if status != 0 {
                return Err(map_error(SfError::from_code(status)));
            }
            // SAFETY: with kSecReturnData=true the result is a CFData.
            let data = unsafe { CFData::wrap_under_create_rule(result.cast()) };
            Ok(data.bytes().to_vec())
        }

        fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
            Self::delete_item(account).map_err(map_error)
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

        /// SecItem dictionaries must build without panicking (CF plumbing).
        #[test]
        fn query_dictionaries_build() {
            let _ = item_dictionary(Vec::new(), "vault-bio-wrap");
            let _ = item_dictionary(
                vec![(
                    sec_key!(kSecReturnData),
                    CFBoolean::true_value().as_CFType(),
                )],
                "vault-bio-wrap",
            );
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::MacSecretStore;

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
