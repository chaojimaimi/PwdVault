//! OS secret storage for the biometric wrap key (Phase 1, P1.3) and for
//! cloud-sync credentials (P3.2) — two SEPARATE store instances.
//!
//! The Touch ID flow wraps the master key under a random 32-byte wrap key
//! that lives ONLY in the platform credential store — never on disk next to
//! the vault. On macOS that is the data-protection Keychain item protected by
//! a `SecAccessControl` of `USER_PRESENCE | BIOMETRY_CURRENT_SET`, so reading
//! the item back triggers a Touch ID prompt and re-enrolling fingerprints
//! invalidates it.
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
/// - elsewhere: [`FileSecretStore`] (0600 JSON), following the api-token
///   file precedent.
pub fn platform_sync_default() -> Arc<dyn SecretStore> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacSyncSecretStore)
    }
    #[cfg(not(target_os = "macos"))]
    {
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
// File-backed store (P3.2) — sync credentials on non-macOS platforms
// ---------------------------------------------------------------------------

/// 0600 JSON file secret store (P3.2, non-macOS `platform_sync_default`).
///
/// Values are base64 (STANDARD) inside a single JSON object
/// `{ "<account>": "<base64>", ... }`; writes go through a temp file + rename
/// so a crash never leaves a truncated store behind. Compiled on every
/// platform so the unit tests run in CI; only non-macOS builds USE it as the
/// platform default.
pub struct FileSecretStore {
    path: std::path::PathBuf,
}

impl FileSecretStore {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }

    fn read_map(&self) -> Result<HashMap<String, Vec<u8>>, SecretStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(e) => {
                return Err(SecretStoreError::Unavailable(format!(
                    "cannot read credential file: {e}"
                )))
            }
        };
        let raw: HashMap<String, String> = serde_json::from_slice(&bytes)
            .map_err(|e| SecretStoreError::Unavailable(format!("corrupt credential file: {e}")))?;
        let mut map = HashMap::with_capacity(raw.len());
        for (account, encoded) in raw {
            use base64::Engine;
            let value = base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| {
                    SecretStoreError::Unavailable("corrupt credential file entry".to_string())
                })?;
            map.insert(account, value);
        }
        Ok(map)
    }

    fn write_map(&self, map: &HashMap<String, Vec<u8>>) -> Result<(), SecretStoreError> {
        use base64::Engine;
        let raw: HashMap<&String, String> = map
            .iter()
            .map(|(account, value)| {
                (
                    account,
                    base64::engine::general_purpose::STANDARD.encode(value),
                )
            })
            .collect();
        let bytes = serde_json::to_vec(&raw)
            .map_err(|e| SecretStoreError::Unavailable(format!("serialize error: {e}")))?;

        // Atomic replace through a same-directory temp file (0600), so a
        // crash mid-write cannot truncate the previous store.
        let parent = self
            .path
            .parent()
            .ok_or_else(|| SecretStoreError::Unavailable("credential path has no parent".into()))?;
        std::fs::create_dir_all(parent).map_err(|e| {
            SecretStoreError::Unavailable(format!("cannot create credential dir: {e}"))
        })?;
        let temp = tempfile_in(parent)?;
        std::fs::write(&temp, &bytes).map_err(|e| {
            SecretStoreError::Unavailable(format!("cannot write credential file: {e}"))
        })?;
        restrict_permissions(&temp);
        std::fs::rename(&temp, &self.path)
            .map_err(|e| SecretStoreError::Unavailable(format!("cannot persist credential file: {e}")))?;
        restrict_permissions(&self.path);
        Ok(())
    }
}

/// Create a unique temp file inside `dir` with a deterministic suffix.
fn tempfile_in(dir: &std::path::Path) -> Result<std::path::PathBuf, SecretStoreError> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut name = String::from(".sync-secrets-");
    for _ in 0..12 {
        let mut byte = [0u8; 1];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut byte);
        name.push(CHARS[(byte[0] as usize) % CHARS.len()] as char);
    }
    Ok(dir.join(name))
}

fn restrict_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

impl SecretStore for FileSecretStore {
    fn available(&self) -> bool {
        true
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), SecretStoreError> {
        let mut map = self.read_map()?;
        map.insert(account.to_string(), value.to_vec());
        self.write_map(&map)
    }

    fn get(&self, account: &str) -> Result<Vec<u8>, SecretStoreError> {
        self.read_map()?
            .remove(account)
            .ok_or(SecretStoreError::NotFound)
    }

    fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
        let mut map = self.read_map()?;
        map.remove(account)
            .ok_or(SecretStoreError::NotFound)?;
        self.write_map(&map)
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
            match delete_item(account) {
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
            delete_item(account).map_err(map_error)
        }
    }

    impl SecretStore for MacSyncSecretStore {
        /// Sync credentials never require biometry — the store is usable
        /// whenever the data-protection keychain is, i.e. always for a
        /// running, unlocked user session.
        fn available(&self) -> bool {
            true
        }

        fn set(&self, account: &str, value: &[u8]) -> Result<(), SecretStoreError> {
            match delete_item(account) {
                Ok(()) => {}
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {}
                Err(e) => return Err(map_error(e)),
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
            // Same query shape as the bio store's get — but the item carries
            // no ACL, so this NEVER prompts.
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
            delete_item(account).map_err(map_error)
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

    /// P3.2: the file store round-trips, upserts, isolates accounts and
    /// reports NotFound; the file on disk is JSON with 0600 permissions and
    /// accounts are namespaced (sync- prefix) by the caller.
    #[test]
    fn file_store_roundtrip_and_permissions() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sync-secrets.json");
        let store = FileSecretStore::new(path.clone());

        assert!(store.available());
        assert!(matches!(store.get("sync-webdav-password"), Err(SecretStoreError::NotFound)));
        assert!(matches!(store.delete("sync-webdav-password"), Err(SecretStoreError::NotFound)));

        store.set(SYNC_WEBDAV_PASSWORD_ACCOUNT, b"dav-pass".as_slice()).unwrap();
        store.set(SYNC_BAIDU_TOKEN_ACCOUNT, &[0xde, 0xad, 0xbe, 0xef]).unwrap();
        assert_eq!(store.get(SYNC_WEBDAV_PASSWORD_ACCOUNT).unwrap(), b"dav-pass".to_vec());
        assert_eq!(store.get(SYNC_BAIDU_TOKEN_ACCOUNT).unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);

        // Overwrite is an upsert and leaves the other account untouched.
        store.set(SYNC_WEBDAV_PASSWORD_ACCOUNT, b"new-pass".as_slice()).unwrap();
        assert_eq!(store.get(SYNC_WEBDAV_PASSWORD_ACCOUNT).unwrap(), b"new-pass".to_vec());
        assert_eq!(store.get(SYNC_BAIDU_TOKEN_ACCOUNT).unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);

        // File is JSON, 0600 on unix, and holds base64 values.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "credential file must be user-only");
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(json[SYNC_WEBDAV_PASSWORD_ACCOUNT].is_string());
        assert!(json.get("vault-bio-wrap").is_none(), "bio namespace must stay disjoint");

        // Delete removes only the target account.
        store.delete(SYNC_WEBDAV_PASSWORD_ACCOUNT).unwrap();
        assert!(matches!(
            store.get(SYNC_WEBDAV_PASSWORD_ACCOUNT),
            Err(SecretStoreError::NotFound)
        ));
        assert!(store.get(SYNC_BAIDU_TOKEN_ACCOUNT).is_ok());

        // A fresh store instance reads the same persisted state.
        let reopened = FileSecretStore::new(path.clone());
        assert_eq!(reopened.get(SYNC_BAIDU_TOKEN_ACCOUNT).unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }
}
