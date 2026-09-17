//! OS secret storage for the biometric wrap key (Phase 1, P1.3) and for
//! cloud-sync credentials (P3.2) — two SEPARATE store instances.
//!
//! The Touch ID flow wraps the master key under a random 32-byte wrap key
//! that lives ONLY in the platform credential store — never on disk next to
//! the vault. On macOS a bio-store item is written in one of two modes,
//! recorded as a one-byte tag prefix on the stored payload:
//!
//! - `0x01` data-protection keychain + `SecAccessControl` of
//!   `USER_PRESENCE | BIOMETRY_CURRENT_SET` — the OS itself blocks every
//!   read on a Touch ID prompt, and re-enrolling fingerprints invalidates
//!   the item.
//! - `0x02` legacy login keychain WITHOUT an access control — the legacy
//!   keychain rejects `kSecAttrAccessControl` outright (errSecParam / -50:
//!   Touch ID ACLs only exist on the data-protection keychain), so reads
//!   are gated in-process by an explicit `LAContext` evaluation instead
//!   (the KeePassXC-style two-step model, see the `biometric_gate`
//!   submodule).
//!
//! Every write prefers mode `0x01` and falls back to mode `0x02` when the
//! app lacks the data-protection entitlement (errSecMissingEntitlement /
//! -34018, e.g. any unsigned local build) or the ACL parameter is rejected
//! (-50). Reads query both keychains and route on the tag.
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
mod biometric_gate;

#[cfg(target_os = "macos")]
mod macos;

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
