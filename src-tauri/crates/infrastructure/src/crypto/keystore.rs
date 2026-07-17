//! Secure key storage in memory
//!
//! The encryption key is stored in a per-AppState Mutex and cleared on lock.

use std::sync::Mutex;
use thiserror::Error;
use zeroize::Zeroize;

use super::KEY_SIZE;

/// Error type for keystore operations
#[derive(Error, Debug)]
pub enum KeyStoreError {
    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault is already unlocked")]
    AlreadyUnlocked,
}

/// Type alias for the encryption key
pub type EncryptionKey = [u8; KEY_SIZE];

/// In-memory key storage. Owned by AppState so each test/app instance is isolated.
#[derive(Debug, Default)]
pub struct KeyStore {
    key: Mutex<Option<EncryptionKey>>,
}

impl KeyStore {
    /// Create a new empty keystore
    pub fn new() -> Self {
        Self {
            key: Mutex::new(None),
        }
    }

    /// Set the encryption key in memory
    pub fn set_key(&self, mut key: EncryptionKey) -> Result<(), KeyStoreError> {
        let mut keystore = self.key.lock().expect("keystore lock poisoned");

        // Idempotent: if already unlocked with the same key, succeed silently
        if let Some(existing) = keystore.as_ref() {
            if existing == &key {
                key.zeroize();
                return Ok(());
            }
            key.zeroize();
            return Err(KeyStoreError::AlreadyUnlocked);
        }

        *keystore = Some(key);
        Ok(())
    }

    /// Get the encryption key from memory.
    ///
    /// Returns an owned copy of the key. Prefer `with_key` to avoid
    /// unnecessary copies (§5.1.5).
    pub fn get_key(&self) -> Result<EncryptionKey, KeyStoreError> {
        let keystore = self.key.lock().expect("keystore lock poisoned");
        keystore.ok_or(KeyStoreError::VaultLocked)
    }

    /// Borrow the key for the duration of a closure, without copying (§5.1.5).
    ///
    /// This is the preferred way to access the key: it holds the mutex only
    /// for the closure's lifetime and does not return an owned copy.
    pub fn with_key<F, R>(&self, f: F) -> Result<R, KeyStoreError>
    where
        F: FnOnce(&EncryptionKey) -> R,
    {
        let keystore = self.key.lock().expect("keystore lock poisoned");
        let key = keystore.as_ref().ok_or(KeyStoreError::VaultLocked)?;
        Ok(f(key))
    }

    /// Check if the vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        let keystore = self.key.lock().expect("keystore lock poisoned");
        keystore.is_some()
    }

    /// Clear the encryption key from memory
    pub fn clear_key(&self) {
        let mut keystore = self.key.lock().expect("keystore lock poisoned");

        if let Some(mut key) = keystore.take() {
            key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_get_clear_key() {
        let store = KeyStore::new();
        let test_key = [123u8; KEY_SIZE];

        store.set_key(test_key).unwrap();
        let retrieved = store.get_key().unwrap();
        assert_eq!(test_key, retrieved);

        store.clear_key();
        assert!(store.get_key().is_err());
        assert!(!store.is_unlocked());
    }

    #[test]
    fn test_double_set_fails() {
        let store = KeyStore::new();

        store.set_key([1u8; KEY_SIZE]).unwrap();
        assert!(store.set_key([2u8; KEY_SIZE]).is_err());
    }

    #[test]
    fn test_idempotent_set_same_key() {
        let store = KeyStore::new();

        let key = [42u8; KEY_SIZE];
        store.set_key(key).unwrap();
        // Setting the same key again should succeed (idempotent)
        assert!(store.set_key(key).is_ok());
    }
}
