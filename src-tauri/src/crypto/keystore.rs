//! Secure key storage in memory
//!
//! The encryption key is stored in a static Mutex and cleared on lock.

use std::sync::Mutex;
use once_cell::sync::Lazy;
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

type EncryptionKey = [u8; KEY_SIZE];

static KEYSTORE: Lazy<Mutex<Option<EncryptionKey>>> = Lazy::new(|| Mutex::new(None));

/// Set the encryption key in memory
pub fn set_key(key: [u8; KEY_SIZE]) -> Result<(), KeyStoreError> {
    let mut keystore = KEYSTORE.lock().unwrap();

    if keystore.is_some() {
        return Err(KeyStoreError::AlreadyUnlocked);
    }

    *keystore = Some(key);
    Ok(())
}

/// Get the encryption key from memory
pub fn get_key() -> Result<[u8; KEY_SIZE], KeyStoreError> {
    let keystore = KEYSTORE.lock().unwrap();
    keystore.ok_or(KeyStoreError::VaultLocked)
}

/// Check if the vault is unlocked
pub fn is_unlocked() -> bool {
    let keystore = KEYSTORE.lock().unwrap();
    keystore.is_some()
}

/// Clear the encryption key from memory
pub fn clear_key() {
    let mut keystore = KEYSTORE.lock().unwrap();

    if let Some(mut key) = keystore.take() {
        key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_keystore() {
        let mut keystore = KEYSTORE.lock().unwrap();
        *keystore = None;
    }

    #[test]
    fn test_set_get_clear_key() {
        clear_keystore();

        let test_key = [123u8; KEY_SIZE];

        set_key(test_key).unwrap();
        let retrieved = get_key().unwrap();
        assert_eq!(test_key, retrieved);

        clear_key();
        assert!(get_key().is_err());
        assert!(!is_unlocked());
    }

    #[test]
    fn test_double_set_fails() {
        clear_keystore();

        set_key([1u8; KEY_SIZE]).unwrap();
        assert!(set_key([2u8; KEY_SIZE]).is_err());

        clear_keystore();
    }
}