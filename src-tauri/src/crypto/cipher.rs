//! Symmetric encryption using AES-256-GCM
//!
//! Provides authenticated encryption with associated data (AEAD).

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use typenum::U12;

use super::{KEY_SIZE, NONCE_SIZE};

/// Error type for encryption operations
#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),
}

/// Encrypted data with nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The nonce used for encryption (12 bytes for AES-GCM)
    pub nonce: Vec<u8>,
    /// The encrypted ciphertext (includes authentication tag)
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Convert to bytes for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NONCE_SIZE + self.ciphertext.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() < NONCE_SIZE + 16 {
            return Err(EncryptionError::InvalidCiphertext(
                "Ciphertext too short".to_string(),
            ));
        }

        Ok(Self {
            nonce: bytes[..NONCE_SIZE].to_vec(),
            ciphertext: bytes[NONCE_SIZE..].to_vec(),
        })
    }
}

/// Generate a random nonce
fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypt plaintext using AES-256-GCM
pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<EncryptedData, EncryptionError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::<U12>::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    Ok(EncryptedData {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt ciphertext using AES-256-GCM
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    encrypted: &EncryptedData,
) -> Result<Vec<u8>, EncryptionError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    if encrypted.nonce.len() != NONCE_SIZE {
        return Err(EncryptionError::InvalidCiphertext(
            "Invalid nonce length".to_string(),
        ));
    }

    let nonce = Nonce::<U12>::from_slice(&encrypted.nonce);

    cipher
        .decrypt(nonce, encrypted.ciphertext.as_slice())
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
}

/// Encrypt plaintext with associated data (AAD) using AES-256-GCM.
///
/// The AAD is authenticated but not encrypted. This binds each record to
/// its context (table name, record id, format version) so that a blob
/// moved between tables or records fails decryption. (§5.1.4)
pub fn encrypt_with_aad(
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedData, EncryptionError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::<U12>::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    Ok(EncryptedData {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypt ciphertext with associated data (AAD) using AES-256-GCM.
///
/// Decryption fails if the AAD does not match what was used during
/// encryption, providing cryptographic binding to the record context.
pub fn decrypt_with_aad(
    key: &[u8; KEY_SIZE],
    encrypted: &EncryptedData,
    aad: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    if encrypted.nonce.len() != NONCE_SIZE {
        return Err(EncryptionError::InvalidCiphertext(
            "Invalid nonce length".to_string(),
        ));
    }

    let nonce = Nonce::<U12>::from_slice(&encrypted.nonce);
    let payload = Payload {
        msg: encrypted.ciphertext.as_slice(),
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_key() -> [u8; KEY_SIZE] {
        [42u8; KEY_SIZE]
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = get_test_key();
        let plaintext = b"Hello, World!";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let key = get_test_key();
        let plaintext = b"Test data";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let bytes = encrypted.to_bytes();
        let parsed = EncryptedData::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.nonce, parsed.nonce);
        assert_eq!(encrypted.ciphertext, parsed.ciphertext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; KEY_SIZE];
        let key2 = [2u8; KEY_SIZE];

        let encrypted = encrypt(&key1, b"secret").unwrap();
        let result = decrypt(&key2, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_different_nonce_each_time() {
        let key = get_test_key();
        let plaintext = b"Same plaintext";

        let encrypted1 = encrypt(&key, plaintext).unwrap();
        let encrypted2 = encrypt(&key, plaintext).unwrap();

        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }
}
