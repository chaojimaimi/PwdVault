//! Password verification using verification header
//!
//! Stores an encrypted known plaintext to verify the master password
//! without decrypting actual data.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::cipher::{self, EncryptedData};
use super::keystore;
use super::kdf::{derive_key_with_params, AdaptiveParams};
use super::{KEY_SIZE, SALT_SIZE, VERIFICATION_HEADER};

/// Error type for verification operations
#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Password verification failed")]
    InvalidPassword,

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] cipher::EncryptionError),

    #[error("Key store error: {0}")]
    KeyStoreError(#[from] keystore::KeyStoreError),

    #[error("KDF error: {0}")]
    KdfError(String),

    #[error("Invalid verification header")]
    InvalidHeader,
}

/// Verification data stored in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationData {
    /// Salt used for key derivation
    pub salt: [u8; SALT_SIZE],
    /// KDF parameters
    pub params: AdaptiveParams,
    /// Encrypted verification header
    pub encrypted_header: EncryptedData,
}

/// Create a verification header for a new vault
pub fn create_verification_header(
    key: &[u8; KEY_SIZE],
    salt: [u8; SALT_SIZE],
    params: AdaptiveParams,
) -> Result<VerificationData, VerificationError> {
    let encrypted_header = cipher::encrypt(key, VERIFICATION_HEADER)?;

    Ok(VerificationData {
        salt,
        params,
        encrypted_header,
    })
}

/// Verify the master password using stored verification data
pub fn verify_password(
    password: &str,
    verification_data: &VerificationData,
) -> Result<bool, VerificationError> {
    let (key, _) =
        derive_key_with_params(password, &verification_data.salt, &verification_data.params)
            .map_err(|e| VerificationError::KdfError(e.to_string()))?;

    match cipher::decrypt(&key, &verification_data.encrypted_header) {
        Ok(decrypted) => Ok(decrypted.as_slice() == VERIFICATION_HEADER),
        Err(_) => Ok(false),
    }
}

/// Verify password and store key in keystore if correct
pub fn unlock_with_password(
    password: &str,
    verification_data: &VerificationData,
) -> Result<bool, VerificationError> {
    let (key, _) =
        derive_key_with_params(password, &verification_data.salt, &verification_data.params)
            .map_err(|e| VerificationError::KdfError(e.to_string()))?;

    match cipher::decrypt(&key, &verification_data.encrypted_header) {
        Ok(decrypted) => {
            if decrypted.as_slice() == VERIFICATION_HEADER {
                keystore::set_key(key)?;
                return Ok(true);
            }
            Ok(false)
        }
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::super::kdf::{derive_key, generate_salt};
    use super::*;

    #[test]
    fn test_create_and_verify() {
        let salt = generate_salt();
        let (key, params) = derive_key("correct_password", &salt).unwrap();

        let verification = create_verification_header(&key, salt, params).unwrap();

        assert!(verify_password("correct_password", &verification).unwrap());
        assert!(!verify_password("wrong_password", &verification).unwrap());
    }

    #[test]
    fn test_unlock_with_password() {
        keystore::clear_key();

        let salt = generate_salt();
        let (key, params) = derive_key("my_password", &salt).unwrap();

        let verification = create_verification_header(&key, salt, params).unwrap();

        let result = unlock_with_password("wrong", &verification).unwrap();
        assert!(!result);
        assert!(!keystore::is_unlocked());

        let result = unlock_with_password("my_password", &verification).unwrap();
        assert!(result);
        assert!(keystore::is_unlocked());

        keystore::clear_key();
    }
}