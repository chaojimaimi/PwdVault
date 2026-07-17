//! Password verification using verification header
//!
//! Stores an encrypted known plaintext to verify the master password
//! without decrypting actual data.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

use super::cipher::{self, EncryptedData};
use super::kdf::{derive_key_with_params, derive_subkeys, AdaptiveParams};
use super::{SecretKey, KEY_SIZE, SALT_SIZE, VERIFICATION_HEADER};

pub type DerivedSubkeys = (SecretKey, SecretKey);

/// Error type for verification operations
#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Password verification failed")]
    InvalidPassword,

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] cipher::EncryptionError),

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
    let (mut key, _) =
        derive_key_with_params(password, &verification_data.salt, &verification_data.params)
            .map_err(|e| VerificationError::KdfError(e.to_string()))?;

    let result = match cipher::decrypt(&key, &verification_data.encrypted_header) {
        Ok(decrypted) => Ok(decrypted.as_slice().ct_eq(VERIFICATION_HEADER).into()),
        Err(_) => Ok(false),
    };
    key.zeroize();
    result
}

/// Verify password and return derived (encryption_key, integrity_mac_key) if correct.
pub fn unlock_with_password(
    password: &str,
    verification_data: &VerificationData,
) -> Result<Option<DerivedSubkeys>, VerificationError> {
    let (mut master_key, _) =
        derive_key_with_params(password, &verification_data.salt, &verification_data.params)
            .map_err(|e| VerificationError::KdfError(e.to_string()))?;

    let result = match cipher::decrypt(&master_key, &verification_data.encrypted_header) {
        Ok(decrypted) => {
            if decrypted.as_slice().ct_eq(VERIFICATION_HEADER).into() {
                let (enc_key, mac_key) = derive_subkeys(&master_key, &verification_data.salt);
                master_key.zeroize();
                Ok(Some((enc_key.into(), mac_key.into())))
            } else {
                Ok(None)
            }
        }
        Err(_) => Ok(None),
    };
    master_key.zeroize();
    result
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
        let salt = generate_salt();
        let (master_key, params) = derive_key("my_password", &salt).unwrap();

        let verification = create_verification_header(&master_key, salt, params).unwrap();

        let result = unlock_with_password("wrong", &verification).unwrap();
        assert!(result.is_none());

        let result = unlock_with_password("my_password", &verification).unwrap();
        assert!(result.is_some());
        let (enc_key, mac_key) = result.unwrap();
        assert_ne!(enc_key.as_ref(), mac_key.as_ref());
        assert_ne!(enc_key.as_ref(), &master_key);
    }
}
