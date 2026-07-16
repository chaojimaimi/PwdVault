//! Cryptography module for PwdVault
//!
//! This module provides secure encryption and key derivation functionality:
//! - Argon2id for key derivation (adaptive parameters)
//! - AES-256-GCM for symmetric encryption
//! - Secure key storage in memory (Mutex)
//! - Verification header for password validation

pub mod cipher;
pub mod kdf;
pub mod keystore;
pub mod verification;

// Re-export commonly used types and functions
pub use cipher::{
    decrypt, decrypt_with_aad, encrypt, encrypt_with_aad, EncryptedData, EncryptionError,
};
pub use kdf::{derive_key, derive_key_with_params, generate_salt, AdaptiveParams, KdfError};
pub use keystore::{KeyStore, KeyStoreError};
pub use verification::{
    create_verification_header, unlock_with_password, verify_password, VerificationData,
    VerificationError,
};

/// Size of the encryption key in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Size of the salt in bytes
pub const SALT_SIZE: usize = 16;

/// Size of the nonce in bytes (96 bits for AES-GCM)
pub const NONCE_SIZE: usize = 12;

/// Verification header constant
pub const VERIFICATION_HEADER: &[u8] = b"PWDVAULT_VERIFICATION_V1";
