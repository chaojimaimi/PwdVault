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

use zeroize::Zeroizing;

/// Size of the encryption key in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// A secret key wrapper that zeroizes on drop and cannot be Copy'd.
///
/// (§5.1.5) Wraps bare `[u8; 32]` key material in `Zeroizing<[u8; KEY_SIZE]>`
/// so the key bytes are wiped from memory when the value goes out of scope.
/// The type does NOT implement Copy or Clone, preventing accidental key
/// duplication. Use `as_ref()` to get a `&[u8; KEY_SIZE]` for crypto operations.
pub struct SecretKey(Zeroizing<[u8; KEY_SIZE]>);

impl SecretKey {
    /// Create a SecretKey from raw bytes (takes ownership).
    pub fn new(bytes: [u8; KEY_SIZE]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the key bytes for cryptographic operations.
    pub fn as_ref(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }

    /// Consume into raw bytes (caller responsible for zeroization).
    pub fn into_bytes(self) -> [u8; KEY_SIZE] {
        // Zeroizing derefs to the inner value; we extract via Deref.
        let tmp = self.0;
        *tmp
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log key material (§5.1.5: logs must not contain keys)
        write!(f, "SecretKey([REDACTED])")
    }
}

/// Size of the salt in bytes
pub const SALT_SIZE: usize = 16;

/// Size of the nonce in bytes (96 bits for AES-GCM)
pub const NONCE_SIZE: usize = 12;

/// Verification header constant
pub const VERIFICATION_HEADER: &[u8] = b"PWDVAULT_VERIFICATION_V1";
