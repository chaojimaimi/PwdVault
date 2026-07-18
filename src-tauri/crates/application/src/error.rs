//! Aggregate error type for the application layer.
//!
//! `VaultError` unifies domain validation errors, infrastructure crypto/db
//! errors, and application-level failures (locked vault, rate limit, etc.).
//! Adapters (Tauri IPC, Native Messaging) receive this type and serialize it
//! for the frontend/extension.

use pwdvault_domain::DomainError;
use pwdvault_infrastructure::crypto::{
    EncryptionError, KdfError, KeyStoreError, VerificationError,
};
use pwdvault_infrastructure::database::DatabaseError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum VaultError {
    VaultLocked,
    VaultAlreadyExists,
    InvalidPassword,
    EntryNotFound,
    EncryptionFailed(String),
    DecryptionFailed(String),
    DatabaseError(String),
    InternalError(String),
    InvalidBackup(String),
    InvalidInput { code: String, message: String },
    RateLimited { retry_after_secs: u64 },
}

impl From<DomainError> for VaultError {
    fn from(e: DomainError) -> Self {
        VaultError::InvalidInput {
            code: e.code,
            message: e.message,
        }
    }
}

impl From<EncryptionError> for VaultError {
    fn from(e: EncryptionError) -> Self {
        VaultError::EncryptionFailed(e.to_string())
    }
}

impl From<KeyStoreError> for VaultError {
    fn from(e: KeyStoreError) -> Self {
        match e {
            KeyStoreError::VaultLocked => VaultError::VaultLocked,
            KeyStoreError::AlreadyUnlocked => VaultError::VaultAlreadyExists,
        }
    }
}

impl From<KdfError> for VaultError {
    fn from(e: KdfError) -> Self {
        VaultError::InternalError(e.to_string())
    }
}

impl From<VerificationError> for VaultError {
    fn from(e: VerificationError) -> Self {
        VaultError::InternalError(e.to_string())
    }
}

impl From<DatabaseError> for VaultError {
    fn from(e: DatabaseError) -> Self {
        VaultError::DatabaseError(e.to_string())
    }
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::VaultLocked => write!(f, "Vault is locked"),
            VaultError::VaultAlreadyExists => write!(f, "Vault already exists"),
            VaultError::InvalidPassword => write!(f, "Invalid password"),
            VaultError::EntryNotFound => write!(f, "Entry not found"),
            VaultError::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            VaultError::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            VaultError::DatabaseError(e) => write!(f, "Database error: {}", e),
            VaultError::InternalError(e) => write!(f, "Internal error: {}", e),
            VaultError::InvalidBackup(e) => write!(f, "Invalid backup: {}", e),
            VaultError::InvalidInput { code, message } => write!(f, "{}: {}", code, message),
            VaultError::RateLimited { retry_after_secs } => {
                write!(
                    f,
                    "Too many failed attempts. Try again in {}s",
                    retry_after_secs
                )
            }
        }
    }
}

impl VaultError {
    /// Returns a sanitized message suitable for external callers (HTTP API,
    /// browser extension). Internal details such as file paths or serialization
    /// errors are stripped to avoid information leakage.
    pub fn public_message(&self) -> String {
        match self {
            VaultError::VaultLocked => "Vault is locked".to_string(),
            VaultError::VaultAlreadyExists => "Vault already exists".to_string(),
            VaultError::InvalidPassword => "Invalid password".to_string(),
            VaultError::EntryNotFound => "Entry not found".to_string(),
            VaultError::RateLimited { retry_after_secs } => {
                format!("Too many attempts. Retry in {}s", retry_after_secs)
            }
            VaultError::InvalidBackup(_) => "Invalid backup file".to_string(),
            VaultError::InvalidInput { code, message } => format!("{}: {}", code, message),
            VaultError::EncryptionFailed(_)
            | VaultError::DecryptionFailed(_)
            | VaultError::DatabaseError(_)
            | VaultError::InternalError(_) => "Internal error".to_string(),
        }
    }
}
