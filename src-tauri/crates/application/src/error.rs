//! Aggregate error type for the application layer.
//!
//! `VaultError` unifies domain validation errors, infrastructure crypto/db
//! errors, and application-level failures (locked vault, rate limit, etc.).
//! Adapters (Tauri IPC, Native Messaging) receive this type and serialize it
//! for the frontend/extension.

use pwdvault_domain::DomainError;
use pwdvault_infrastructure::crypto::{EncryptionError, KdfError, VerificationError};
use pwdvault_infrastructure::database::DatabaseError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum VaultError {
    VaultLocked,
    VaultAlreadyExists,
    LegacyVaultRequiresMigration,
    InvalidPassword,
    EntryNotFound,
    EncryptionFailed(String),
    DecryptionFailed(String),
    DatabaseError(String),
    InternalError(String),
    InvalidBackup(String),
    /// X6: the backup's embedded KDF parameters are below the import-side
    /// product floor (OWASP baseline). Rejected before any key derivation.
    WeakKdfParams,
    InvalidInput { code: String, message: String },
    RateLimited { retry_after_secs: u64 },
    // --- Phase 1 (change password / Touch ID / recovery key) ---
    /// The platform cannot offer biometric unlock right now (unsupported,
    /// not enrolled, or the stored credentials are out of sync).
    BiometricUnavailable,
    /// The user dismissed the Touch ID prompt.
    BiometricCancelled,
    /// Biometry is locked out after repeated failed attempts.
    BiometricLockedOut,
    /// A stored wrap blob failed authentication/parsing (tampered, corrupt,
    /// or out of sync with the credential store).
    WrapBlobCorrupt,
    /// The pasted recovery key has a bad format or does not match the vault.
    RecoveryKeyInvalid,
    /// No recovery wrap blob exists for this vault.
    RecoveryNotEnabled,
    /// The "current master password" field of a settings operation is wrong.
    CurrentPasswordInvalid,
    /// The platform credential store failed in an unexpected way. The string
    /// carries user guidance only — never secret material.
    KeychainError(String),
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

impl From<pwdvault_infrastructure::crypto::WrapError> for VaultError {
    fn from(e: pwdvault_infrastructure::crypto::WrapError) -> Self {
        match e {
            pwdvault_infrastructure::crypto::WrapError::InvalidBlob => VaultError::WrapBlobCorrupt,
            pwdvault_infrastructure::crypto::WrapError::RecoveryKeyInvalid => {
                VaultError::RecoveryKeyInvalid
            }
        }
    }
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::VaultLocked => write!(f, "Vault is locked"),
            VaultError::VaultAlreadyExists => write!(f, "Vault already exists"),
            VaultError::LegacyVaultRequiresMigration => write!(
                f,
                "Vault database is missing its integrity header and must be migrated"
            ),
            VaultError::InvalidPassword => write!(f, "Invalid password"),
            VaultError::EntryNotFound => write!(f, "Entry not found"),
            VaultError::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            VaultError::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            VaultError::DatabaseError(e) => write!(f, "Database error: {}", e),
            VaultError::InternalError(e) => write!(f, "Internal error: {}", e),
            VaultError::InvalidBackup(e) => write!(f, "Invalid backup: {}", e),
            VaultError::WeakKdfParams => write!(
                f,
                "Backup KDF parameters are below the import policy floor"
            ),
            VaultError::InvalidInput { code, message } => write!(f, "{}: {}", code, message),
            VaultError::RateLimited { retry_after_secs } => {
                write!(
                    f,
                    "Too many failed attempts. Try again in {}s",
                    retry_after_secs
                )
            }
            VaultError::BiometricUnavailable => write!(
                f,
                "Biometric unlock is not available or is out of sync with this vault"
            ),
            VaultError::BiometricCancelled => write!(f, "Touch ID was cancelled"),
            VaultError::BiometricLockedOut => write!(
                f,
                "Biometric authentication is locked out. Unlock with your master password and try again"
            ),
            VaultError::WrapBlobCorrupt => write!(
                f,
                "Stored credential blob is corrupt or out of sync. Disable and re-enable the affected unlock method"
            ),
            VaultError::RecoveryKeyInvalid => write!(f, "Recovery key is invalid"),
            VaultError::RecoveryNotEnabled => {
                write!(f, "Recovery key is not enabled for this vault")
            }
            VaultError::CurrentPasswordInvalid => {
                write!(f, "Current password is incorrect")
            }
            VaultError::KeychainError(e) => write!(f, "Keychain error: {}", e),
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
            VaultError::LegacyVaultRequiresMigration => "Vault database is missing its integrity header. If this vault \
                was created by an older version of PwdVault (pre-1.0.5), \
                please migrate it using PwdVault 1.1.4 first, or restore from \
                a backup."
                .to_string(),
            VaultError::InvalidPassword => "Invalid password".to_string(),
            VaultError::EntryNotFound => "Entry not found".to_string(),
            VaultError::RateLimited { retry_after_secs } => {
                format!("Too many attempts. Retry in {}s", retry_after_secs)
            }
            VaultError::InvalidBackup(_) => "Invalid backup file".to_string(),
            VaultError::WeakKdfParams => "This backup uses weak KDF parameters and is rejected by the import policy"
                .to_string(),
            VaultError::InvalidInput { code, message } => format!("{}: {}", code, message),
            VaultError::EncryptionFailed(_)
            | VaultError::DecryptionFailed(_)
            | VaultError::DatabaseError(_)
            | VaultError::InternalError(_) => "Internal error".to_string(),
            VaultError::BiometricUnavailable => {
                "Biometric unlock is not available on this device or is out of sync with this vault. \
                Unlock with your master password and set it up again"
                    .to_string()
            }
            VaultError::BiometricCancelled => "Touch ID was cancelled".to_string(),
            VaultError::BiometricLockedOut => {
                "Biometric authentication is locked out. Unlock with your master password and try again"
                    .to_string()
            }
            VaultError::WrapBlobCorrupt => {
                "Stored credential is corrupt or out of sync. Unlock with your master password, \
                then disable and re-enable the affected unlock method in Settings"
                    .to_string()
            }
            VaultError::RecoveryKeyInvalid => {
                "Recovery key is invalid. Check the saved key and try again".to_string()
            }
            VaultError::RecoveryNotEnabled => {
                "Recovery key is not enabled for this vault".to_string()
            }
            VaultError::CurrentPasswordInvalid => {
                "Current password is incorrect".to_string()
            }
            VaultError::KeychainError(e) => format!("Keychain error: {}", e),
        }
    }
}
