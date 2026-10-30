//! Aggregate error type for the application layer.
//!
//! `VaultError` unifies domain validation errors, infrastructure crypto/db
//! errors, and application-level failures (locked vault, rate limit, etc.).
//! Adapters (Tauri IPC, Native Messaging) receive this type and serialize it
//! for the frontend/extension.
//!
//! Serialization is hand-written (v1.3.2): every variant serializes to its
//! [`VaultError::public_message`] string, so both IPC and HTTP present the
//! SAME sanitized shape — the derived enum shape used to leak internal detail
//! (paths, serialization errors) through the Tauri reject value.

use pwdvault_domain::DomainError;
use pwdvault_infrastructure::crypto::{EncryptionError, KdfError, VerificationError};
use pwdvault_infrastructure::database::DatabaseError;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Deserialize)]
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
    InvalidInput {
        code: String,
        message: String,
    },
    RateLimited {
        retry_after_secs: u64,
    },
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
    /// Digest pre-verification rejected a write (fix plan A §2.2): the
    /// stored digest does not match the database contents under the keys the
    /// caller held. The transaction rolled back; the vault is unchanged.
    IntegrityCheckFailed,
}

impl Serialize for VaultError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Single shape for every transport: the sanitized public message (the
        // same string the HTTP bridge sends). Raw payloads never serialize.
        serializer.serialize_str(&self.public_message())
    }
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
        match e {
            // Surface the integrity failure distinctly so public_message can
            // tell the user their data refused verification (fix plan A).
            DatabaseError::IntegrityMismatch => VaultError::IntegrityCheckFailed,
            other => VaultError::DatabaseError(other.to_string()),
        }
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
            VaultError::IntegrityCheckFailed => write!(f, "Database integrity check failed"),
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
            // Wire shape pinned by biometric_cancelled_wire_shape_is_pinned
            // below and by the frontend guard AuthContext.isBiometricCancelled
            // (src/context/AuthContext.tsx) — change both sides together.
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
            VaultError::IntegrityCheckFailed => {
                "Vault integrity check failed. The operation was cancelled and \
                the vault is unchanged — if this keeps happening, restore from \
                a backup"
                    .to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v1.3.2: the IPC serialization of a VaultError is its public message —
    /// internal payloads (paths, serialization errors) must never cross the
    /// boundary the way the old derived enum shape let them.
    #[test]
    fn ipc_serialization_exposes_only_the_public_message() {
        let err = VaultError::InternalError("C:\\secret\\path".to_string());
        let json = serde_json::to_string(&err).expect("serialize VaultError");
        assert!(
            !json.contains("secret"),
            "raw payload leaked through serialization: {json}"
        );
        assert_eq!(json, "\"Internal error\"");

        // Same single shape for every variant family, matching the HTTP path.
        let input = VaultError::InvalidInput {
            code: "TOTP_NOT_CONFIGURED".to_string(),
            message: "no secret".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&input).expect("serialize InvalidInput"),
            "\"TOTP_NOT_CONFIGURED: no secret\""
        );

        let rate = VaultError::RateLimited {
            retry_after_secs: 42,
        };
        assert_eq!(
            serde_json::to_string(&rate).expect("serialize RateLimited"),
            "\"Too many attempts. Retry in 42s\""
        );
    }

    /// v1.8.1 cross-boundary contract: the dismissed-Touch-ID wire string is
    /// matched EXACTLY by the frontend guard AuthContext.isBiometricCancelled
    /// (src/context/AuthContext.tsx, guarded there by
    /// biometricCancelledContract.test.ts). Changing this copy requires
    /// updating that set in the same commit.
    #[test]
    fn biometric_cancelled_wire_shape_is_pinned() {
        let err = VaultError::BiometricCancelled;
        assert_eq!(
            serde_json::to_string(&err).expect("serialize VaultError"),
            "\"Touch ID was cancelled\""
        );
    }
}
