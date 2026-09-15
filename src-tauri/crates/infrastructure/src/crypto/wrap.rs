//! Wrap-key primitives for master-key wrapping (Phase 1).
//!
//! A "wrap" stores the master key encrypted under a separate wrap key:
//! - **Biometric**: the wrap key lives only in the macOS Keychain behind a
//!   Touch ID access control (see `crate::keychain`).
//! - **Recovery**: the wrap key is SHA-256 of a random 32-byte recovery key
//!   shown once to the user at enable time.
//!
//! The wrapped blob is an AES-256-GCM `EncryptedData` (self-authenticating),
//! bound to its purpose via AAD so a bio blob can never be replayed as a
//! recovery blob or vice versa. Storage goes through `VAULT_TABLE` rows
//! (`VaultStore::write`), so the integrity digest also covers the blob.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{cipher, EncryptedData, KEY_SIZE};

/// AAD binding for the biometric wrap blob.
pub const WRAP_AAD_BIO: &[u8] = b"pwdvault-bio-wrap-v1";

/// AAD binding for the recovery wrap blob.
pub const WRAP_AAD_RECOVERY: &[u8] = b"pwdvault-recovery-wrap-v1";

#[derive(Error, Debug)]
pub enum WrapError {
    /// The blob failed authentication or parsing. Deliberately a single
    /// variant: tampered vs. corrupted vs. wrong-key are indistinguishable
    /// by GCM design, and merging them avoids a decryption oracle.
    #[error("Wrapped secret is invalid")]
    InvalidBlob,

    /// The pasted recovery key is not a valid 32-byte base64url value.
    #[error("Recovery key format is invalid")]
    RecoveryKeyInvalid,
}

impl From<cipher::EncryptionError> for WrapError {
    fn from(_: cipher::EncryptionError) -> Self {
        // Encryption/decryption failures collapse into InvalidBlob: callers
        // must not learn whether a blob was tampered with or malformed.
        WrapError::InvalidBlob
    }
}

/// Wrap `master_key` under `wrap_key` with purpose-bound AAD.
///
/// Output is `EncryptedData::to_bytes` (nonce || ciphertext+tag), ready for a
/// `VAULT_TABLE` blob row.
pub fn wrap_secret(
    wrap_key: &[u8; KEY_SIZE],
    master_key: &[u8; KEY_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>, WrapError> {
    let encrypted = cipher::encrypt_with_aad(wrap_key, master_key, aad)?;
    Ok(encrypted.to_bytes())
}

/// Unwrap a blob produced by [`wrap_secret`].
///
/// Returns the master key zeroized on drop. Any authentication or format
/// failure maps to [`WrapError::InvalidBlob`].
pub fn unwrap_secret(
    wrap_key: &[u8; KEY_SIZE],
    blob: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, WrapError> {
    let encrypted = EncryptedData::from_bytes(blob)?;
    let plain = cipher::decrypt_with_aad(wrap_key, &encrypted, aad)?;
    let plain: [u8; KEY_SIZE] = plain
        .try_into()
        .map_err(|_| WrapError::InvalidBlob)?;
    Ok(Zeroizing::new(plain))
}

/// Derive the recovery wrap key from a user-pasted recovery key.
///
/// trim → base64url decode (43 chars / 32 bytes expected) → SHA-256. The
/// recovery key has 256 bits of entropy, so SHA-256 alone is a sound AES key
/// — no password KDF needed.
pub fn recovery_wrap_key(recovery_key_paste: &str) -> Result<[u8; KEY_SIZE], WrapError> {
    let trimmed = recovery_key_paste.trim();
    let raw = URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .map_err(|_| WrapError::RecoveryKeyInvalid)?;
    // Accept exactly 32 decoded bytes. The canonical encoding is 43 chars, but
    // accept any base64url spelling that decodes to 32 bytes (e.g. a stray
    // '=' padded variant is rejected by URL_SAFE_NO_PAD, which is intended).
    if raw.len() != KEY_SIZE {
        return Err(WrapError::RecoveryKeyInvalid);
    }
    let key: [u8; KEY_SIZE] = raw
        .try_into()
        .map_err(|_| WrapError::RecoveryKeyInvalid)?;
    let digest: [u8; KEY_SIZE] = Sha256::digest(key).into();
    Ok(digest)
}

/// Generate a fresh biometric wrap key: 32 random bytes from the OS CSPRNG.
/// Stored only in the platform credential store (D5) — never on disk.
pub fn generate_wrap_key() -> [u8; KEY_SIZE] {
    let mut bytes = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a fresh recovery key: 32 random bytes, base64url, no padding
/// (43 characters). Shown to the user exactly once at enable time.
pub fn generate_recovery_key() -> String {
    let mut bytes = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; KEY_SIZE] = [0x11; KEY_SIZE];
    const WRAP: [u8; KEY_SIZE] = [0x22; KEY_SIZE];

    /// Length of a base64url (unpadded) encoding of a 32-byte recovery key.
    const RECOVERY_KEY_B64_LEN: usize = 43;

    #[test]
    fn wrap_roundtrip_bio_and_recovery() {
        for aad in [WRAP_AAD_BIO, WRAP_AAD_RECOVERY] {
            let blob = wrap_secret(&WRAP, &MASTER, aad).unwrap();
            let unwrapped = unwrap_secret(&WRAP, &blob, aad).unwrap();
            assert_eq!(*unwrapped, MASTER);
        }
    }

    #[test]
    fn aad_tamper_is_rejected() {
        let blob = wrap_secret(&WRAP, &MASTER, WRAP_AAD_BIO).unwrap();
        // Replaying the bio blob as a recovery blob must fail.
        assert!(matches!(
            unwrap_secret(&WRAP, &blob, WRAP_AAD_RECOVERY),
            Err(WrapError::InvalidBlob)
        ));
    }

    #[test]
    fn corrupted_blob_is_rejected() {
        let mut blob = wrap_secret(&WRAP, &MASTER, WRAP_AAD_BIO).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(
            unwrap_secret(&WRAP, &blob, WRAP_AAD_BIO),
            Err(WrapError::InvalidBlob)
        ));
    }

    #[test]
    fn truncated_blob_is_rejected() {
        let blob = wrap_secret(&WRAP, &MASTER, WRAP_AAD_BIO).unwrap();
        assert!(matches!(
            unwrap_secret(&WRAP, &blob[..blob.len() - 1], WRAP_AAD_BIO),
            Err(WrapError::InvalidBlob)
        ));
        assert!(matches!(
            unwrap_secret(&WRAP, &[], WRAP_AAD_BIO),
            Err(WrapError::InvalidBlob)
        ));
    }

    #[test]
    fn wrong_wrap_key_is_rejected() {
        let blob = wrap_secret(&WRAP, &MASTER, WRAP_AAD_BIO).unwrap();
        let wrong = [0x33; KEY_SIZE];
        assert!(matches!(
            unwrap_secret(&wrong, &blob, WRAP_AAD_BIO),
            Err(WrapError::InvalidBlob)
        ));
    }

    #[test]
    fn recovery_key_generation_roundtrip() {
        let key = generate_recovery_key();
        assert_eq!(key.len(), RECOVERY_KEY_B64_LEN);
        // Whitespace around the paste is tolerated.
        let derived = recovery_wrap_key(&format!("  {key}  ")).unwrap();

        // The derived wrap key must be reproducible from the same paste and
        // usable as an AES key for a full wrap roundtrip.
        let blob = wrap_secret(&derived, &MASTER, WRAP_AAD_RECOVERY).unwrap();
        assert_eq!(*unwrap_secret(&derived, &blob, WRAP_AAD_RECOVERY).unwrap(), MASTER);
    }

    #[test]
    fn recovery_keys_are_unique() {
        let a = recovery_wrap_key(&generate_recovery_key()).unwrap();
        let b = recovery_wrap_key(&generate_recovery_key()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_recovery_keys_are_rejected() {
        // Not base64url.
        assert!(recovery_wrap_key("not a key at all!!").is_err());
        // Valid base64url but wrong length (decoded != 32 bytes).
        assert!(recovery_wrap_key(URL_SAFE_NO_PAD.encode([0u8; 16]).as_str()).is_err());
        // 44 chars (padded) is rejected by the no-pad engine.
        let padded = format!("{}=", generate_recovery_key());
        assert!(recovery_wrap_key(&padded).is_err());
        // Empty.
        assert!(recovery_wrap_key("").is_err());
    }
}
