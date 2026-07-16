//! AEAD-authenticated vault header for integrity anti-downgrade (§5.1.4).
//!
//! The vault header is stored as a row in `VAULT_TABLE["header"]`, encrypted
//! with `enc_key`. It contains version metadata that, once
//! `integrity_required = true`, prevents downgrade attacks:
//!
//! - Missing digest → reject unlock (not auto-migrate)
//! - Unknown digest version → reject unlock
//! - Migration only triggered by header absence or `integrity_required = false`

use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt_with_aad, encrypt_with_aad, EncryptedData};
use crate::database::{DatabaseError, VAULT_TABLE};
use redb::{Database, ReadableTable, WriteTransaction};

/// Current vault format version.
pub const VAULT_FORMAT_VERSION: u32 = 1;

/// Current schema version (stored in header for consistency).
pub const HEADER_SCHEMA_VERSION: u32 = 1;

/// Current record format version (AAD-enabled, §5.1.4).
pub const HEADER_RECORD_FORMAT_VERSION: u32 = 2;

/// Current digest algorithm version (v4 = AAD records, §5.1.4).
pub const HEADER_DIGEST_VERSION: u32 = 4;

/// Key under which the encrypted header is stored in VAULT_TABLE.
pub const HEADER_KEY: &str = "header";

/// AEAD-authenticated vault header.
///
/// Encrypted with `enc_key` so an attacker cannot forge it. The AAD for
/// the header itself is `b"vault_header"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub vault_format_version: u32,
    pub schema_version: u32,
    pub record_format_version: u32,
    pub digest_algorithm_version: u32,
    /// Once true, missing/unknown digest versions cause unlock to fail
    /// rather than triggering migration.
    pub integrity_required: bool,
    /// Incremented each time migration runs. Used to detect re-migration.
    pub migration_generation: u64,
}

impl VaultHeader {
    /// Create a new header for a freshly migrated or initialized vault.
    pub fn new_migrated() -> Self {
        Self {
            vault_format_version: VAULT_FORMAT_VERSION,
            schema_version: HEADER_SCHEMA_VERSION,
            record_format_version: HEADER_RECORD_FORMAT_VERSION,
            digest_algorithm_version: HEADER_DIGEST_VERSION,
            integrity_required: true,
            migration_generation: 1,
        }
    }

    /// Create a header for initial vault creation (no migration needed).
    pub fn new_initial() -> Self {
        Self {
            vault_format_version: VAULT_FORMAT_VERSION,
            schema_version: HEADER_SCHEMA_VERSION,
            record_format_version: HEADER_RECORD_FORMAT_VERSION,
            digest_algorithm_version: HEADER_DIGEST_VERSION,
            integrity_required: true,
            migration_generation: 0,
        }
    }

    /// Serialize and encrypt the header with enc_key.
    pub fn seal(&self, enc_key: &[u8; 32]) -> Result<Vec<u8>, DatabaseError> {
        let plain = bincode::serialize(self)
            .map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
        let aad = b"vault_header";
        let enc = encrypt_with_aad(enc_key, &plain, aad)
            .map_err(|e| DatabaseError::EncryptionError(e.to_string()))?;
        bincode::serialize(&enc).map_err(|e| DatabaseError::SerializationError(e.to_string()))
    }

    /// Decrypt and deserialize the header from a stored blob.
    pub fn open(blob: &[u8], enc_key: &[u8; 32]) -> Result<Self, DatabaseError> {
        let enc: EncryptedData = bincode::deserialize(blob)
            .map_err(|e| DatabaseError::DeserializationError(e.to_string()))?;
        let aad = b"vault_header";
        let plain = decrypt_with_aad(enc_key, &enc, aad)
            .map_err(|e| DatabaseError::DecryptionError(e.to_string()))?;
        bincode::deserialize(&plain).map_err(|e| DatabaseError::DeserializationError(e.to_string()))
    }
}

/// Read the vault header from the database (if present).
pub fn load_header(
    db: &Database,
    enc_key: &[u8; 32],
) -> Result<Option<VaultHeader>, DatabaseError> {
    let txn = db.begin_read()?;
    let table = txn.open_table(VAULT_TABLE)?;
    match table.get(HEADER_KEY)? {
        Some(value) => {
            let header = VaultHeader::open(value.value(), enc_key)?;
            Ok(Some(header))
        }
        None => Ok(None),
    }
}

/// Save the vault header within a write transaction (for use with VaultStore).
pub fn save_header_in_txn(
    txn: &WriteTransaction,
    header: &VaultHeader,
    enc_key: &[u8; 32],
) -> Result<(), DatabaseError> {
    let sealed = header.seal(enc_key)?;
    let mut table = txn.open_table(VAULT_TABLE)?;
    table.insert(HEADER_KEY, sealed.as_slice())?;
    Ok(())
}

/// Check whether the vault has integrity protection enabled (header present
/// with integrity_required=true). This is used by the unlock flow to decide
/// whether missing/unknown digest versions should fail-closed.
pub fn is_integrity_required(header: Option<&VaultHeader>) -> bool {
    header.map_or(false, |h| h.integrity_required)
}

/// Check whether the stored digest version is known/compatible.
pub fn is_digest_version_known(header: Option<&VaultHeader>) -> bool {
    header.map_or(false, |h| {
        h.digest_algorithm_version <= HEADER_DIGEST_VERSION
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [0xAB; 32];

    #[test]
    fn test_header_seal_open_roundtrip() {
        let header = VaultHeader::new_initial();
        let sealed = header.seal(&TEST_KEY).unwrap();
        let opened = VaultHeader::open(&sealed, &TEST_KEY).unwrap();
        assert_eq!(opened.vault_format_version, header.vault_format_version);
        assert_eq!(opened.integrity_required, true);
    }

    #[test]
    fn test_header_wrong_key_fails() {
        let header = VaultHeader::new_initial();
        let sealed = header.seal(&TEST_KEY).unwrap();
        let wrong_key = [0xCD; 32];
        assert!(VaultHeader::open(&sealed, &wrong_key).is_err());
    }

    #[test]
    fn test_header_tampered_fails() {
        let header = VaultHeader::new_initial();
        let mut sealed = header.seal(&TEST_KEY).unwrap();
        // Flip a byte in the ciphertext
        if !sealed.is_empty() {
            sealed[0] ^= 0xFF;
        }
        assert!(VaultHeader::open(&sealed, &TEST_KEY).is_err());
    }

    #[test]
    fn test_is_integrity_required() {
        assert!(!is_integrity_required(None));
        let h = VaultHeader::new_initial();
        assert!(is_integrity_required(Some(&h)));
    }
}
