//! Entry encryption codec
//!
//! Seals an entire PasswordEntry into an encrypted blob so that metadata
//! (title, url, username, tags, group, timestamps) is not readable from the
//! raw database file. The entry id remains the plaintext table key.
//!
//! ## Record format versions
//!
//! - **v1**: AES-256-GCM without AAD (pre-§5.1.4). Legacy data from v1.0.5.
//! - **v2**: AES-256-GCM with AAD = `table_name || record_id || record_format_version` (§5.1.4).
//!   Binds each record to its table and id, preventing cross-table/cross-record swap.

use crate::crypto::{decrypt, decrypt_with_aad, encrypt, encrypt_with_aad, EncryptedData};

use super::{DatabaseError, PasswordEntry};

/// Current record format version for entries (§5.1.4: AAD introduced).
pub const ENTRY_RECORD_FORMAT_VERSION: u32 = 2;

/// Build the AAD for an entry: `table_name || record_id || record_format_version`
fn entry_aad(entry_id: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"entries");
    aad.extend_from_slice(entry_id.as_bytes());
    aad.extend_from_slice(&ENTRY_RECORD_FORMAT_VERSION.to_le_bytes());
    aad
}

/// Serialize and encrypt a PasswordEntry with AAD (§5.1.4 record format v2).
pub fn seal_entry(entry: &PasswordEntry, key: &[u8; 32]) -> Result<Vec<u8>, DatabaseError> {
    let plain =
        bincode::serialize(entry).map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
    let aad = entry_aad(&entry.id);
    let enc = encrypt_with_aad(key, &plain, &aad)
        .map_err(|e| DatabaseError::EncryptionError(e.to_string()))?;
    bincode::serialize(&enc).map_err(|e| DatabaseError::SerializationError(e.to_string()))
}

/// Decrypt and deserialize a stored PasswordEntry blob.
///
/// Supports three formats (tried in order):
/// 1. **v2**: AES-256-GCM with AAD (current, §5.1.4)
/// 2. **v1**: AES-256-GCM without AAD (legacy v1.0.5)
/// 3. **pre-v1.0.5**: plaintext bincode of PasswordEntry (no encryption)
///
/// The fallbacks are only used during migration; after migration all entries
/// are re-saved in the v2 format.
pub fn open_entry(
    blob: &[u8],
    key: &[u8; 32],
    entry_id: &str,
) -> Result<PasswordEntry, DatabaseError> {
    // Try v2 (AAD) first.
    if let Ok(enc) = bincode::deserialize::<EncryptedData>(blob) {
        let aad = entry_aad(entry_id);
        if let Ok(plain) = decrypt_with_aad(key, &enc, &aad) {
            return bincode::deserialize(&plain)
                .map_err(|e| DatabaseError::SerializationError(e.to_string()));
        }
        // Try v1 (no AAD) as fallback.
        if let Ok(plain) = decrypt(key, &enc) {
            return bincode::deserialize(&plain)
                .map_err(|e| DatabaseError::SerializationError(e.to_string()));
        }
    }
    // Fallback: old plaintext format (pre-v1.0.5).
    bincode::deserialize(blob).map_err(|e| DatabaseError::SerializationError(e.to_string()))
}

/// Returns `true` if the blob is in the encrypted format (v1 or v2).
pub fn is_encrypted(blob: &[u8]) -> bool {
    bincode::deserialize::<EncryptedData>(blob).is_ok()
}
