//! Group encryption codec
//!
//! Seals an entire Group into an encrypted blob so that the group name is
//! not readable from the raw database file. The group id remains the plaintext
//! table key.
//!
//! ## Record format versions
//!
//! - **v1**: AES-256-GCM without AAD (pre-§5.1.4).
//! - **v2**: AES-256-GCM with AAD = `table_name || record_id || record_format_version` (§5.1.4).

use crate::crypto::{decrypt, decrypt_with_aad, encrypt, encrypt_with_aad, EncryptedData};

use super::{DatabaseError, Group};

/// Current record format version for groups (§5.1.4: AAD introduced).
pub const GROUP_RECORD_FORMAT_VERSION: u32 = 2;

/// Build the AAD for a group: `table_name || record_id || record_format_version`
fn group_aad(group_id: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"groups");
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(&GROUP_RECORD_FORMAT_VERSION.to_le_bytes());
    aad
}

/// Serialize and encrypt a Group with AAD (§5.1.4 record format v2).
pub fn seal_group(group: &Group, key: &[u8; 32]) -> Result<Vec<u8>, DatabaseError> {
    let plain =
        bincode::serialize(group).map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
    let aad = group_aad(&group.id);
    let enc = encrypt_with_aad(key, &plain, &aad)
        .map_err(|e| DatabaseError::EncryptionError(e.to_string()))?;
    bincode::serialize(&enc).map_err(|e| DatabaseError::SerializationError(e.to_string()))
}

/// Decrypt and deserialize a stored Group blob.
///
/// Supports three formats (tried in order):
/// 1. **v2**: AES-256-GCM with AAD (current, §5.1.4)
/// 2. **v1**: AES-256-GCM without AAD (legacy v1.0.5)
/// 3. **pre-v1.0.5**: plaintext bincode of Group
pub fn open_group(blob: &[u8], key: &[u8; 32], group_id: &str) -> Result<Group, DatabaseError> {
    // Try v2 (AAD) first.
    if let Ok(enc) = bincode::deserialize::<EncryptedData>(blob) {
        let aad = group_aad(group_id);
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
