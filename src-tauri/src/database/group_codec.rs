//! Group encryption codec
//!
//! Seals an entire Group into an encrypted blob so that the group name is
//! not readable from the raw database file. The group id remains the plaintext
//! table key.

use crate::crypto::{decrypt, encrypt, EncryptedData};

use super::{DatabaseError, Group};

/// Serialize and encrypt a Group.
pub fn seal_group(group: &Group, key: &[u8; 32]) -> Result<Vec<u8>, DatabaseError> {
    let plain = bincode::serialize(group)
        .map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
    let enc = encrypt(key, &plain).map_err(|e| DatabaseError::EncryptionError(e.to_string()))?;
    bincode::serialize(&enc)
        .map_err(|e| DatabaseError::SerializationError(e.to_string()))
}

/// Decrypt and deserialize a stored Group blob.
///
/// Supports two formats:
/// - **v1.0.5+**: AES-256-GCM encrypted blob.
/// - **pre-v1.0.5**: plaintext bincode of Group.
pub fn open_group(blob: &[u8], key: &[u8; 32]) -> Result<Group, DatabaseError> {
    // Try new encrypted format first.
    if let Ok(enc) = bincode::deserialize::<EncryptedData>(blob) {
        if let Ok(plain) = decrypt(key, &enc) {
            return bincode::deserialize(&plain)
                .map_err(|e| DatabaseError::SerializationError(e.to_string()));
        }
    }
    // Fallback: old plaintext format (pre-v1.0.5).
    bincode::deserialize(blob)
        .map_err(|e| DatabaseError::SerializationError(e.to_string()))
}
