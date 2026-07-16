//! Entry encryption codec
//!
//! Seals an entire PasswordEntry into an encrypted blob so that metadata
//! (title, url, username, tags, group, timestamps) is not readable from the
//! raw database file. The entry id remains the plaintext table key.

use crate::crypto::{decrypt, encrypt, EncryptedData};

use super::{DatabaseError, PasswordEntry};

/// Serialize and encrypt a PasswordEntry.
pub fn seal_entry(entry: &PasswordEntry, key: &[u8; 32]) -> Result<Vec<u8>, DatabaseError> {
    let plain =
        bincode::serialize(entry).map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
    let enc = encrypt(key, &plain).map_err(|e| DatabaseError::EncryptionError(e.to_string()))?;
    bincode::serialize(&enc).map_err(|e| DatabaseError::SerializationError(e.to_string()))
}

/// Decrypt and deserialize a stored PasswordEntry blob.
///
/// Supports two formats:
/// - **v1.0.5+**: AES-256-GCM encrypted blob (EncryptedData serialized via bincode).
/// - **pre-v1.0.5**: plaintext bincode of PasswordEntry (no metadata encryption).
///
/// The fallback is only used during the one-time migration on unlock; after
/// migration all entries are re-saved in the encrypted format.
pub fn open_entry(blob: &[u8], key: &[u8; 32]) -> Result<PasswordEntry, DatabaseError> {
    // Try new encrypted format first.
    if let Ok(enc) = bincode::deserialize::<EncryptedData>(blob) {
        if let Ok(plain) = decrypt(key, &enc) {
            return bincode::deserialize(&plain)
                .map_err(|e| DatabaseError::SerializationError(e.to_string()));
        }
    }
    // Fallback: old plaintext format (pre-v1.0.5).
    bincode::deserialize(blob).map_err(|e| DatabaseError::SerializationError(e.to_string()))
}

/// Returns `true` if the blob is in the new encrypted format.
pub fn is_encrypted(blob: &[u8]) -> bool {
    bincode::deserialize::<EncryptedData>(blob).is_ok()
}
