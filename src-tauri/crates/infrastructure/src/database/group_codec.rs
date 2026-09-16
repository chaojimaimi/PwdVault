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
//!
//! ## Layout dual-read (format v3 groundwork)
//!
//! The inner plaintext layout gained the trailing `deleted_at` field. Bincode
//! 1.x encodes structs positionally and does NOT honor serde field defaults
//! (upstream bincode#179), so every inner deserialization goes through
//! [`decode_group_plain`] — the same pattern as `LegacySettingsV1` in
//! `database/mod.rs`.

use serde::Deserialize;

use crate::crypto::{decrypt, decrypt_with_aad, encrypt_with_aad, EncryptedData};

use super::{DatabaseError, Group};

/// Current record format version for groups (§5.1.4: AAD introduced).
pub const GROUP_RECORD_FORMAT_VERSION: u32 = 2;

/// Group layout written by versions before soft delete. Deserialize-only:
/// never written back.
#[derive(Debug, Deserialize)]
struct LegacyGroupV2 {
    id: String,
    name: String,
    created_at: i64,
    updated_at: i64,
}

/// Build the AAD for a group: `table_name || record_id || record_format_version`
fn group_aad(group_id: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"groups");
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(&GROUP_RECORD_FORMAT_VERSION.to_le_bytes());
    aad
}

/// Deserialize inner plaintext bytes as a [`Group`].
///
/// Tries the current layout first, then the legacy pre-v3 layout with
/// `deleted_at` defaulting to `None`. All three `open_group` inner channels
/// (v2 AAD / v1 / plaintext migration) route through this helper.
fn decode_group_plain(plain: &[u8]) -> Result<Group, DatabaseError> {
    if let Ok(group) = bincode::deserialize::<Group>(plain) {
        return Ok(group);
    }
    let legacy: LegacyGroupV2 = bincode::deserialize(plain)
        .map_err(|e| DatabaseError::DeserializationError(e.to_string()))?;
    Ok(Group {
        id: legacy.id,
        name: legacy.name,
        created_at: legacy.created_at,
        updated_at: legacy.updated_at,
        deleted_at: None,
    })
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
///
/// The plaintext fallback is only permitted when `allow_plaintext` is true —
/// reserved for the explicit legacy migration path. Runtime callers must pass
/// `false` so injected plaintext records fail closed (see `open_entry`).
///
/// Every inner deserialization is layout dual-read: records written before the
/// soft-delete field was added are upgraded with `deleted_at = None` (see
/// [`decode_group_plain`]).
pub fn open_group(
    blob: &[u8],
    key: &[u8; 32],
    group_id: &str,
    allow_plaintext: bool,
) -> Result<Group, DatabaseError> {
    super::check_encoded_blob_size(blob)?;
    // Try v2 (AAD) first.
    if let Ok(enc) = bincode::deserialize::<EncryptedData>(blob) {
        let aad = group_aad(group_id);
        if let Ok(plain) = decrypt_with_aad(key, &enc, &aad) {
            return decode_group_plain(&plain);
        }
        // Try v1 (no AAD) as fallback.
        if let Ok(plain) = decrypt(key, &enc) {
            return decode_group_plain(&plain);
        }
    }
    // Fallback: old plaintext format (pre-v1.0.5), migration path only.
    if !allow_plaintext {
        return Err(DatabaseError::DeserializationError(
            "group record is not in an encrypted format".to_string(),
        ));
    }
    decode_group_plain(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt, encrypt_with_aad};

    const TEST_KEY: [u8; 32] = [4u8; 32];

    /// Fixture with the exact field layout written by versions before the
    /// soft-delete field was added.
    #[derive(serde::Serialize)]
    struct LegacyGroupFixture {
        id: String,
        name: String,
        created_at: i64,
        updated_at: i64,
    }

    fn legacy_blob() -> (String, Vec<u8>) {
        let fixture = LegacyGroupFixture {
            id: "legacy-group-1".to_string(),
            name: "Legacy Group".to_string(),
            created_at: 1_700_000_000,
            updated_at: 1_700_000_050,
        };
        let id = fixture.id.clone();
        (id, bincode::serialize(&fixture).unwrap())
    }

    /// Channel 3 (pre-v1.0.5 plaintext migration path).
    #[test]
    fn legacy_plaintext_layout_reads_with_deleted_at_none() {
        let (id, blob) = legacy_blob();
        let group = open_group(&blob, &TEST_KEY, &id, true).unwrap();
        assert_eq!(group.id, id);
        assert_eq!(group.name, "Legacy Group");
        assert_eq!(group.deleted_at, None);
    }

    /// Channel 1 (v2 AAD).
    #[test]
    fn legacy_layout_in_v2_aad_channel_reads_with_deleted_at_none() {
        let (id, legacy) = legacy_blob();
        let mut aad = Vec::new();
        aad.extend_from_slice(b"groups");
        aad.extend_from_slice(id.as_bytes());
        aad.extend_from_slice(&GROUP_RECORD_FORMAT_VERSION.to_le_bytes());
        let enc = encrypt_with_aad(&TEST_KEY, &legacy, &aad).unwrap();
        let blob = bincode::serialize(&enc).unwrap();

        let group = open_group(&blob, &TEST_KEY, &id, false).unwrap();
        assert_eq!(group.name, "Legacy Group");
        assert_eq!(group.deleted_at, None);
    }

    /// Channel 2 (v1, no AAD).
    #[test]
    fn legacy_layout_in_v1_channel_reads_with_deleted_at_none() {
        let (id, legacy) = legacy_blob();
        let enc = encrypt(&TEST_KEY, &legacy).unwrap();
        let blob = bincode::serialize(&enc).unwrap();

        let group = open_group(&blob, &TEST_KEY, &id, false).unwrap();
        assert_eq!(group.name, "Legacy Group");
        assert_eq!(group.deleted_at, None);
    }

    /// New-layout round trip preserves the tombstone.
    #[test]
    fn current_layout_roundtrip_preserves_deleted_at() {
        let mut group = Group::new("Current".to_string());
        group.deleted_at = Some(1_234_567_890);
        let blob = seal_group(&group, &TEST_KEY).unwrap();

        let loaded = open_group(&blob, &TEST_KEY, &group.id, false).unwrap();
        assert_eq!(loaded.deleted_at, Some(1_234_567_890));
    }

    /// A live current group round-trips with `deleted_at = None`.
    #[test]
    fn current_layout_live_group_roundtrip() {
        let group = Group::new("Live".to_string());
        let blob = seal_group(&group, &TEST_KEY).unwrap();
        let loaded = open_group(&blob, &TEST_KEY, &group.id, false).unwrap();
        assert_eq!(loaded.id, group.id);
        assert_eq!(loaded.name, "Live");
        assert_eq!(loaded.deleted_at, None);
    }
}
