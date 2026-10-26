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
//!
//! ## Layout generation chain (format v3 groundwork)
//!
//! The inner plaintext layout has gained trailing fields over time. Bincode
//! encodes structs positionally and does NOT honor serde field defaults
//! (upstream bincode#179), so a legacy record fails to deserialize as the
//! current struct (EOF) and the current struct fails as a legacy record
//! ("trailing bytes" in the other direction). Every inner deserialization
//! therefore goes through [`decode_entry_plain`], which walks the generation
//! chain newest-first:
//!
//! 1. **current (v1.5.0+)**: 14 fields — the struct gained `url_match_mode`;
//! 2. [`LegacyEntryV3`] (v1.1.5–v1.4.1): 13 fields — `url_match_mode`
//!    defaults to [`UrlMatchMode::Auto`];
//! 3. [`LegacyEntryV2`] (pre-v1.1.5): 11 fields — `deleted_at` /
//!    `encrypted_totp_secret` / `url_match_mode` all default.
//!
//! Adding a field WITHOUT extending this chain makes every entry written by
//! older versions unreadable (P0, caught in the v1.5.0 plan review); the
//! permanent 13-field golden fixture in `bincode_golden.rs` is the tripwire
//! that keeps generation 2 honest.

use serde::Deserialize;

use crate::crypto::{
    bc_deserialize, bc_serialize, decrypt, decrypt_with_aad, encrypt_with_aad, EncryptedData,
};

use super::{DatabaseError, PasswordEntry};
use pwdvault_domain::UrlMatchMode;

/// Current record format version for entries (§5.1.4: AAD introduced).
pub const ENTRY_RECORD_FORMAT_VERSION: u32 = 2;

/// Entry layout written by versions before soft delete + TOTP (the record
/// layout shipped in v1.1.5). Deserialize-only: never written back.
#[derive(Debug, Deserialize)]
struct LegacyEntryV2 {
    id: String,
    title: String,
    url: Option<String>,
    username: String,
    encrypted_password: Vec<u8>,
    encrypted_notes: Option<Vec<u8>>,
    tags: Vec<String>,
    created_at: i64,
    updated_at: i64,
    last_used_at: Option<i64>,
    group_id: Option<String>,
}

/// Entry layout written by v1.1.5–v1.4.1: exactly the pre-v1.5.0 13-field
/// shape (soft delete + TOTP, no per-entry URL match mode). Deserialize-only:
/// never written back. Generation 2 of the read chain — see the module docs.
#[derive(Debug, Deserialize)]
struct LegacyEntryV3 {
    id: String,
    title: String,
    url: Option<String>,
    username: String,
    encrypted_password: Vec<u8>,
    encrypted_notes: Option<Vec<u8>>,
    tags: Vec<String>,
    created_at: i64,
    updated_at: i64,
    last_used_at: Option<i64>,
    group_id: Option<String>,
    deleted_at: Option<i64>,
    encrypted_totp_secret: Option<Vec<u8>>,
}

/// Build the AAD for an entry: `table_name || record_id || record_format_version`
fn entry_aad(entry_id: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"entries");
    aad.extend_from_slice(entry_id.as_bytes());
    aad.extend_from_slice(&ENTRY_RECORD_FORMAT_VERSION.to_le_bytes());
    aad
}

/// Deserialize inner plaintext bytes as a [`PasswordEntry`].
///
/// Walks the layout generation chain newest-first: current 14-field layout →
/// [`LegacyEntryV3`] (13 fields, `url_match_mode` = Auto) → [`LegacyEntryV2`]
/// (11 fields, the v1.5.0 fields additionally defaulting). All three
/// `open_entry` inner channels (v2 AAD / v1 / plaintext migration) read
/// records that may use any generation, so they must all route through this
/// helper.
///
/// `pub(crate)` so the permanent 13-field golden fixture in
/// `bincode_golden.rs` can drive the real read path.
pub(crate) fn decode_entry_plain(plain: &[u8]) -> Result<PasswordEntry, DatabaseError> {
    if let Ok(entry) = bc_deserialize::<PasswordEntry>(plain) {
        return Ok(entry);
    }
    if let Ok(legacy) = bc_deserialize::<LegacyEntryV3>(plain) {
        return Ok(PasswordEntry {
            id: legacy.id,
            title: legacy.title,
            url: legacy.url,
            username: legacy.username,
            encrypted_password: legacy.encrypted_password,
            encrypted_notes: legacy.encrypted_notes,
            tags: legacy.tags,
            created_at: legacy.created_at,
            updated_at: legacy.updated_at,
            last_used_at: legacy.last_used_at,
            group_id: legacy.group_id,
            deleted_at: legacy.deleted_at,
            encrypted_totp_secret: legacy.encrypted_totp_secret,
            url_match_mode: UrlMatchMode::Auto,
        });
    }
    let legacy: LegacyEntryV2 =
        bc_deserialize(plain).map_err(|e| DatabaseError::DeserializationError(e.to_string()))?;
    Ok(PasswordEntry {
        id: legacy.id,
        title: legacy.title,
        url: legacy.url,
        username: legacy.username,
        encrypted_password: legacy.encrypted_password,
        encrypted_notes: legacy.encrypted_notes,
        tags: legacy.tags,
        created_at: legacy.created_at,
        updated_at: legacy.updated_at,
        last_used_at: legacy.last_used_at,
        group_id: legacy.group_id,
        deleted_at: None,
        encrypted_totp_secret: None,
        url_match_mode: UrlMatchMode::Auto,
    })
}

/// Serialize and encrypt a PasswordEntry with AAD (§5.1.4 record format v2).
pub fn seal_entry(entry: &PasswordEntry, key: &[u8; 32]) -> Result<Vec<u8>, DatabaseError> {
    let plain =
        bc_serialize(entry).map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
    let aad = entry_aad(&entry.id);
    let enc = encrypt_with_aad(key, &plain, &aad)
        .map_err(|e| DatabaseError::EncryptionError(e.to_string()))?;
    bc_serialize(&enc).map_err(|e| DatabaseError::SerializationError(e.to_string()))
}

/// Decrypt and deserialize a stored PasswordEntry blob.
///
/// Supports three formats (tried in order):
/// 1. **v2**: AES-256-GCM with AAD (current, §5.1.4)
/// 2. **v1**: AES-256-GCM without AAD (legacy v1.0.5)
/// 3. **pre-v1.0.5**: plaintext bincode of PasswordEntry (no encryption)
///
/// The plaintext fallback is only permitted when `allow_plaintext` is true —
/// reserved for the explicit legacy migration path. In the running vault a
/// plaintext record is attacker-injectable (the attacker needs only file write
/// access), so runtime callers must pass `false` and fail closed.
///
/// Every inner deserialization walks the layout generation chain: records
/// written before a trailing field was added are upgraded with the new fields
/// defaulted (see [`decode_entry_plain`]).
pub fn open_entry(
    blob: &[u8],
    key: &[u8; 32],
    entry_id: &str,
    allow_plaintext: bool,
) -> Result<PasswordEntry, DatabaseError> {
    super::check_encoded_blob_size(blob)?;
    // Try v2 (AAD) first.
    if let Ok(enc) = bc_deserialize::<EncryptedData>(blob) {
        let aad = entry_aad(entry_id);
        if let Ok(plain) = decrypt_with_aad(key, &enc, &aad) {
            return decode_entry_plain(&plain);
        }
        // Try v1 (no AAD) as fallback.
        if let Ok(plain) = decrypt(key, &enc) {
            return decode_entry_plain(&plain);
        }
    }
    // Fallback: old plaintext format (pre-v1.0.5), migration path only.
    if !allow_plaintext {
        return Err(DatabaseError::DeserializationError(
            "entry record is not in an encrypted format".to_string(),
        ));
    }
    decode_entry_plain(blob)
}

/// Returns `true` if the blob is in the encrypted format (v1 or v2).
/// Test-only: production readers decide via `decode_entry`'s versioned
/// fallback chain, not via a pre-classification probe.
#[cfg(test)]
pub fn is_encrypted(blob: &[u8]) -> bool {
    if super::check_encoded_blob_size(blob).is_err() {
        return false;
    }
    bc_deserialize::<EncryptedData>(blob).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt, encrypt_with_aad};

    const TEST_KEY: [u8; 32] = [3u8; 32];

    /// Fixture with the exact field layout written by versions before the
    /// soft-delete/TOTP fields were added (serialize, unlike the read-side
    /// `LegacyEntryV2`, so tests can produce real legacy blobs).
    #[derive(serde::Serialize)]
    struct LegacyEntryFixture {
        id: String,
        title: String,
        url: Option<String>,
        username: String,
        encrypted_password: Vec<u8>,
        encrypted_notes: Option<Vec<u8>>,
        tags: Vec<String>,
        created_at: i64,
        updated_at: i64,
        last_used_at: Option<i64>,
        group_id: Option<String>,
    }

    fn legacy_blob() -> (String, Vec<u8>) {
        let fixture = LegacyEntryFixture {
            id: "legacy-entry-1".to_string(),
            title: "Legacy Site".to_string(),
            url: Some("https://legacy.example".to_string()),
            username: "legacy-user".to_string(),
            encrypted_password: vec![9, 9, 9],
            encrypted_notes: None,
            tags: vec!["legacy".to_string()],
            created_at: 1_700_000_000,
            updated_at: 1_700_000_100,
            last_used_at: None,
            group_id: Some("group-7".to_string()),
        };
        let id = fixture.id.clone();
        (id, bc_serialize(&fixture).unwrap())
    }

    /// Channel 3 (pre-v1.0.5 plaintext migration path): a legacy-layout
    /// plaintext record opens with the new fields as `None`.
    #[test]
    fn legacy_plaintext_layout_reads_with_new_fields_none() {
        let (id, blob) = legacy_blob();
        let entry = open_entry(&blob, &TEST_KEY, &id, true).unwrap();
        assert_eq!(entry.id, id);
        assert_eq!(entry.title, "Legacy Site");
        assert_eq!(entry.group_id.as_deref(), Some("group-7"));
        assert_eq!(entry.created_at, 1_700_000_000);
        assert_eq!(entry.deleted_at, None);
        assert_eq!(entry.encrypted_totp_secret, None);
    }

    /// Channel 1 (v2 AAD): a legacy-layout record sealed under the current
    /// record format must decrypt and upgrade to the new layout.
    #[test]
    fn legacy_layout_in_v2_aad_channel_reads_with_new_fields_none() {
        let (id, legacy) = legacy_blob();
        let mut aad = Vec::new();
        aad.extend_from_slice(b"entries");
        aad.extend_from_slice(id.as_bytes());
        aad.extend_from_slice(&ENTRY_RECORD_FORMAT_VERSION.to_le_bytes());
        let enc = encrypt_with_aad(&TEST_KEY, &legacy, &aad).unwrap();
        let blob = bc_serialize(&enc).unwrap();

        let entry = open_entry(&blob, &TEST_KEY, &id, false).unwrap();
        assert_eq!(entry.title, "Legacy Site");
        assert_eq!(entry.deleted_at, None);
        assert_eq!(entry.encrypted_totp_secret, None);
    }

    /// Channel 2 (v1, no AAD): same generation-chain guarantee for v1.0.5
    /// records.
    #[test]
    fn legacy_layout_in_v1_channel_reads_with_new_fields_none() {
        let (id, legacy) = legacy_blob();
        let enc = encrypt(&TEST_KEY, &legacy).unwrap();
        let blob = bc_serialize(&enc).unwrap();

        let entry = open_entry(&blob, &TEST_KEY, &id, false).unwrap();
        assert_eq!(entry.title, "Legacy Site");
        assert_eq!(entry.deleted_at, None);
        assert_eq!(entry.encrypted_totp_secret, None);
    }

    /// New-layout round trip preserves the trailing fields.
    #[test]
    fn current_layout_roundtrip_preserves_new_fields() {
        let mut entry = PasswordEntry::new("Current".to_string(), None, "user".to_string());
        entry.deleted_at = Some(1_234_567_890);
        entry.encrypted_totp_secret = Some(vec![1, 2, 3, 4]);
        let blob = seal_entry(&entry, &TEST_KEY).unwrap();

        let loaded = open_entry(&blob, &TEST_KEY, &entry.id, false).unwrap();
        assert_eq!(loaded.deleted_at, Some(1_234_567_890));
        assert_eq!(loaded.encrypted_totp_secret, Some(vec![1, 2, 3, 4]));
    }

    /// Current-layout records stay sealed/unsealed symmetrically with the
    /// legacy channels: a live current entry round-trips through seal/open.
    #[test]
    fn current_layout_live_entry_roundtrip() {
        let entry = PasswordEntry::new("Live".to_string(), None, "user".to_string());
        let blob = seal_entry(&entry, &TEST_KEY).unwrap();
        let loaded = open_entry(&blob, &TEST_KEY, &entry.id, false).unwrap();
        assert_eq!(loaded.id, entry.id);
        assert_eq!(loaded.title, "Live");
        assert_eq!(loaded.deleted_at, None);
        assert_eq!(loaded.encrypted_totp_secret, None);
    }

    // -------------------------------------------------------------------
    // v1.5.0 WP4: generation 2 (LegacyEntryV3, the 13-field layout written
    // by v1.1.5–v1.4.1) + the 14-field round trip. The permanent golden
    // fixture for a REAL 13-field blob lives in bincode_golden.rs; these
    // tests cover the chain behavior on freshly produced blobs.
    // -------------------------------------------------------------------

    /// Fixture with the exact 13-field layout written by v1.1.5–v1.4.1
    /// (serialize so tests can produce real generation-2 blobs).
    #[derive(serde::Serialize)]
    struct LegacyEntryV3Fixture {
        id: String,
        title: String,
        url: Option<String>,
        username: String,
        encrypted_password: Vec<u8>,
        encrypted_notes: Option<Vec<u8>>,
        tags: Vec<String>,
        created_at: i64,
        updated_at: i64,
        last_used_at: Option<i64>,
        group_id: Option<String>,
        deleted_at: Option<i64>,
        encrypted_totp_secret: Option<Vec<u8>>,
    }

    fn v3_blob() -> (String, Vec<u8>) {
        let fixture = LegacyEntryV3Fixture {
            id: "v3-entry-1".to_string(),
            title: "V3 Site".to_string(),
            url: Some("https://v3.example".to_string()),
            username: "v3-user".to_string(),
            encrypted_password: vec![7, 7, 7],
            encrypted_notes: Some(vec![8, 8, 8]),
            tags: vec!["v3".to_string()],
            created_at: 1_700_000_000,
            updated_at: 1_700_000_200,
            last_used_at: Some(1_700_000_300),
            group_id: Some("group-9".to_string()),
            deleted_at: None,
            encrypted_totp_secret: Some(vec![1, 2, 3]),
        };
        let id = fixture.id.clone();
        (id, bc_serialize(&fixture).unwrap())
    }

    /// Generation 2 (13-field, v1.1.5–v1.4.1) plaintext records read with
    /// `url_match_mode` defaulted to Auto and every other field preserved.
    #[test]
    fn v3_layout_plaintext_reads_with_match_mode_auto() {
        let (id, blob) = v3_blob();
        let entry = open_entry(&blob, &TEST_KEY, &id, true).unwrap();
        assert_eq!(entry.id, id);
        assert_eq!(entry.title, "V3 Site");
        assert_eq!(entry.group_id.as_deref(), Some("group-9"));
        assert_eq!(entry.last_used_at, Some(1_700_000_300));
        assert_eq!(entry.deleted_at, None);
        assert_eq!(entry.encrypted_totp_secret, Some(vec![1, 2, 3]));
        assert_eq!(entry.url_match_mode, UrlMatchMode::Auto);
    }

    /// Generation 2 records sealed under the current record format (v2 AAD)
    /// still read — the layout chain is orthogonal to the record channel.
    #[test]
    fn v3_layout_in_v2_aad_channel_reads_with_match_mode_auto() {
        let (id, legacy) = v3_blob();
        let mut aad = Vec::new();
        aad.extend_from_slice(b"entries");
        aad.extend_from_slice(id.as_bytes());
        aad.extend_from_slice(&ENTRY_RECORD_FORMAT_VERSION.to_le_bytes());
        let enc = encrypt_with_aad(&TEST_KEY, &legacy, &aad).unwrap();
        let blob = bc_serialize(&enc).unwrap();

        let entry = open_entry(&blob, &TEST_KEY, &id, false).unwrap();
        assert_eq!(entry.title, "V3 Site");
        assert_eq!(entry.url_match_mode, UrlMatchMode::Auto);
    }

    /// The current 14-field layout round-trips the per-entry match mode
    /// through all three variants (bincode variant index is positional).
    #[test]
    fn current_layout_roundtrips_all_match_modes() {
        for (mode, other) in [
            (UrlMatchMode::Auto, UrlMatchMode::Exact),
            (UrlMatchMode::Exact, UrlMatchMode::Domain),
            (UrlMatchMode::Domain, UrlMatchMode::Auto),
        ] {
            let mut entry = PasswordEntry::new("Modes".to_string(), None, "user".to_string());
            entry.url_match_mode = mode;
            let blob = seal_entry(&entry, &TEST_KEY).unwrap();
            let loaded = open_entry(&blob, &TEST_KEY, &entry.id, false).unwrap();
            assert_eq!(loaded.url_match_mode, mode);
            assert_ne!(loaded.url_match_mode, other);
        }
    }

    /// A current-layout entry with a NON-default match mode still round-trips
    /// its other fields (guards a copy-paste slip in the field mapping).
    #[test]
    fn current_layout_roundtrip_preserves_match_mode_with_other_fields() {
        let mut entry = PasswordEntry::new(
            "Exact Site".to_string(),
            Some("https://exact.example".to_string()),
            "user".to_string(),
        );
        entry.url_match_mode = UrlMatchMode::Exact;
        entry.deleted_at = Some(1_234_567_890);
        entry.encrypted_totp_secret = Some(vec![4, 5, 6]);
        let blob = seal_entry(&entry, &TEST_KEY).unwrap();

        let loaded = open_entry(&blob, &TEST_KEY, &entry.id, false).unwrap();
        assert_eq!(loaded.url_match_mode, UrlMatchMode::Exact);
        assert_eq!(loaded.deleted_at, Some(1_234_567_890));
        assert_eq!(loaded.encrypted_totp_secret, Some(vec![4, 5, 6]));
    }
}
