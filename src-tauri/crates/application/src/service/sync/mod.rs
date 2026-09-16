//! Multi-device sync (P3.1-P3.3 / D1-D4).
//!
//! Layout:
//! - this file: sync domain types + local↔sync conversion helpers,
//! - [`container`]: the self-contained encrypted snapshot container (D2),
//! - [`merge`]: the 2-way LWW merge engine (D3),
//! - [`backend`]: the [`backend::CloudBackend`] trait, WebDAV implementation
//!   and the mock test double (P3.2),
//! - [`engine`]: the sync engine + config/state rows + Tauri-facing
//!   `sync_connect`/`sync_now`/`sync_disconnect`/`sync_status` (P3.3).

pub mod backend;
pub mod container;
pub mod engine;
pub mod merge;

#[cfg(test)]
mod tests_webdav;
#[cfg(test)]
mod tests_engine;

use std::collections::HashMap;

use pwdvault_domain::validation::normalize_url;
use pwdvault_infrastructure::crypto::{encrypt, KEY_SIZE};
use pwdvault_infrastructure::database::PasswordEntry;

use crate::VaultError;

pub use container::{
    create_container, entry_fingerprint, open_container, ContainerError, SyncContainerV1,
};
pub use merge::{
    merge_entries, merge_groups, merge_snapshots, snapshots_equivalent, MergedSnapshot,
};

/// One password entry in sync (plaintext-domain) form (D2).
///
/// `password`, `notes` and `totp_secret` are PLAINTEXT: the snapshot exists
/// only inside the encrypted container (the E2E boundary — cloud storage only
/// ever sees ciphertext) or transiently in memory during a merge. It is never
/// written to redb or disk in this form.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SyncEntry {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    /// Plaintext password. `Some("")` mirrors the local empty-password
    /// representation (`PasswordEntry.encrypted_password` is non-optional).
    pub password: Option<String>,
    pub notes: Option<String>,
    /// Plaintext TOTP secret — a base32 string or a whole `otpauth://` URI
    /// (the generator parses either at read time, P2.4).
    pub totp_secret: Option<String>,
    pub tags: Vec<String>,
    /// Dangling references to tombstoned groups are allowed and preserved
    /// (P2.2: group removal does not cascade; the UI shows "ungrouped").
    pub group_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

/// One group in sync (plaintext-domain) form (D2).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SyncGroup {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

/// The full plaintext snapshot carried inside a container (D2).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SyncSnapshot {
    pub rev: u64,
    pub device_id: String,
    pub generated_at: i64,
    pub entries: Vec<SyncEntry>,
    pub groups: Vec<SyncGroup>,
}

/// Decrypted inner fields of one local entry, supplied by the caller (the
/// engine owns the session key — the conversion helpers below never touch key
/// material or the database).
#[derive(Debug, Clone)]
pub struct SyncSecrets {
    pub password: String,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
}

/// Convert local entries (raw rows with encrypted inner fields) to sync form.
///
/// `secrets` maps entry id → decrypted inner fields. An id missing from the
/// map converts with an empty password and no notes/TOTP secret — the engine
/// is expected to decrypt every entry it passes in; the fallback only keeps
/// the function total. URLs are normalized (same rule as backup import) so
/// both devices compare canonical values; `group_id` is passed through as-is
/// (hanging references are legitimate sync state, see [`SyncEntry`]).
pub fn entries_to_sync(
    entries: &[PasswordEntry],
    secrets: &HashMap<String, SyncSecrets>,
) -> Vec<SyncEntry> {
    entries
        .iter()
        .map(|entry| {
            let secret = secrets.get(&entry.id);
            SyncEntry {
                id: entry.id.clone(),
                title: entry.title.clone(),
                url: normalize_url(entry.url.clone()),
                username: entry.username.clone(),
                password: Some(secret.map(|s| s.password.clone()).unwrap_or_default()),
                notes: secret.and_then(|s| s.notes.clone()),
                totp_secret: secret.and_then(|s| s.totp_secret.clone()),
                tags: entry.tags.clone(),
                group_id: entry.group_id.clone(),
                created_at: entry.created_at,
                updated_at: entry.updated_at,
                deleted_at: entry.deleted_at,
            }
        })
        .collect()
}

/// Re-seal a merged sync entry as a local row: encrypts the inner fields with
/// the session enc key (bincode `EncryptedData` blobs — the same layout the
/// CRUD service writes) and preserves id, timestamps and tombstone so LWW
/// state survives the write-back. URLs are normalized on the way in, and a
/// `Some("")` TOTP secret means "cleared" (matching update_entry semantics).
pub fn sync_to_entry(
    entry: SyncEntry,
    enc_key: &[u8; KEY_SIZE],
) -> Result<PasswordEntry, VaultError> {
    let mut sealed = PasswordEntry::new(entry.title, normalize_url(entry.url), entry.username);
    sealed.id = entry.id;
    let encrypted_password = encrypt(
        enc_key,
        entry.password.as_deref().unwrap_or_default().as_bytes(),
    )?;
    sealed.encrypted_password = bincode::serialize(&encrypted_password)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
    sealed.encrypted_notes = match entry.notes {
        Some(notes) => Some(seal_inner(enc_key, &notes)?),
        None => None,
    };
    sealed.encrypted_totp_secret = match entry.totp_secret {
        Some(secret) if !secret.is_empty() => Some(seal_inner(enc_key, &secret)?),
        _ => None,
    };
    sealed.tags = entry.tags;
    sealed.group_id = entry.group_id;
    sealed.created_at = entry.created_at;
    sealed.updated_at = entry.updated_at;
    sealed.deleted_at = entry.deleted_at;
    Ok(sealed)
}

/// Encrypt one inner string field to its stored blob form.
fn seal_inner(enc_key: &[u8; KEY_SIZE], plain: &str) -> Result<Vec<u8>, VaultError> {
    let encrypted = encrypt(enc_key, plain.as_bytes())?;
    bincode::serialize(&encrypted).map_err(|e| VaultError::EncryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdvault_infrastructure::crypto::{decrypt, EncryptedData};

    const ENC_KEY: [u8; KEY_SIZE] = [7; KEY_SIZE];

    fn decrypt_inner(blob: &[u8]) -> String {
        let encrypted: EncryptedData = bincode::deserialize(blob).unwrap();
        String::from_utf8(decrypt(&ENC_KEY, &encrypted).unwrap()).unwrap()
    }

    fn sync_entry(id: &str) -> SyncEntry {
        SyncEntry {
            id: id.to_string(),
            title: format!("Title {id}"),
            url: Some("https://example.com".to_string()),
            username: format!("user-{id}"),
            password: Some("s3cret".to_string()),
            notes: Some("note".to_string()),
            totp_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
            tags: vec!["work".to_string()],
            group_id: Some("g1".to_string()),
            created_at: 1_700_000_000,
            updated_at: 1_700_000_100,
            deleted_at: None,
        }
    }

    /// Local → sync → local roundtrip preserves every field, with the inner
    /// secrets sealed exactly like the CRUD service writes them.
    #[test]
    fn conversion_roundtrip_preserves_fields_and_secrets() {
        let entry = sync_entry("e1");
        let sealed = sync_to_entry(entry.clone(), &ENC_KEY).unwrap();
        assert_eq!(sealed.id, "e1");
        assert_eq!(sealed.tags, entry.tags);
        assert_eq!(sealed.group_id.as_deref(), Some("g1"));
        assert_eq!(sealed.created_at, entry.created_at);
        assert_eq!(sealed.updated_at, entry.updated_at);
        assert_eq!(sealed.deleted_at, None);
        assert_eq!(decrypt_inner(&sealed.encrypted_password), "s3cret");
        assert!(sealed.encrypted_notes.is_some());
        assert!(sealed.encrypted_totp_secret.is_some());

        let mut secrets = HashMap::new();
        secrets.insert(
            sealed.id.clone(),
            SyncSecrets {
                password: "s3cret".to_string(),
                notes: Some("note".to_string()),
                totp_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
            },
        );
        let back = entries_to_sync(&[sealed], &secrets);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0], entry);
    }

    /// Optional-field edges: missing notes/TOTP stay `None`, a `Some("")`
    /// TOTP secret means "cleared", tombstones and empty passwords survive.
    #[test]
    fn conversion_handles_missing_empty_and_tombstoned_fields() {
        let mut entry = sync_entry("e2");
        entry.password = Some(String::new());
        entry.notes = None;
        entry.totp_secret = Some(String::new());
        entry.deleted_at = Some(1_700_000_200);
        entry.url = None;

        let sealed = sync_to_entry(entry, &ENC_KEY).unwrap();
        assert!(sealed.encrypted_notes.is_none());
        assert!(sealed.encrypted_totp_secret.is_none());
        assert_eq!(sealed.url, None);
        assert_eq!(sealed.deleted_at, Some(1_700_000_200));
        assert_eq!(decrypt_inner(&sealed.encrypted_password), "");

        // The documented fallback: an id without decrypted secrets converts
        // with an empty password and no notes/TOTP.
        let back = entries_to_sync(&[sealed], &HashMap::new());
        assert_eq!(back[0].password.as_deref(), Some(""));
        assert_eq!(back[0].notes, None);
        assert_eq!(back[0].totp_secret, None);
        assert_eq!(back[0].deleted_at, Some(1_700_000_200));
    }

    /// URLs are normalized on both conversion directions (same rule as
    /// backup import).
    #[test]
    fn conversion_normalizes_urls() {
        let mut entry = sync_entry("e3");
        entry.url = Some("  https://example.com/login  ".to_string());
        let sealed = sync_to_entry(entry, &ENC_KEY).unwrap();
        assert_eq!(sealed.url.as_deref(), Some("https://example.com/login"));

        let mut raw = PasswordEntry::new("Raw".to_string(), None, "user".to_string());
        raw.url = Some("  https://example.com/login  ".to_string());
        let synced = entries_to_sync(&[raw], &HashMap::new());
        assert_eq!(synced[0].url.as_deref(), Some("https://example.com/login"));
    }
}
