//! Multi-device sync (P3.1-P3.4 / D1-D4).
//!
//! Layout:
//! - this file: sync domain types + local↔sync conversion helpers,
//! - [`container`]: the self-contained encrypted snapshot container (D2),
//! - [`merge`]: the 2-way LWW merge engine (D3),
//! - [`backend`]: the [`backend::CloudBackend`] trait, WebDAV implementation
//!   and the mock test double (P3.2),
//! - [`baidu`]: the Baidu Netdisk adapter (P3.4),
//! - [`baidu_oauth`]: the Baidu OAuth2 pairing flow (P3.4),
//! - [`engine`]: the sync engine orchestration + Tauri-facing
//!   `sync_connect`/`sync_now`/`sync_disconnect`/`sync_status` (P3.3). The
//!   former single-file engine was split (M-3) into [`state_io`] (rows,
//!   config/state + local read/write-back I/O, session-key copies) and
//!   [`publish`] (container pull/push, manifest, history); `engine`
//!   re-exports their public names so pre-split import paths are stable.

pub mod backend;
pub mod baidu;
pub mod baidu_oauth;
pub mod container;
pub mod engine;
pub mod merge;
pub mod publish;
/// v1.6.0 split of `state_io` (800-line ceiling): sealed config/state row IO.
/// `state_io` re-exports its names, so the pre-split paths keep working.
pub mod sealed_rows;
pub mod state_io;

#[cfg(test)]
mod tests_auto_sync;
#[cfg(test)]
mod tests_baidu;
#[cfg(test)]
mod tests_baidu_flows;
#[cfg(test)]
mod tests_baidu_oauth;
#[cfg(test)]
mod tests_conflicts;
#[cfg(test)]
mod tests_connect;
#[cfg(test)]
mod tests_container_v2_fixture;
#[cfg(test)]
mod tests_engine;
#[cfg(test)]
mod tests_merge;
#[cfg(test)]
mod tests_state_io;
#[cfg(test)]
mod tests_webdav;
#[cfg(test)]
mod tests_window;

use std::collections::HashMap;
use std::mem;

use pwdvault_domain::validation::normalize_url;
use pwdvault_domain::{CustomField, UrlMatchMode};
use pwdvault_infrastructure::crypto::{bc_serialize, encrypt, KEY_SIZE};
use pwdvault_infrastructure::database::PasswordEntry;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
///
/// SEC-M3: the whole plaintext domain derives `Zeroize`/`ZeroizeOnDrop`, so
/// dropped snapshots/entries wipe their fields. CONSEQUENTLY: never debug-log
/// a value of these types (`Debug` would print the plaintext and defeat the
/// zeroization boundary), and never partially move a field out of them
/// (E0509) — take fields with `mem::take` instead.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
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
    /// Per-entry URL match override for the extension's autofill gates
    /// (v1.5.0 WP4). `#[serde(default)]` is LOAD-BEARING for read-side v1
    /// container compatibility: the snapshot payload is serde_json (not
    /// bincode), so containers written before the field existed deserialize
    /// with every entry on Auto. Bincode IS used for the LWW fingerprint —
    /// both devices must therefore run the same container format version
    /// (the reason CONTAINER_FORMAT_VERSION bumped to 2).
    #[serde(default)]
    pub url_match_mode: UrlMatchMode,
    /// User-defined custom fields (v1.6.0 WP1), values PLAINTEXT here: the
    /// snapshot exists only inside the encrypted container or transiently in
    /// memory during a merge (same disclosure boundary as `password`).
    /// `#[serde(default)]` is LOAD-BEARING for read-side v1/v2 container
    /// compatibility, exactly like `url_match_mode` above: older containers'
    /// serde_json snapshots lack the key and deserialize with empty fields.
    /// The field also changes the bincode LWW fingerprint input — cross-version
    /// sync is cut off at the container version gate (see container.rs).
    #[serde(default)]
    pub custom_fields: Vec<SyncCustomField>,
}

/// One custom field in sync (plaintext-domain) form (v1.6.0 WP1). The value
/// is plaintext and zeroizes with the entry — labels/flags follow the same
/// disclosure boundary as every other `SyncEntry` field.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SyncCustomField {
    pub label: String,
    /// Plaintext value; the empty string mirrors the local placeholder row.
    pub value: String,
    /// UI mask hint, mirrored from the stored field.
    pub secret: bool,
}

/// One group in sync (plaintext-domain) form (D2).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SyncGroup {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

/// The full plaintext snapshot carried inside a container (D2).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
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
///
/// v1.6.0: `custom_fields` carries the decrypted custom-field values (full
/// `SyncCustomField` rows — label/secret ride along so the sync snapshot is
/// self-contained). An id missing from the map converts with an empty vec
/// (same fallback contract as `password`).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SyncSecrets {
    pub password: String,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub custom_fields: Vec<SyncCustomField>,
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
                url_match_mode: entry.url_match_mode,
                // Documented fallback: a missing secrets entry converts with
                // empty fields (same contract as the empty password above).
                custom_fields: secret.map(|s| s.custom_fields.clone()).unwrap_or_default(),
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
    mut entry: SyncEntry,
    enc_key: &[u8; KEY_SIZE],
) -> Result<PasswordEntry, VaultError> {
    // `SyncEntry` is ZeroizeOnDrop — partial moves are forbidden (E0509).
    // Take each owned field instead: the values flow on exactly as before
    // and the emptied shell is wiped when `entry` drops. `url_match_mode`
    // is Copy, so it is read (copied) out alongside the takes.
    let id = mem::take(&mut entry.id);
    let title = mem::take(&mut entry.title);
    let url = normalize_url(mem::take(&mut entry.url));
    let username = mem::take(&mut entry.username);
    let notes = mem::take(&mut entry.notes);
    let totp_secret = mem::take(&mut entry.totp_secret);
    let tags = mem::take(&mut entry.tags);
    let group_id = mem::take(&mut entry.group_id);
    let custom_fields = mem::take(&mut entry.custom_fields);
    let url_match_mode = entry.url_match_mode;

    let mut sealed = PasswordEntry::new(title, url, username);
    sealed.id = id;
    let encrypted_password = encrypt(
        enc_key,
        entry.password.as_deref().unwrap_or_default().as_bytes(),
    )?;
    sealed.encrypted_password = bc_serialize(&encrypted_password)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
    sealed.encrypted_notes = match notes {
        Some(notes) => Some(seal_inner(enc_key, &notes)?),
        None => None,
    };
    sealed.encrypted_totp_secret = match totp_secret {
        Some(secret) if !secret.is_empty() => Some(seal_inner(enc_key, &secret)?),
        _ => None,
    };
    sealed.tags = tags;
    sealed.group_id = group_id;
    sealed.created_at = entry.created_at;
    sealed.updated_at = entry.updated_at;
    sealed.deleted_at = entry.deleted_at;
    sealed.url_match_mode = url_match_mode;
    sealed.custom_fields = seal_sync_custom_fields(enc_key, &custom_fields)?;
    Ok(sealed)
}

/// Seal sync plaintext custom fields into their stored form: label/secret
/// stay plaintext (the outer blob covers them), each value is inner-encrypted.
/// An empty plaintext skips encryption and stores the empty-vec placeholder —
/// the same symmetry the backup import path applies.
fn seal_sync_custom_fields(
    enc_key: &[u8; KEY_SIZE],
    fields: &[SyncCustomField],
) -> Result<Vec<CustomField>, VaultError> {
    fields
        .iter()
        .map(|field| {
            Ok(CustomField {
                label: field.label.clone(),
                value: if field.value.is_empty() {
                    Vec::new()
                } else {
                    seal_inner(enc_key, &field.value)?
                },
                secret: field.secret,
            })
        })
        .collect()
}

/// Encrypt one inner string field to its stored blob form.
fn seal_inner(enc_key: &[u8; KEY_SIZE], plain: &str) -> Result<Vec<u8>, VaultError> {
    let encrypted = encrypt(enc_key, plain.as_bytes())?;
    bc_serialize(&encrypted).map_err(|e| VaultError::EncryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdvault_infrastructure::crypto::{bc_deserialize, decrypt, EncryptedData};

    const ENC_KEY: [u8; KEY_SIZE] = [7; KEY_SIZE];

    fn decrypt_inner(blob: &[u8]) -> String {
        let encrypted: EncryptedData = bc_deserialize(blob).unwrap();
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
            url_match_mode: UrlMatchMode::Auto,
            custom_fields: vec![
                SyncCustomField {
                    label: "API Key".to_string(),
                    value: "key-value-1".to_string(),
                    secret: true,
                },
                SyncCustomField {
                    label: "Placeholder".to_string(),
                    value: String::new(),
                    secret: false,
                },
            ],
        }
    }

    fn sync_secrets(id: &str) -> (String, SyncSecrets) {
        (
            id.to_string(),
            SyncSecrets {
                password: "s3cret".to_string(),
                notes: Some("note".to_string()),
                totp_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
                custom_fields: vec![
                    SyncCustomField {
                        label: "API Key".to_string(),
                        value: "key-value-1".to_string(),
                        secret: true,
                    },
                    SyncCustomField {
                        label: "Placeholder".to_string(),
                        value: String::new(),
                        secret: false,
                    },
                ],
            },
        )
    }

    /// Local → sync → local roundtrip preserves every field, with the inner
    /// secrets sealed exactly like the CRUD service writes them.
    #[test]
    fn conversion_roundtrip_preserves_fields_and_secrets() {
        let mut entry = sync_entry("e1");
        // v1.5.0 WP4: a non-default match mode must survive both directions.
        entry.url_match_mode = UrlMatchMode::Exact;
        let sealed = sync_to_entry(entry.clone(), &ENC_KEY).unwrap();
        assert_eq!(sealed.id, "e1");
        assert_eq!(sealed.tags, entry.tags);
        assert_eq!(sealed.group_id.as_deref(), Some("g1"));
        assert_eq!(sealed.created_at, entry.created_at);
        assert_eq!(sealed.updated_at, entry.updated_at);
        assert_eq!(sealed.deleted_at, None);
        assert_eq!(sealed.url_match_mode, UrlMatchMode::Exact);
        assert_eq!(decrypt_inner(&sealed.encrypted_password), "s3cret");
        assert!(sealed.encrypted_notes.is_some());
        assert!(sealed.encrypted_totp_secret.is_some());
        // v1.6.0: custom-field values seal into the row (labels/flags stay
        // plaintext); the empty placeholder stays an empty vec.
        assert_eq!(sealed.custom_fields.len(), 2);
        assert_eq!(sealed.custom_fields[0].label, "API Key");
        assert!(sealed.custom_fields[0].secret);
        assert_eq!(decrypt_inner(&sealed.custom_fields[0].value), "key-value-1");
        assert_eq!(sealed.custom_fields[1].label, "Placeholder");
        assert!(!sealed.custom_fields[1].secret);
        assert!(sealed.custom_fields[1].value.is_empty());

        let (id, secrets) = sync_secrets("e1");
        assert_eq!(id, sealed.id);
        let mut secrets_map = HashMap::new();
        secrets_map.insert(id, secrets);
        let back = entries_to_sync(&[sealed], &secrets_map);
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
        // with an empty password, no notes/TOTP, and no custom fields.
        let back = entries_to_sync(&[sealed], &HashMap::new());
        assert_eq!(back[0].password.as_deref(), Some(""));
        assert_eq!(back[0].notes, None);
        assert_eq!(back[0].totp_secret, None);
        assert_eq!(back[0].deleted_at, Some(1_700_000_200));
        assert!(back[0].custom_fields.is_empty());
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

    /// SEC-M3: the plaintext domain is explicitly scrubbable — `zeroize()`
    /// empties every field (the same wipe runs automatically on drop via
    /// `ZeroizeOnDrop`).
    #[test]
    fn zeroize_scrubs_plaintext_entry() {
        let mut entry = sync_entry("scrub");
        assert_eq!(entry.password.as_deref(), Some("s3cret"));
        entry.zeroize();
        assert_eq!(entry.id, "");
        assert_eq!(entry.title, "");
        assert_eq!(entry.url, None);
        assert_eq!(entry.username, "");
        assert_eq!(entry.password, None);
        assert_eq!(entry.notes, None);
        assert_eq!(entry.totp_secret, None);
        assert!(entry.tags.is_empty());
        assert_eq!(entry.group_id, None);
        assert_eq!(entry.created_at, 0);
        assert_eq!(entry.updated_at, 0);
        assert_eq!(entry.deleted_at, None);
        // The match override zeroes back to the default (Auto), not garbage.
        assert_eq!(entry.url_match_mode, UrlMatchMode::Auto);
        // v1.6.0: the custom-field rows (plaintext values included) wipe too.
        assert!(entry.custom_fields.is_empty());
    }
}
