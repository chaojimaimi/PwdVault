//! Request/response DTOs and backup file format models.
//!
//! These are wire-format types shared between the Tauri IPC and Native
//! Messaging adapters. They carry plaintext secrets wrapped in `Zeroizing`
//! so the heap buffer is wiped on drop.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entities::{Group, PasswordEntry, Settings, UrlMatchMode};

/// One custom field as submitted on create/update (v1.6.0 WP1). The value is
/// PLAINTEXT — the service layer encrypts it into `CustomField.value`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CustomFieldInput {
    pub label: String,
    /// Plaintext value; the empty string is legal (placeholder row).
    pub value: String,
    /// UI mask hint only — never a storage decision.
    pub secret: bool,
}

/// Request to create a new password entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateEntryRequest {
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    /// Plaintext password. Wrapped in Zeroizing so the heap buffer is wiped
    /// when the request is dropped (after encryption).
    pub password: Zeroizing<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub group_id: Option<String>,
    /// Per-entry URL match override for browser-extension autofill (v1.5.0).
    /// Serde default keeps older request payloads on the status-quo Auto.
    #[serde(default)]
    pub url_match_mode: UrlMatchMode,
    /// Custom fields (v1.6.0), created wholesale. Serde default keeps older
    /// request payloads (NM create without the field) on "no custom fields".
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldInput>,
}

/// Patch request for an existing entry. Sensitive fields are optional so a
/// metadata-only edit never needs to decrypt and resubmit the old secret.
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateEntryRequest {
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    #[serde(default)]
    pub password: Option<Zeroizing<String>>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub update_notes: bool,
    pub tags: Vec<String>,
    pub group_id: Option<String>,
    /// TOTP secret tri-state (same update semantics as the notes patch):
    /// `None` = leave unchanged, `Some("")` = clear, `Some(x)` = set. The
    /// value may be a plain base32 secret or a full `otpauth://` URI.
    #[serde(default)]
    pub totp_secret: Option<String>,
    /// Per-entry URL match override (v1.5.0). Replaced wholesale on update
    /// (metadata semantics, same as title/url/tags); the serde default keeps
    /// older request payloads on the status-quo Auto.
    #[serde(default)]
    pub url_match_mode: UrlMatchMode,
    /// Custom fields tri-state batch (v1.6.0): `None` = leave unchanged (a
    /// metadata-only edit never needs to resubmit values it does not hold),
    /// `Some(list)` = replace wholesale (same metadata semantics as tags —
    /// per-field patching would require the plaintext values on every edit).
    #[serde(default)]
    pub custom_fields: Option<Vec<CustomFieldInput>>,
}

impl From<CreateEntryRequest> for UpdateEntryRequest {
    fn from(request: CreateEntryRequest) -> Self {
        Self {
            title: request.title,
            url: request.url,
            username: request.username,
            password: Some(request.password),
            notes: request.notes,
            update_notes: true,
            tags: request.tags,
            group_id: request.group_id,
            totp_secret: None,
            url_match_mode: request.url_match_mode,
            custom_fields: Some(request.custom_fields),
        }
    }
}

/// Decrypted secrets for a password entry.
/// Returned only by explicit secret-fetch endpoints so plaintext fields are not
/// kept in memory longer than necessary.
#[derive(Debug, Serialize, Deserialize)]
pub struct EntrySecretResponse {
    pub password: Zeroizing<String>,
    pub notes: Option<Zeroizing<String>>,
    pub last_used_at: Option<i64>,
    /// Decrypted custom-field values (v1.6.0), one-shot like password/notes.
    /// `#[serde(default)]` keeps the response shape non-breaking for any
    /// consumer predating the field.
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldValue>,
}

/// Current TOTP code for an entry (`totp_code`, Tauri-only command).
#[derive(Debug, Serialize, Deserialize)]
pub struct TotpCodeResponse {
    pub code: String,
    /// Seconds until the displayed code rotates.
    pub seconds_remaining: i64,
}

/// Request for `verify_entry_password` (v1.6.0 WP3 / D7): does the stored
/// entry password hash to the supplied digest? The extension's save/update
/// prompt hashes the user's newly typed password client-side (WebCrypto) and
/// asks the desktop for a bare boolean — the stored password plaintext NEVER
/// crosses the boundary (B4 deferred-fetch posture), and the candidate
/// digest is all the request carries.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyEntryPasswordRequest {
    pub id: String,
    /// SHA-256 of the candidate password as 64 hex chars. Case-insensitive:
    /// uppercase input is normalized before the constant-time comparison
    /// (pinned by a service test). Anything that does not decode to exactly
    /// 32 bytes is rejected as invalid input.
    pub password_sha256: String,
}

/// Response for `verify_entry_password`. Deliberately minimal: a single
/// boolean — no plaintext, no secret metadata, nothing else (pinned by a
/// serialization test at the service layer).
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyEntryPasswordResponse {
    pub matches: bool,
}

/// List-view projection of one custom field: label + secret flag ONLY. The
/// value never appears outside `EntrySecretResponse` — every summary exit
/// (Tauri `list_all_entries`, NM `list_all_entries`/`get_entry_meta`) gets
/// this shape via `EntrySummary::From<PasswordEntry>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomFieldMeta {
    pub label: String,
    pub secret: bool,
}

/// One decrypted custom-field value, served only by `get_entry_secret`
/// (same one-shot disclosure channel as the entry password/notes).
#[derive(Debug, Serialize, Deserialize)]
pub struct CustomFieldValue {
    pub label: String,
    /// Plaintext value; Zeroizing wipes the heap buffer on drop.
    pub value: Zeroizing<String>,
    /// UI mask hint, mirrored from the stored field.
    pub secret: bool,
}

/// Summary of password entry (without decrypted password).
///
/// v1.4.0: `last_used_at` powers the "Recent" vault sort; `deleted_at` is
/// `Some` only in `list_deleted_entries` (trash) responses. Both are
/// device-local / tombstone metadata and are ignored by the sync domain
/// (`SyncEntry` carries neither).
///
/// v1.5.0: `url_match_mode` carries the per-entry autofill match override;
/// the serde default keeps responses from being a breaking change for any
/// consumer that predates the field.
///
/// v1.6.0: `custom_fields` carries label + secret flag ONLY (see
/// [`CustomFieldMeta`]) — the `From<PasswordEntry>` mapping is the single
/// source feeding all three summary exits; dropping the field there would
/// silently empty all of them (pinned by tests).
#[derive(Debug, Serialize, Deserialize)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    pub tags: Vec<String>,
    pub group_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
    #[serde(default)]
    pub deleted_at: Option<i64>,
    #[serde(default)]
    pub url_match_mode: UrlMatchMode,
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldMeta>,
}

impl From<PasswordEntry> for EntrySummary {
    fn from(entry: PasswordEntry) -> Self {
        Self {
            id: entry.id,
            title: entry.title,
            url: crate::validation::normalize_url(entry.url),
            username: entry.username,
            tags: entry.tags,
            group_id: entry.group_id,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
            last_used_at: entry.last_used_at,
            deleted_at: entry.deleted_at,
            url_match_mode: entry.url_match_mode,
            // Meta only — the ciphertext value MUST NOT ride along on a
            // summary (it belongs to get_entry_secret alone). `CustomField`
            // is ZeroizeOnDrop, so the label is taken (`mem::take`), never
            // partially moved (E0509).
            custom_fields: entry
                .custom_fields
                .into_iter()
                .map(|mut field| CustomFieldMeta {
                    label: std::mem::take(&mut field.label),
                    secret: field.secret,
                })
                .collect(),
        }
    }
}

/// One custom field in plaintext backup-payload form (v1.6.0 WP1 / D8).
/// The `.pvault` payload is plaintext by design (export decrypts, import
/// re-seals), so the value rides as a string here — Zeroizing keeps the
/// disclosure discipline identical to `ExportEntry.password/notes`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportCustomField {
    pub label: String,
    /// Plaintext value; the empty string mirrors the placeholder blob row.
    pub value: Zeroizing<String>,
    pub secret: bool,
}

/// Plaintext entry for export (password/notes as strings, not encrypted bytes).
///
/// v1.6.0 (D8): gained `url_match_mode` / `totp_secret` / `custom_fields`,
/// all `#[serde(default)]`. OLD backups (pre-v1.6.0) lacking the keys import
/// smoothly on the defaults. The reverse direction is a documented one-way
/// loss: a NEW backup imported by an OLD build silently drops the fields
/// (serde_json ignores unknown keys) — migrate with both ends upgraded.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportEntry {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    pub password: Zeroizing<String>,
    pub notes: Option<Zeroizing<String>>,
    pub tags: Vec<String>,
    pub group_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub url_match_mode: UrlMatchMode,
    /// Plaintext TOTP secret (base32 or a whole `otpauth://` URI), `None`
    /// when the entry has none. Restores via re-encryption on import.
    #[serde(default)]
    pub totp_secret: Option<Zeroizing<String>>,
    #[serde(default)]
    pub custom_fields: Vec<ExportCustomField>,
}

/// Plaintext backup payload (encrypted into [`VaultBackup`] by the infra layer).
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupPayload {
    pub entries: Vec<ExportEntry>,
    pub groups: Vec<Group>,
    pub settings: Settings,
}

/// Encrypted backup file format (v1 and v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBackup {
    pub version: u32,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher_name: Option<String>,
    pub salt: String, // base64
    pub kdf_memory: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub nonce: String, // base64
    pub data: String,  // base64 (AES-256-GCM encrypted payload)
}

/// Result of an import operation.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportResult {
    pub entries_imported: usize,
    pub groups_imported: usize,
}

/// Biometric unlock availability (Phase 1).
///
/// `available` — the platform credential store can prompt for biometry
/// (device support + enrolled biometry). `enabled` — the vault has a
/// biometric wrap blob, i.e. Touch ID unlock was set up for this vault.
#[derive(Debug, Serialize, Deserialize)]
pub struct BiometricStatus {
    pub available: bool,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v1.6.0 WP1 (three-exit contract): `EntrySummary::From<PasswordEntry>`
    /// maps label + secret ONLY — no ciphertext and no plaintext value may
    /// ride along on a summary. All three summary exits (Tauri list, NM
    /// list_all_entries, NM get_entry_meta) serialize this struct; the
    /// wire-JSON "no value key" shape is asserted at the adapter layer
    /// (entries service tests), where serde_json is available.
    #[test]
    fn entry_summary_maps_custom_field_meta_without_values() {
        let mut entry = PasswordEntry::new("Title".to_string(), None, "user".to_string());
        entry.custom_fields = vec![
            crate::entities::CustomField {
                label: "API Key".to_string(),
                value: vec![0xde, 0xad, 0xbe, 0xef], // ciphertext bytes
                secret: true,
            },
            crate::entities::CustomField {
                label: "Visible".to_string(),
                value: Vec::new(),
                secret: false,
            },
        ];

        let summary = EntrySummary::from(entry);
        assert_eq!(
            summary.custom_fields,
            vec![
                CustomFieldMeta {
                    label: "API Key".to_string(),
                    secret: true,
                },
                CustomFieldMeta {
                    label: "Visible".to_string(),
                    secret: false,
                },
            ]
        );
    }
}
