//! Request/response DTOs and backup file format models.
//!
//! These are wire-format types shared between the Tauri IPC and Native
//! Messaging adapters. They carry plaintext secrets wrapped in `Zeroizing`
//! so the heap buffer is wiped on drop.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entities::{Group, PasswordEntry, Settings, UrlMatchMode};

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
}

/// Current TOTP code for an entry (`totp_code`, Tauri-only command).
#[derive(Debug, Serialize, Deserialize)]
pub struct TotpCodeResponse {
    pub code: String,
    /// Seconds until the displayed code rotates.
    pub seconds_remaining: i64,
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
        }
    }
}

/// Plaintext entry for export (password/notes as strings, not encrypted bytes).
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
