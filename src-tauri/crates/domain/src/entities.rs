//! Domain entities — pure data models owned by the domain layer.
//!
//! These types describe the business data shape. The `infrastructure` layer
//! (redb repository, codecs) imports them; persistence concerns live there,
//! not here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Per-entry URL matching override for the browser extension's autofill
/// gates (v1.5.0 WP4).
///
/// - `Auto` — the v1.4.0 behavior: registrable-domain (eTLD+1) comparison
///   with the curated suffix table + fail-closed ccTLD fallback. The default.
/// - `Exact` — full hostname equality (post-`new URL()` normalization:
///   lowercase + IDN→punycode, port excluded).
/// - `Domain` — registrable-domain comparison pinned by contract (today
///   identical to Auto; Auto may evolve, Domain never does).
///
/// `Auto` is the serde default so JSON payloads written before the field
/// existed (sync container v1 snapshots, NM requests, old frontends) land on
/// the status-quo behavior. Bincode is positional and ignores serde defaults
/// — entry blobs must go through the codec's three-generation read chain
/// (see `entry_codec::decode_entry_plain`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UrlMatchMode {
    #[default]
    Auto,
    Exact,
    Domain,
}

/// Manual `Zeroize` (NOT the derive — `ZeroizeOnDrop` installs a `Drop`
/// glue type, which is incompatible with `Copy`): zeroizing a match mode
/// resets it to `Auto`, satisfying the `SyncEntry` plaintext-domain derive
/// without giving up value semantics.
impl Zeroize for UrlMatchMode {
    fn zeroize(&mut self) {
        *self = Self::default();
    }
}

/// A password entry stored in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    /// Unique identifier
    pub id: String,
    /// Website or service name
    pub title: String,
    /// URL of the service
    pub url: Option<String>,
    /// Username or email
    pub username: String,
    /// Encrypted password blob (ciphertext produced by the infra crypto layer)
    pub encrypted_password: Vec<u8>,
    /// Encrypted notes blob, if any
    pub encrypted_notes: Option<Vec<u8>>,
    /// Tags for organization
    pub tags: Vec<String>,
    /// Creation timestamp (epoch seconds)
    pub created_at: i64,
    /// Last modified timestamp (epoch seconds)
    pub updated_at: i64,
    /// Last used timestamp (epoch seconds)
    pub last_used_at: Option<i64>,
    /// Optional group id this entry belongs to
    #[serde(default)]
    pub group_id: Option<String>,
    /// Soft-delete tombstone (epoch seconds). `None` = live entry. The serde
    /// default is inert for bincode (positional, see the codec generation
    /// chain) but keeps old backup JSON importable.
    #[serde(default)]
    pub deleted_at: Option<i64>,
    /// Encrypted TOTP secret blob (ciphertext produced by the infra crypto
    /// layer). Same serde-default rationale as `deleted_at`.
    #[serde(default)]
    pub encrypted_totp_secret: Option<Vec<u8>>,
    /// Per-entry URL match override for browser-extension autofill (v1.5.0
    /// WP4). The serde default keeps JSON payloads written before the field
    /// existed on `Auto`; bincode layouts are bridged by the entry codec's
    /// three-generation read chain.
    #[serde(default)]
    pub url_match_mode: UrlMatchMode,
}

impl PasswordEntry {
    /// Create a new password entry with a fresh id and empty secret fields.
    pub fn new(title: String, url: Option<String>, username: String) -> Self {
        let now = Utc::now().timestamp();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title,
            url,
            username,
            encrypted_password: Vec::new(),
            encrypted_notes: None,
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
            last_used_at: None,
            group_id: None,
            deleted_at: None,
            encrypted_totp_secret: None,
            url_match_mode: UrlMatchMode::default(),
        }
    }
}

/// A logical group (folder) for entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// Soft-delete tombstone (epoch seconds). `None` = live group. The serde
    /// default is inert for bincode (positional, see the codec generation
    /// chain) but keeps old backup JSON importable.
    #[serde(default)]
    pub deleted_at: Option<i64>,
}

impl Group {
    pub fn new(name: String) -> Self {
        let now = Utc::now().timestamp();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }
}

/// Per-vault settings (single row, key "current").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub auto_lock_secs: u64,
    pub default_length: usize,
    pub default_include_uppercase: bool,
    pub default_include_lowercase: bool,
    pub default_include_numbers: bool,
    pub default_include_symbols: bool,
    #[serde(default = "default_true")]
    pub check_updates: bool,
    /// Vault-list sort mode ("recent" | "updated" | "alpha"), persisted so
    /// the chosen ordering survives restarts (v1.4.0). Unknown values fall
    /// back to "recent" at the consumption site.
    #[serde(default = "default_sort_mode")]
    pub sort_mode: String,
    /// Global shortcut toggle + accelerator (v1.4.0). Registration happens
    /// in the tauri-app layer (register_global_shortcut command); these
    /// fields only persist the user's choice.
    #[serde(default = "default_true")]
    pub global_shortcut_enabled: bool,
    #[serde(default = "default_global_shortcut")]
    pub global_shortcut: String,
    /// Trash auto-purge (v1.5.0 WP3): tombstones older than this many days
    /// are physically deleted by the post-unlock sweep (one ≤500-row batch
    /// per unlock). 0 = disabled — permanent deletion is strict opt-in, the
    /// UI offers 0/7/30/90.
    #[serde(default)]
    pub trash_auto_purge_days: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_secs: 600,
            default_length: 16,
            default_include_uppercase: true,
            default_include_lowercase: true,
            default_include_numbers: true,
            default_include_symbols: true,
            check_updates: true,
            sort_mode: default_sort_mode(),
            global_shortcut_enabled: true,
            global_shortcut: default_global_shortcut(),
            trash_auto_purge_days: 0,
        }
    }
}

fn default_sort_mode() -> String {
    "recent".to_string()
}

/// Default global accelerator: CmdOrCtrl+Shift+Space (maps to Cmd on macOS,
/// Ctrl on Windows/Linux).
fn default_global_shortcut() -> String {
    "CmdOrCtrl+Shift+Space".to_string()
}

fn default_true() -> bool {
    true
}

/// Marker re-export so `DateTime<Utc>` stays a single import path for callers
/// that previously got it transitively.
pub type Timestamp = DateTime<Utc>;
