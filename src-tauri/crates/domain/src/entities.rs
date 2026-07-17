//! Domain entities — pure data models owned by the domain layer.
//!
//! These types describe the business data shape. The `infrastructure` layer
//! (redb repository, codecs) imports them; persistence concerns live there,
//! not here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
}

impl Group {
    pub fn new(name: String) -> Self {
        let now = Utc::now().timestamp();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            created_at: now,
            updated_at: now,
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
}

fn default_true() -> bool {
    true
}

/// Marker re-export so `DateTime<Utc>` stays a single import path for callers
/// that previously got it transitively.
pub type Timestamp = DateTime<Utc>;
