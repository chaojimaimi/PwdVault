//! Persistent storage using redb
//!
//! Provides ACID-compliant storage for password entries and verification data.

use redb::{CommitError, Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

use super::VerificationData;

// ============================================================================
// Constants
// ============================================================================

pub(crate) const VAULT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("vault");
pub(crate) const ENTRIES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("entries");
pub(crate) const GROUPS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("groups");
pub(crate) const SETTINGS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("settings");

pub mod entry_codec;
pub mod group_codec;
pub mod integrity;
pub mod migrations;
pub mod vault_store;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Database error: {0}")]
    DatabaseError(Box<redb::DatabaseError>),

    #[error("Storage error: {0}")]
    StorageError(Box<redb::StorageError>),

    #[error("Table error: {0}")]
    TableError(Box<redb::TableError>),

    #[error("Transaction error: {0}")]
    TransactionError(Box<redb::TransactionError>),

    #[error("Commit error: {0}")]
    CommitError(Box<CommitError>),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Entry not found")]
    EntryNotFound,

    #[error("Vault not initialized")]
    VaultNotInitialized,

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

impl From<redb::DatabaseError> for DatabaseError {
    fn from(error: redb::DatabaseError) -> Self {
        Self::DatabaseError(Box::new(error))
    }
}

impl From<redb::StorageError> for DatabaseError {
    fn from(error: redb::StorageError) -> Self {
        Self::StorageError(Box::new(error))
    }
}

impl From<redb::TableError> for DatabaseError {
    fn from(error: redb::TableError) -> Self {
        Self::TableError(Box::new(error))
    }
}

impl From<redb::TransactionError> for DatabaseError {
    fn from(error: redb::TransactionError) -> Self {
        Self::TransactionError(Box::new(error))
    }
}

impl From<CommitError> for DatabaseError {
    fn from(error: CommitError) -> Self {
        Self::CommitError(Box::new(error))
    }
}

// ============================================================================
// Data Types
// ============================================================================

/// A password entry stored in the vault
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
    /// Encrypted password
    pub encrypted_password: Vec<u8>,
    /// Encrypted notes
    pub encrypted_notes: Option<Vec<u8>>,
    /// Tags for organization
    pub tags: Vec<String>,
    /// Creation timestamp
    pub created_at: i64,
    /// Last modified timestamp
    pub updated_at: i64,
    /// Last used timestamp
    pub last_used_at: Option<i64>,
    /// Optional group id this entry belongs to
    #[serde(default)]
    pub group_id: Option<String>,
}

impl PasswordEntry {
    /// Create a new password entry
    pub fn new(title: String, url: Option<String>, username: String) -> Self {
        let now = chrono::Utc::now().timestamp();
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

/// A logical group (folder) for entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Group {
    pub fn new(name: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Per-vault settings (single row, key "current")
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

/// Settings layout written by PwdVault versions before `check_updates` was
/// added. Bincode encodes structs positionally, so serde's field default does
/// not make a six-field record readable as the current seven-field struct.
#[derive(Debug, Deserialize)]
struct LegacySettingsV1 {
    auto_lock_secs: u64,
    default_length: usize,
    default_include_uppercase: bool,
    default_include_lowercase: bool,
    default_include_numbers: bool,
    default_include_symbols: bool,
}

impl From<LegacySettingsV1> for Settings {
    fn from(legacy: LegacySettingsV1) -> Self {
        Self {
            auto_lock_secs: legacy.auto_lock_secs,
            default_length: legacy.default_length,
            default_include_uppercase: legacy.default_include_uppercase,
            default_include_lowercase: legacy.default_include_lowercase,
            default_include_numbers: legacy.default_include_numbers,
            default_include_symbols: legacy.default_include_symbols,
            check_updates: true,
        }
    }
}

fn default_true() -> bool {
    true
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
        }
    }
}

// ============================================================================
// Database Operations
// ============================================================================

/// Initialize the database at the given path
pub fn init_database<P: AsRef<Path>>(path: P) -> Result<Database, DatabaseError> {
    crate::paths::prepare_sensitive_file(path.as_ref())?;
    let db = Database::create(path.as_ref())?;
    crate::paths::secure_file(path.as_ref())?;

    // Create tables if they don't exist
    let write_txn = db.begin_write()?;
    write_txn.open_table(VAULT_TABLE)?;
    write_txn.open_table(ENTRIES_TABLE)?;
    write_txn.open_table(GROUPS_TABLE)?;
    write_txn.open_table(SETTINGS_TABLE)?;
    write_txn.open_table(integrity::META_TABLE)?;
    write_txn.commit()?;

    Ok(db)
}

/// Save verification data to the database
pub fn save_verification_data(db: &Database, data: &VerificationData) -> Result<(), DatabaseError> {
    let encoded =
        bincode::serialize(data).map_err(|e| DatabaseError::SerializationError(e.to_string()))?;

    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(VAULT_TABLE)?;
        table.insert("verification", encoded.as_slice())?;
    }
    write_txn.commit()?;

    Ok(())
}

/// Load verification data from the database
pub fn load_verification_data(db: &Database) -> Result<Option<VerificationData>, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(VAULT_TABLE)?;

    match table.get("verification")? {
        Some(value) => {
            let data: VerificationData = bincode::deserialize(value.value())
                .map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
            Ok(Some(data))
        }
        None => Ok(None),
    }
}

/// Save a password entry to the database (entry is encrypted as a whole blob)
pub fn save_entry(
    db: &Database,
    key: &[u8; 32],
    entry: &PasswordEntry,
) -> Result<(), DatabaseError> {
    let encoded = entry_codec::seal_entry(entry, key)?;

    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(ENTRIES_TABLE)?;
        table.insert(entry.id.as_str(), encoded.as_slice())?;
    }
    write_txn.commit()?;

    Ok(())
}

/// Load a password entry from the database (decrypts the stored blob)
pub fn load_entry(
    db: &Database,
    key: &[u8; 32],
    id: &str,
) -> Result<Option<PasswordEntry>, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(ENTRIES_TABLE)?;

    match table.get(id)? {
        Some(value) => {
            let entry = entry_codec::open_entry(value.value(), key, id)?;
            Ok(Some(entry))
        }
        None => Ok(None),
    }
}

/// Delete a password entry from the database
pub fn delete_entry(db: &Database, id: &str) -> Result<bool, DatabaseError> {
    let write_txn = db.begin_write()?;
    let existed = {
        let mut table = write_txn.open_table(ENTRIES_TABLE)?;
        let result = table.remove(id)?;
        result.is_some()
    };
    write_txn.commit()?;
    Ok(existed)
}

/// List all password entry IDs
pub fn list_entries(db: &Database) -> Result<Vec<String>, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(ENTRIES_TABLE)?;

    let mut ids = Vec::new();
    for result in table.iter()? {
        let (key, _) = result?;
        ids.push(key.value().to_string());
    }

    Ok(ids)
}

/// Load and decrypt every entry in a single read transaction (§5.6.2).
///
/// This replaces the previous list-IDs-then-load-each pattern that opened
/// 1+N read transactions. The bulk scan iterates the table once, decrypting
/// each record as it goes. `filter_group` optionally restricts to a group.
pub fn list_all_entries_bulk(
    db: &Database,
    key: &[u8; 32],
    filter_group: Option<&str>,
) -> Result<Vec<PasswordEntry>, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(ENTRIES_TABLE)?;

    let mut entries = Vec::new();
    for result in table.iter()? {
        let (key_handle, value) = result?;
        let id = key_handle.value();
        let entry = entry_codec::open_entry(value.value(), key, id)?;
        if let Some(group) = filter_group {
            if entry.group_id.as_deref() != Some(group) {
                continue;
            }
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Count password entries
pub fn count_entries(db: &Database) -> Result<usize, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(ENTRIES_TABLE)?;
    Ok(table.len()? as usize)
}

/// Save a group to the database (group is encrypted as a whole blob)
pub fn save_group(db: &Database, key: &[u8; 32], group: &Group) -> Result<(), DatabaseError> {
    let encoded = group_codec::seal_group(group, key)?;

    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(GROUPS_TABLE)?;
        table.insert(group.id.as_str(), encoded.as_slice())?;
    }
    write_txn.commit()?;

    Ok(())
}

/// Load a group from the database (decrypts the stored blob)
pub fn load_group(db: &Database, key: &[u8; 32], id: &str) -> Result<Option<Group>, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(GROUPS_TABLE)?;

    match table.get(id)? {
        Some(value) => {
            let g = group_codec::open_group(value.value(), key, id)?;
            Ok(Some(g))
        }
        None => Ok(None),
    }
}

/// Delete a group
pub fn delete_group(db: &Database, id: &str) -> Result<bool, DatabaseError> {
    let write_txn = db.begin_write()?;
    let existed = {
        let mut table = write_txn.open_table(GROUPS_TABLE)?;
        let result = table.remove(id)?;
        result.is_some()
    };
    write_txn.commit()?;
    Ok(existed)
}

/// List all groups' IDs
pub fn list_groups(db: &Database) -> Result<Vec<String>, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(GROUPS_TABLE)?;

    let mut ids = Vec::new();
    for result in table.iter()? {
        let (key, _) = result?;
        ids.push(key.value().to_string());
    }

    Ok(ids)
}

/// Load and decrypt every group in a single read transaction (§5.6.2).
///
/// Replaces the list-IDs-then-load-each pattern (1+N read transactions).
pub fn list_all_groups_bulk(db: &Database, key: &[u8; 32]) -> Result<Vec<Group>, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(GROUPS_TABLE)?;

    let mut groups = Vec::new();
    for result in table.iter()? {
        let (key_handle, value) = result?;
        let id = key_handle.value();
        let group = group_codec::open_group(value.value(), key, id)?;
        groups.push(group);
    }
    Ok(groups)
}

/// Count groups
pub fn count_groups(db: &Database) -> Result<usize, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(GROUPS_TABLE)?;
    Ok(table.len()? as usize)
}

/// Save settings (single row with key "current")
pub fn save_settings(db: &Database, settings: &Settings) -> Result<(), DatabaseError> {
    let encoded = serde_json::to_vec(settings)
        .map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(SETTINGS_TABLE)?;
        table.insert("current", encoded.as_slice())?;
    }
    write_txn.commit()?;
    Ok(())
}

/// Load settings, falling back to defaults if not found
pub fn load_settings(db: &Database) -> Result<Settings, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(SETTINGS_TABLE)?;
    match table.get("current")? {
        Some(value) => {
            let data = value.value();
            // Try JSON first (current format), then both bincode layouts used
            // by released versions. Keep malformed data fail-closed.
            if let Ok(settings) = serde_json::from_slice::<Settings>(data) {
                Ok(settings)
            } else if let Ok(settings) = bincode::deserialize::<Settings>(data) {
                Ok(settings)
            } else if let Ok(settings) = bincode::deserialize::<LegacySettingsV1>(data) {
                Ok(settings.into())
            } else {
                Err(DatabaseError::DeserializationError(
                    "settings record is corrupt".to_string(),
                ))
            }
        }
        None => Ok(Settings::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    const TEST_KEY: [u8; 32] = [1u8; 32];

    fn get_test_db() -> (Database, NamedTempFile) {
        let temp = NamedTempFile::new().unwrap();
        let db = init_database(temp.path()).unwrap();
        (db, temp)
    }

    #[test]
    fn test_init_database() {
        let temp = NamedTempFile::new().unwrap();
        let result = init_database(temp.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_save_and_load_entry() {
        let (db, _temp) = get_test_db();

        let mut entry = PasswordEntry::new(
            "Test Site".to_string(),
            Some("https://example.com".to_string()),
            "user@example.com".to_string(),
        );
        entry.encrypted_password = vec![1, 2, 3, 4];

        save_entry(&db, &TEST_KEY, &entry).unwrap();
        let loaded = load_entry(&db, &TEST_KEY, &entry.id).unwrap();

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(entry.id, loaded.id);
        assert_eq!(entry.title, loaded.title);
        assert_eq!(entry.username, loaded.username);
    }

    #[test]
    fn test_delete_entry() {
        let (db, _temp) = get_test_db();

        let entry = PasswordEntry::new("Test".to_string(), None, "user".to_string());

        save_entry(&db, &TEST_KEY, &entry).unwrap();
        assert!(load_entry(&db, &TEST_KEY, &entry.id).unwrap().is_some());

        let deleted = delete_entry(&db, &entry.id).unwrap();
        assert!(deleted);
        assert!(load_entry(&db, &TEST_KEY, &entry.id).unwrap().is_none());
    }

    #[test]
    fn corrupt_settings_do_not_fall_back_to_defaults() {
        let (db, _temp) = get_test_db();
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SETTINGS_TABLE).unwrap();
            table.insert("current", &[0xFF, 0x00][..]).unwrap();
        }
        txn.commit().unwrap();
        assert!(load_settings(&db).is_err());
    }

    #[test]
    fn legacy_bincode_settings_without_check_updates_are_supported() {
        let (db, _temp) = get_test_db();
        let legacy = LegacySettingsV1 {
            auto_lock_secs: 300,
            default_length: 24,
            default_include_uppercase: true,
            default_include_lowercase: true,
            default_include_numbers: false,
            default_include_symbols: true,
        };
        let encoded = bincode::serialize(&(
            legacy.auto_lock_secs,
            legacy.default_length,
            legacy.default_include_uppercase,
            legacy.default_include_lowercase,
            legacy.default_include_numbers,
            legacy.default_include_symbols,
        ))
        .unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(SETTINGS_TABLE).unwrap();
            table.insert("current", encoded.as_slice()).unwrap();
        }
        txn.commit().unwrap();

        let loaded = load_settings(&db).unwrap();
        assert_eq!(loaded.auto_lock_secs, 300);
        assert_eq!(loaded.default_length, 24);
        assert!(!loaded.default_include_numbers);
        assert!(loaded.check_updates);
    }

    #[test]
    fn test_list_entries() {
        let (db, _temp) = get_test_db();

        let entry1 = PasswordEntry::new("Site 1".to_string(), None, "user1".to_string());
        let entry2 = PasswordEntry::new("Site 2".to_string(), None, "user2".to_string());

        save_entry(&db, &TEST_KEY, &entry1).unwrap();
        save_entry(&db, &TEST_KEY, &entry2).unwrap();

        let ids = list_entries(&db).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&entry1.id));
        assert!(ids.contains(&entry2.id));
    }

    #[test]
    fn test_count_entries() {
        let (db, _temp) = get_test_db();

        assert_eq!(count_entries(&db).unwrap(), 0);

        let entry = PasswordEntry::new("Test".to_string(), None, "user".to_string());
        save_entry(&db, &TEST_KEY, &entry).unwrap();

        assert_eq!(count_entries(&db).unwrap(), 1);
    }

    #[test]
    fn test_save_and_load_group() {
        let (db, _temp) = get_test_db();

        let group = Group::new("Personal".to_string());
        save_group(&db, &TEST_KEY, &group).unwrap();

        let loaded = load_group(&db, &TEST_KEY, &group.id).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(group.id, loaded.id);
        assert_eq!(group.name, loaded.name);
    }

    #[test]
    fn test_delete_group() {
        let (db, _temp) = get_test_db();

        let group = Group::new("Work".to_string());
        save_group(&db, &TEST_KEY, &group).unwrap();
        assert!(load_group(&db, &TEST_KEY, &group.id).unwrap().is_some());

        let deleted = delete_group(&db, &group.id).unwrap();
        assert!(deleted);
        assert!(load_group(&db, &TEST_KEY, &group.id).unwrap().is_none());
    }

    #[test]
    fn test_list_groups() {
        let (db, _temp) = get_test_db();

        let g1 = Group::new("A".to_string());
        let g2 = Group::new("B".to_string());

        save_group(&db, &TEST_KEY, &g1).unwrap();
        save_group(&db, &TEST_KEY, &g2).unwrap();

        let ids = list_groups(&db).unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&g1.id));
        assert!(ids.contains(&g2.id));
    }

    #[test]
    fn test_count_groups() {
        let (db, _temp) = get_test_db();

        assert_eq!(count_groups(&db).unwrap(), 0);

        let g = Group::new("X".to_string());
        save_group(&db, &TEST_KEY, &g).unwrap();

        assert_eq!(count_groups(&db).unwrap(), 1);
    }
}
