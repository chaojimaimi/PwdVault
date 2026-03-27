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

const VAULT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("vault");
const ENTRIES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("entries");

// ============================================================================
// Error Types
// ============================================================================

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] redb::DatabaseError),

    #[error("Storage error: {0}")]
    StorageError(#[from] redb::StorageError),

    #[error("Table error: {0}")]
    TableError(#[from] redb::TableError),

    #[error("Transaction error: {0}")]
    TransactionError(#[from] redb::TransactionError),

    #[error("Commit error: {0}")]
    CommitError(#[from] CommitError),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Entry not found")]
    EntryNotFound,

    #[error("Vault not initialized")]
    VaultNotInitialized,
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
        }
    }
}

// ============================================================================
// Database Operations
// ============================================================================

/// Initialize the database at the given path
pub fn init_database<P: AsRef<Path>>(path: P) -> Result<Database, DatabaseError> {
    let db = Database::create(path)?;

    // Create tables if they don't exist
    let write_txn = db.begin_write()?;
    write_txn.open_table(VAULT_TABLE)?;
    write_txn.open_table(ENTRIES_TABLE)?;
    write_txn.commit()?;

    Ok(db)
}

/// Save verification data to the database
pub fn save_verification_data(
    db: &Database,
    data: &VerificationData,
) -> Result<(), DatabaseError> {
    let encoded = bincode::serialize(data)
        .map_err(|e| DatabaseError::SerializationError(e.to_string()))?;

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

/// Save a password entry to the database
pub fn save_entry(db: &Database, entry: &PasswordEntry) -> Result<(), DatabaseError> {
    let encoded = bincode::serialize(entry)
        .map_err(|e| DatabaseError::SerializationError(e.to_string()))?;

    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(ENTRIES_TABLE)?;
        table.insert(entry.id.as_str(), encoded.as_slice())?;
    }
    write_txn.commit()?;

    Ok(())
}

/// Load a password entry from the database
pub fn load_entry(db: &Database, id: &str) -> Result<Option<PasswordEntry>, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(ENTRIES_TABLE)?;

    match table.get(id)? {
        Some(value) => {
            let entry: PasswordEntry = bincode::deserialize(value.value())
                .map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
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

/// Count password entries
pub fn count_entries(db: &Database) -> Result<usize, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(ENTRIES_TABLE)?;
    Ok(table.len()? as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

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

        save_entry(&db, &entry).unwrap();
        let loaded = load_entry(&db, &entry.id).unwrap();

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(entry.id, loaded.id);
        assert_eq!(entry.title, loaded.title);
        assert_eq!(entry.username, loaded.username);
    }

    #[test]
    fn test_delete_entry() {
        let (db, _temp) = get_test_db();

        let entry = PasswordEntry::new(
            "Test".to_string(),
            None,
            "user".to_string(),
        );

        save_entry(&db, &entry).unwrap();
        assert!(load_entry(&db, &entry.id).unwrap().is_some());

        let deleted = delete_entry(&db, &entry.id).unwrap();
        assert!(deleted);
        assert!(load_entry(&db, &entry.id).unwrap().is_none());
    }

    #[test]
    fn test_list_entries() {
        let (db, _temp) = get_test_db();

        let entry1 = PasswordEntry::new("Site 1".to_string(), None, "user1".to_string());
        let entry2 = PasswordEntry::new("Site 2".to_string(), None, "user2".to_string());

        save_entry(&db, &entry1).unwrap();
        save_entry(&db, &entry2).unwrap();

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
        save_entry(&db, &entry).unwrap();

        assert_eq!(count_entries(&db).unwrap(), 1);
    }
}