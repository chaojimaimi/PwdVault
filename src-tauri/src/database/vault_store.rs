//! Unified vault write transaction interface (§5.1.2).
//!
//! Provides a single `write` method that executes business mutations and
//! the integrity digest update within the **same** redb write transaction.
//! This eliminates the crash window where the business write has committed
//! but the digest hasn't been refreshed yet.

use redb::{Database, WriteTransaction};

use super::integrity;
use super::{DatabaseError, Group, PasswordEntry, ENTRIES_TABLE, GROUPS_TABLE, SETTINGS_TABLE};

/// Wrapper around a redb `Database` that provides atomic write+digest operations.
pub struct VaultStore<'a> {
    db: &'a Database,
}

impl<'a> VaultStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Execute a write operation with automatic digest refresh.
    ///
    /// Opens a single write transaction, calls `f` to perform business
    /// mutations (using the `_in_txn` helpers), then computes and stores
    /// the integrity digest **within the same transaction**, and commits.
    ///
    /// If `f` or the digest computation returns an error, the transaction
    /// is aborted (rolled back) — no partial state is committed.
    pub fn write<F, R>(&self, mac_key: &[u8; 32], f: F) -> Result<R, DatabaseError>
    where
        F: FnOnce(&WriteTransaction) -> Result<R, DatabaseError>,
    {
        let txn = self.db.begin_write()?;
        let result = f(&txn)?;
        integrity::refresh_digest_in_txn(&txn, mac_key)?;
        txn.commit()?;
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Transaction-scoped CRUD helpers (do NOT commit — caller's transaction owns commit)
// ---------------------------------------------------------------------------

/// Save an entry within an existing write transaction.
pub fn save_entry_in_txn(
    txn: &WriteTransaction,
    key: &[u8; 32],
    entry: &PasswordEntry,
) -> Result<(), DatabaseError> {
    let encoded = super::entry_codec::seal_entry(entry, key)?;
    let mut table = txn.open_table(ENTRIES_TABLE)?;
    table.insert(entry.id.as_str(), encoded.as_slice())?;
    Ok(())
}

/// Delete an entry within an existing write transaction.
pub fn delete_entry_in_txn(txn: &WriteTransaction, id: &str) -> Result<bool, DatabaseError> {
    let mut table = txn.open_table(ENTRIES_TABLE)?;
    let existed = table.remove(id)?.is_some();
    Ok(existed)
}

/// Save a group within an existing write transaction.
pub fn save_group_in_txn(
    txn: &WriteTransaction,
    key: &[u8; 32],
    group: &Group,
) -> Result<(), DatabaseError> {
    let encoded = super::group_codec::seal_group(group, key)?;
    let mut table = txn.open_table(GROUPS_TABLE)?;
    table.insert(group.id.as_str(), encoded.as_slice())?;
    Ok(())
}

/// Delete a group within an existing write transaction.
pub fn delete_group_in_txn(txn: &WriteTransaction, id: &str) -> Result<bool, DatabaseError> {
    let mut table = txn.open_table(GROUPS_TABLE)?;
    let existed = table.remove(id)?.is_some();
    Ok(existed)
}

/// Save settings within an existing write transaction.
pub fn save_settings_in_txn(
    txn: &WriteTransaction,
    settings: &super::Settings,
) -> Result<(), DatabaseError> {
    let encoded = serde_json::to_vec(settings)
        .map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
    let mut table = txn.open_table(SETTINGS_TABLE)?;
    table.insert("current", encoded.as_slice())?;
    Ok(())
}

/// Save verification data within an existing write transaction.
pub fn save_verification_data_in_txn(
    txn: &WriteTransaction,
    data: &super::super::crypto::VerificationData,
) -> Result<(), DatabaseError> {
    let encoded =
        bincode::serialize(data).map_err(|e| DatabaseError::SerializationError(e.to_string()))?;
    let mut table = txn.open_table(super::VAULT_TABLE)?;
    table.insert("verification", encoded.as_slice())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    const TEST_KEY: [u8; 32] = [1u8; 32];
    const TEST_MAC_KEY: [u8; 32] = [2u8; 32];

    #[test]
    fn test_write_txn_business_and_digest_atomic() {
        let temp = NamedTempFile::new().unwrap();
        let db = super::super::init_database(temp.path()).unwrap();

        // Write an entry + digest in one transaction
        let store = VaultStore::new(&db);
        let entry = PasswordEntry::new("Test".into(), None, "user".into());
        let entry_id = entry.id.clone();

        store
            .write(&TEST_MAC_KEY, |txn| {
                save_entry_in_txn(txn, &TEST_KEY, &entry)?;
                Ok(())
            })
            .unwrap();

        // Verify digest was written and matches
        assert!(integrity::has_digest(&db).unwrap());
        assert!(integrity::verify_integrity(&db, &TEST_MAC_KEY).unwrap());

        // Verify entry exists
        assert_eq!(super::super::count_entries(&db).unwrap(), 1);

        // Delete entry + refresh digest in one transaction
        store
            .write(&TEST_MAC_KEY, |txn| {
                delete_entry_in_txn(txn, &entry_id)?;
                Ok(())
            })
            .unwrap();

        // Digest should still be valid after delete
        assert!(integrity::verify_integrity(&db, &TEST_MAC_KEY).unwrap());
        assert_eq!(super::super::count_entries(&db).unwrap(), 0);
    }

    #[test]
    fn test_write_txn_rollback_on_error() {
        let temp = NamedTempFile::new().unwrap();
        let db = super::super::init_database(temp.path()).unwrap();

        let store = VaultStore::new(&db);
        let entry = PasswordEntry::new("Test".into(), None, "user".into());

        // Write an entry successfully
        store
            .write(&TEST_MAC_KEY, |txn| {
                save_entry_in_txn(txn, &TEST_KEY, &entry)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(super::super::count_entries(&db).unwrap(), 1);

        // Attempt a write that fails — the closure returns an error
        let result: Result<(), DatabaseError> = store.write(&TEST_MAC_KEY, |_txn| {
            Err(DatabaseError::SerializationError(
                "simulated failure".into(),
            ))
        });
        assert!(result.is_err());

        // The entry should still be there (rollback)
        assert_eq!(super::super::count_entries(&db).unwrap(), 1);
    }
}
