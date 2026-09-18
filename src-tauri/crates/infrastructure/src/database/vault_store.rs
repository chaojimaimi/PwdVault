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
    /// Opens a single write transaction, **pre-verifies the stored digest
    /// under `mac_key`** (fix plan A §2.2 — a stale-key or interleaved write
    /// is rejected with [`DatabaseError::IntegrityMismatch`] instead of
    /// silently re-baselining the digest over content it cannot account
    /// for), then calls `f` to perform business mutations (using the
    /// `_in_txn` helpers), and computes and stores the integrity digest
    /// **within the same transaction**, and commits.
    ///
    /// If `f`, the pre-verification, or the digest computation returns an
    /// error, the transaction is aborted (rolled back) — no partial state is
    /// committed.
    pub fn write<F, R>(&self, mac_key: &[u8; 32], f: F) -> Result<R, DatabaseError>
    where
        F: FnOnce(&WriteTransaction) -> Result<R, DatabaseError>,
    {
        let txn = self.db.begin_write()?;
        integrity::verify_digest_in_txn(&txn, mac_key)?;
        let result = f(&txn)?;
        integrity::refresh_digest_in_txn(&txn, mac_key)?;
        txn.commit()?;
        Ok(result)
    }

    /// Execute a key-rotating write — the D8 re-seal path (fix plan A §2.2).
    ///
    /// Identical to [`VaultStore::write`] except that the pre-existing digest
    /// is verified under `old_mac` (the key the CURRENT digest was sealed
    /// with) while the refresh after `f` uses `new_mac`. Verifying under
    /// `new_mac` would false-positive: the stored digest stays keyed by
    /// `old_mac` until this very transaction commits. Used by change
    /// password / recovery, which rotate the whole vault in one transaction.
    pub fn write_rekey<F, R>(
        &self,
        old_mac: &[u8; 32],
        new_mac: &[u8; 32],
        f: F,
    ) -> Result<R, DatabaseError>
    where
        F: FnOnce(&WriteTransaction) -> Result<R, DatabaseError>,
    {
        let txn = self.db.begin_write()?;
        integrity::verify_digest_in_txn(&txn, old_mac)?;
        let result = f(&txn)?;
        integrity::refresh_digest_in_txn(&txn, new_mac)?;
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

// ---------------------------------------------------------------------------
// Opaque blob rows (Phase 1 wrap blobs: "bio_wrap", "recovery_wrap")
// ---------------------------------------------------------------------------

/// Save an opaque blob row in VAULT_TABLE within an existing write transaction.
///
/// The blob is already ciphertext (AES-GCM, self-authenticating), so no
/// encryption happens here. Always call through [`VaultStore::write`] so the
/// integrity digest covers the change.
pub fn save_blob_in_txn(
    txn: &WriteTransaction,
    key: &str,
    blob: &[u8],
) -> Result<(), DatabaseError> {
    let mut table = txn.open_table(super::VAULT_TABLE)?;
    table.insert(key, blob)?;
    Ok(())
}

/// Load an opaque blob row from VAULT_TABLE (keyless read).
///
/// No key is required: the blob is GCM ciphertext whose authenticity is
/// checked at unwrap time, and disk-level tampering is caught by the
/// integrity digest on unlock.
pub fn load_blob(db: &Database, key: &str) -> Result<Option<Vec<u8>>, DatabaseError> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(super::VAULT_TABLE)?;
    match table.get(key)? {
        Some(value) => {
            super::check_encoded_blob_size(value.value())?;
            Ok(Some(value.value().to_vec()))
        }
        None => Ok(None),
    }
}

/// Remove an opaque blob row within an existing write transaction.
/// Returns whether the row existed. Use through [`VaultStore::write`].
pub fn remove_blob_in_txn(txn: &WriteTransaction, key: &str) -> Result<bool, DatabaseError> {
    let mut table = txn.open_table(super::VAULT_TABLE)?;
    let existed = table.remove(key)?.is_some();
    Ok(existed)
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

    /// Phase 1 (P1.2): blob rows round-trip through VaultStore::write and the
    /// digest covers them; removal keeps the digest consistent.
    #[test]
    fn test_blob_rows_roundtrip_and_remove_with_digest() {
        let temp = NamedTempFile::new().unwrap();
        let db = super::super::init_database(temp.path()).unwrap();
        let store = VaultStore::new(&db);

        assert!(load_blob(&db, "bio_wrap").unwrap().is_none());

        let blob = vec![7u8; 64];
        store
            .write(&TEST_MAC_KEY, |txn| {
                save_blob_in_txn(txn, "bio_wrap", &blob)?;
                Ok(())
            })
            .unwrap();

        assert!(integrity::verify_integrity(&db, &TEST_MAC_KEY).unwrap());
        assert_eq!(
            load_blob(&db, "bio_wrap").unwrap().as_deref(),
            Some(blob.as_slice())
        );

        store
            .write(&TEST_MAC_KEY, |txn| {
                assert!(remove_blob_in_txn(txn, "bio_wrap")?);
                Ok(())
            })
            .unwrap();

        assert!(integrity::verify_integrity(&db, &TEST_MAC_KEY).unwrap());
        assert!(load_blob(&db, "bio_wrap").unwrap().is_none());
        // Second remove reports absence.
        store
            .write(&TEST_MAC_KEY, |txn| {
                assert!(!remove_blob_in_txn(txn, "bio_wrap")?);
                Ok(())
            })
            .unwrap();
    }

    /// Blob writes that skip VaultStore::write leave the digest stale —
    /// exactly the property D8 relies on: plain transactions must not be used
    /// for blob rows.
    #[test]
    fn test_plain_txn_blob_write_breaks_digest() {
        let temp = NamedTempFile::new().unwrap();
        let db = super::super::init_database(temp.path()).unwrap();
        let store = VaultStore::new(&db);

        store
            .write(&TEST_MAC_KEY, |txn| {
                save_blob_in_txn(txn, "bio_wrap", &[1, 2, 3])?;
                Ok(())
            })
            .unwrap();
        assert!(integrity::verify_integrity(&db, &TEST_MAC_KEY).unwrap());

        // Bypass the digest refresh.
        let txn = db.begin_write().unwrap();
        save_blob_in_txn(&txn, "bio_wrap", &[9, 9, 9]).unwrap();
        txn.commit().unwrap();

        assert!(!integrity::verify_integrity(&db, &TEST_MAC_KEY).unwrap());
    }

    // -----------------------------------------------------------------------
    // Digest pre-verification (fix plan A §2.2)
    // -----------------------------------------------------------------------

    /// A write holding STALE keys must be rejected loudly instead of
    /// silently re-baselining the digest over content it cannot account
    /// for — and the failed write must leave the digest untouched.
    #[test]
    fn test_stale_mac_write_rejected_with_integrity_mismatch() {
        let temp = NamedTempFile::new().unwrap();
        let db = super::super::init_database(temp.path()).unwrap();
        let store = VaultStore::new(&db);

        let entry = PasswordEntry::new("Baseline".into(), None, "user".into());
        store
            .write(&TEST_MAC_KEY, |txn| {
                save_entry_in_txn(txn, &TEST_KEY, &entry)?;
                Ok(())
            })
            .unwrap();

        let stale_mac = [3u8; 32];
        let result: Result<(), DatabaseError> = store.write(&stale_mac, |_txn| Ok(()));
        assert!(
            matches!(result, Err(DatabaseError::IntegrityMismatch)),
            "unexpected result: {result:?}"
        );

        // The rejected write did not re-baseline the digest: the REAL key
        // still verifies and the stale key still does not.
        assert!(integrity::verify_integrity(&db, &TEST_MAC_KEY).unwrap());
        assert!(!integrity::verify_integrity(&db, &stale_mac).unwrap());
    }

    /// A freshly created database has no digest row yet — the FIRST write
    /// must establish the baseline rather than fail the pre-check.
    #[test]
    fn test_fresh_database_first_write_establishes_digest() {
        let temp = NamedTempFile::new().unwrap();
        let db = super::super::init_database(temp.path()).unwrap();
        assert!(!integrity::has_digest(&db).unwrap());

        let store = VaultStore::new(&db);
        let entry = PasswordEntry::new("First".into(), None, "user".into());
        store
            .write(&TEST_MAC_KEY, |txn| {
                save_entry_in_txn(txn, &TEST_KEY, &entry)?;
                Ok(())
            })
            .unwrap();

        assert!(integrity::has_digest(&db).unwrap());
        assert!(integrity::verify_integrity(&db, &TEST_MAC_KEY).unwrap());
    }

    /// A stored digest whose VERSION is below the current one is a
    /// pre-rebuild baseline (same semantics as `needs_digest_rebuild`):
    /// the pre-check must SKIP it — even under a mismatching mac key —
    /// instead of false-positiving legacy/migration flows, and the write
    /// re-establishes a current-version digest.
    #[test]
    fn test_pre_v4_digest_row_skips_precheck() {
        let temp = NamedTempFile::new().unwrap();
        let db = super::super::init_database(temp.path()).unwrap();

        // Forge a v3-era digest row: wrong bytes + an old version marker.
        {
            let txn = db.begin_write().unwrap();
            {
                let mut meta = txn.open_table(integrity::META_TABLE).unwrap();
                meta.insert(integrity::DB_DIGEST_KEY, &[0xFFu8; 32].as_slice())
                    .unwrap();
                meta.insert(
                    integrity::DB_DIGEST_VERSION_KEY,
                    3u32.to_le_bytes().as_slice(),
                )
                .unwrap();
            }
            txn.commit().unwrap();
        }
        assert!(integrity::needs_digest_rebuild(&db).unwrap());

        // Even a mac key that cannot match the forged digest passes, and
        // the write replaces the row with a current-version baseline.
        let legacy_mac = [9u8; 32];
        let store = VaultStore::new(&db);
        let entry = PasswordEntry::new("Migrated".into(), None, "user".into());
        store
            .write(&legacy_mac, |txn| {
                save_entry_in_txn(txn, &TEST_KEY, &entry)?;
                Ok(())
            })
            .unwrap();
        assert!(!integrity::needs_digest_rebuild(&db).unwrap());
        assert!(integrity::verify_integrity(&db, &legacy_mac).unwrap());
    }
}
