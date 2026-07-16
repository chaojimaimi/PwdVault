//! Test infrastructure for Phase 0 regression baseline.
//!
//! This module provides reusable test utilities for:
//! - **Fault injection**: simulate crashes at arbitrary points during DB
//!   mutations to verify crash-consistency properties.
//! - **Concurrency barriers**: coordinate multiple threads to exercise
//!   race conditions in the vault session / auto-lock / HTTP layers.
//! - **File permission verification**: assert that sensitive files are
//!   created with restrictive permissions on Unix.
//!
//! These are the building blocks for Phase 1+ tests; Phase 0 itself
//! establishes only the harness and passes basic sanity tests.

#![cfg(test)]

use redb::Database;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use crate::database;

// ---------------------------------------------------------------------------
// Fault Injection
// ---------------------------------------------------------------------------

/// Fault injection harness for redb operations.
///
/// The idea: perform a sequence of database mutations, but instead of
/// committing the final transaction, **abort** (simulating a crash) and
/// reopen the database file to verify the state is consistent.
///
/// redb provides ACID guarantees: after reopening, the database reflects
/// either the last committed state or nothing — never a partial write.
/// These tests verify that property holds for our usage patterns.
pub struct FaultInjector {
    pub db_path: PathBuf,
    pub dir: tempfile::TempDir,
}

impl FaultInjector {
    /// Create a new fault injection environment with a freshly initialized DB.
    pub fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("create temp dir");
        let db_path = dir.path().join("fault_test.db");
        // Initialize the database so the file exists with all tables.
        {
            let db = database::init_database(&db_path).expect("init db");
            drop(db);
        }
        Self { db_path, dir }
    }

    /// Open the database.
    pub fn open_db(&self) -> Database {
        Database::open(&self.db_path).expect("open db")
    }

    /// Reopen the database and verify it contains exactly `expected_entries`
    /// records in the entries table.
    pub fn verify_entry_count(&self, expected: usize) {
        let db = self.open_db();
        let count = database::count_entries(&db).expect("count entries");
        assert_eq!(
            count, expected,
            "after reopen, entry count should be {} but got {}",
            expected, count
        );
    }

    /// Write `entries` entries, commit, then simulate crash by dropping
    /// the handle without doing anything special. redb's crash recovery
    /// should preserve all committed data on reopen.
    pub fn write_and_crash_after_commit(&self, entries: usize) {
        let db = self.open_db();
        let key = [0x42u8; 32];
        for i in 0..entries {
            let mut entry = database::PasswordEntry::new(
                format!("Crash Test {}", i),
                None,
                format!("crash_user_{}", i),
            );
            entry.encrypted_password = vec![0xAA; 28];
            database::save_entry(&db, &key, &entry).expect("save entry");
        }
        // Drop the handle — simulates process exit.
        drop(db);
    }

    /// Write `entries` entries but DON'T commit the final transaction,
    /// simulating a crash mid-write. After reopen, all committed data
    /// should be present but the uncommitted writes must not.
    pub fn write_and_crash_mid_transaction(
        &self,
        committed_entries: usize,
        uncommitted_entries: usize,
    ) {
        let db = self.open_db();
        let key = [0x42u8; 32];

        // Write committed entries normally
        for i in 0..committed_entries {
            let mut entry = database::PasswordEntry::new(
                format!("Committed {}", i),
                None,
                format!("committed_user_{}", i),
            );
            entry.encrypted_password = vec![0xBB; 28];
            database::save_entry(&db, &key, &entry).expect("save committed entry");
        }

        // Start a write transaction for "uncommitted" entries but don't commit.
        // This simulates a crash during a batch operation.
        {
            let txn = db.begin_write().expect("begin write");
            {
                let mut table = txn
                    .open_table(database::ENTRIES_TABLE)
                    .expect("open entries");
                for i in 0..uncommitted_entries {
                    let entry_id = format!("uncommitted-{}", i);
                    // Insert raw — this is intentionally uncommitted
                    table
                        .insert(entry_id.as_str(), vec![0xCCu8; 28].as_slice())
                        .expect("insert uncommitted");
                }
            }
            // DON'T commit — just drop the transaction
            // redb will abort this transaction automatically on drop
            drop(txn);
        }

        drop(db);
    }
}

impl Default for FaultInjector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Concurrency Barriers
// ---------------------------------------------------------------------------

/// A concurrency test harness that coordinates multiple threads to exercise
/// race conditions.
///
/// Usage:
/// ```no_run
/// let harness = ConcurrencyHarness::new(num_threads);
/// let state = Arc::new(setup_state());
/// for _ in 0..num_threads {
///     let barrier = harness.barrier.clone();
///     let state = state.clone();
///     harness.spawn(move || {
///         barrier.wait(); // all threads start simultaneously
///         // ... do concurrent operations ...
///     });
/// }
/// harness.join_and_assert();
/// ```
pub struct ConcurrencyHarness {
    pub barrier: Arc<Barrier>,
    pub threads: Vec<thread::JoinHandle<()>>,
}

impl ConcurrencyHarness {
    pub fn new(num_threads: usize) -> Self {
        Self {
            barrier: Arc::new(Barrier::new(num_threads)),
            threads: Vec::with_capacity(num_threads),
        }
    }

    pub fn spawn<F>(&mut self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let barrier = self.barrier.clone();
        self.threads.push(thread::spawn(move || {
            barrier.wait();
            f();
        }));
    }

    /// Wait for all threads to complete. Panics if any thread panicked.
    pub fn join_and_assert(self) {
        for handle in self.threads {
            handle.join().expect("thread panicked");
        }
    }
}

/// Run `total_ops` concurrent mutation operations across `num_threads` threads
/// on the same database, then verify the entry count matches expectations.
///
/// Each operation either adds or removes an entry. The final count is checked
/// after all threads complete.
pub fn stress_concurrent_writes(
    db_path: &Path,
    num_threads: usize,
    ops_per_thread: usize,
) -> usize {
    let db = Arc::new(Database::open(db_path).expect("open db"));
    let mut harness = ConcurrencyHarness::new(num_threads);
    let key = [0x33u8; 32];

    for _ in 0..num_threads {
        let db = db.clone();
        harness.spawn(move || {
            for _ in 0..ops_per_thread {
                let entry = database::PasswordEntry::new(
                    "Concurrent".to_string(),
                    None,
                    "concurrent_user".to_string(),
                );
                // This uses the current API which has op_lock in AppState,
                // but at the DB level we're testing redb's MVCC.
                let _ = database::save_entry(&db, &key, &entry);
            }
        });
    }

    harness.join_and_assert();

    database::count_entries(&db).expect("final count")
}

// ---------------------------------------------------------------------------
// File Permission Verification
// ---------------------------------------------------------------------------

/// Verify that a file has the expected permission bits on Unix.
#[cfg(unix)]
pub fn assert_file_permissions(path: &Path, expected_mode: u32, mask: u32) {
    use std::os::unix::fs::PermissionsExt;
    let meta =
        std::fs::metadata(path).unwrap_or_else(|e| panic!("cannot stat {}: {}", path.display(), e));
    let actual = meta.permissions().mode() & mask;
    let expected = expected_mode & mask;
    assert_eq!(
        actual,
        expected,
        "file {} has permissions {:o}, expected {:o} (masked with {:o})",
        path.display(),
        meta.permissions().mode(),
        expected_mode,
        mask
    );
}

/// Verify that a directory has the expected permission bits on Unix.
#[cfg(unix)]
pub fn assert_dir_permissions(path: &Path, expected_mode: u32) {
    assert_file_permissions(path, expected_mode, 0o777);
}

/// Check if a file is readable by the current user only (0600 on Unix).
#[cfg(unix)]
pub fn assert_user_only_file(path: &Path) {
    assert_file_permissions(path, 0o600, 0o077);
}

/// Check if a directory is accessible by the current user only (0700 on Unix).
#[cfg(unix)]
pub fn assert_user_only_dir(path: &Path) {
    assert_file_permissions(path, 0o700, 0o077);
}

// Non-Unix stubs (Windows ACL verification will be added in Phase 2).
#[cfg(not(unix))]
pub fn assert_file_permissions(_path: &Path, _expected_mode: u32, _mask: u32) {
    // Windows uses ACLs, not Unix permission bits.
    // Permission verification on Windows will be implemented in Phase 2.
}

#[cfg(not(unix))]
pub fn assert_user_only_file(_path: &Path) {}
#[cfg(not(unix))]
pub fn assert_user_only_dir(_path: &Path) {}

// ---------------------------------------------------------------------------
// Test Infrastructure Self-Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Fault injection tests ---

    #[test]
    fn test_fault_injector_committed_data_survives_reopen() {
        let injector = FaultInjector::new();
        injector.write_and_crash_after_commit(5);
        injector.verify_entry_count(5);
    }

    #[test]
    fn test_fault_injector_uncommitted_data_not_visible() {
        let injector = FaultInjector::new();
        injector.write_and_crash_mid_transaction(3, 2);
        // Only the 3 committed entries should be visible.
        injector.verify_entry_count(3);
    }

    #[test]
    fn test_fault_injector_empty_db_reopens_cleanly() {
        let injector = FaultInjector::new();
        injector.verify_entry_count(0);
    }

    // --- Concurrency tests ---

    #[test]
    fn test_concurrency_barrier_basic() {
        let mut harness = ConcurrencyHarness::new(4);
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        for _ in 0..4 {
            let c = counter.clone();
            harness.spawn(move || {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        }

        harness.join_and_assert();
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 4);
    }

    #[test]
    fn test_concurrent_writes_are_all_preserved() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("concurrent.db");
        {
            let _db = database::init_database(&db_path).expect("init");
        }

        let num_threads = 4;
        let ops_per_thread = 10;
        let final_count = stress_concurrent_writes(&db_path, num_threads, ops_per_thread);

        // All writes from all threads should be present.
        assert_eq!(
            final_count,
            num_threads * ops_per_thread,
            "all concurrent writes should be preserved"
        );
    }

    #[test]
    fn test_concurrent_reads_during_writes() {
        // Verify reads don't block writes and vice versa (MVCC).
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("mvcc.db");
        let key = [0x55u8; 32];

        {
            let db = database::init_database(&db_path).unwrap();
            // Seed with some entries
            for i in 0..20 {
                let mut entry =
                    database::PasswordEntry::new(format!("Seed {}", i), None, format!("s{}", i));
                entry.encrypted_password = vec![0xDD; 28];
                database::save_entry(&db, &key, &entry).unwrap();
            }
            drop(db);
        }

        let db = Arc::new(Database::open(&db_path).unwrap());
        let mut harness = ConcurrencyHarness::new(2);

        // Writer thread
        {
            let db = db.clone();
            harness.spawn(move || {
                for i in 0..10 {
                    let mut entry = database::PasswordEntry::new(
                        format!("Writer {}", i),
                        None,
                        format!("w{}", i),
                    );
                    entry.encrypted_password = vec![0xEE; 28];
                    database::save_entry(&db, &key, &entry).unwrap();
                }
            });
        }

        // Reader thread
        {
            let db = db.clone();
            harness.spawn(move || {
                for _ in 0..10 {
                    let _ = database::count_entries(&db);
                }
            });
        }

        harness.join_and_assert();

        let final_count = database::count_entries(&db).unwrap();
        assert_eq!(final_count, 30); // 20 seed + 10 writer
    }

    // --- File permission tests (Unix only) ---

    #[cfg(unix)]
    #[test]
    fn test_assert_file_permissions_works() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test_file");
        std::fs::write(&file_path, b"test").unwrap();

        // Set known permissions
        let mut perms = std::fs::metadata(&file_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&file_path, perms).unwrap();

        assert_user_only_file(&file_path);
    }

    #[cfg(unix)]
    #[test]
    fn test_temp_dir_permissions() {
        // Verify that a directory with 0700 passes the user-only check.
        let dir = tempfile::TempDir::new().unwrap();
        let test_path = dir.path().join("restricted_dir");
        std::fs::create_dir(&test_path).unwrap();

        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&test_path).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&test_path, perms).unwrap();

        assert_user_only_dir(&test_path);
    }
}
