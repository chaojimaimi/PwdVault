//! Test fixtures for database and backup format compatibility testing.
//!
//! This module provides programmatically generated synthetic databases and
//! backups that represent each released format version. These fixtures are
//! the regression baseline for Phase 0 of the Comprehensive Optimization Plan
//! v1.0.5: every future migration must be able to read these fixtures, and
//! no fixture contains real user credentials.
//!
//! ## Format history
//!
//! | Version tag    | Format description                                             |
//! |----------------|----------------------------------------------------------------|
//! | pre-v1.0.5     | Plaintext `bincode(PasswordEntry)` blobs, no digest, no HKDF   |
//! | v1.0.5/digest-v3 | `seal_entry` outer encryption, HKDF subkeys, HMAC digest v3  |
//! | backup-v1      | `.pvault` JSON envelope, AES-256-GCM, Argon2id (no HKDF)      |
//!
//! ## Synthetic data convention
//!
//! All entries use titles like "Fixture Entry 0", usernames like
//! "fixture_user_0@example.test", passwords like "fixture-password-0".
//! These are obviously synthetic and contain no sensitive information.

#![cfg(test)]

use redb::Database;
use tempfile::TempDir;

use crate::crypto;
use crate::database;

/// Synthetic test password used across all fixtures. Obviously fake.
pub const FIXTURE_PASSWORD: &str = "fixture-test-password-not-real";

/// A fixture database and the key material needed to open it.
pub struct DbFixture {
    pub dir: TempDir,
    pub db_path: std::path::PathBuf,
    pub db: Database,
    /// The master password that unlocks this fixture.
    pub password: &'static str,
    /// Salt used for KDF.
    pub salt: [u8; 16],
}

/// Create a v1.0.5 database with digest v3 (current format).
///
/// This fixture has:
/// - HKDF-derived enc_key + mac_key
/// - `seal_entry` outer encryption (whole-entry AES-256-GCM blob)
/// - Inner encrypted_password/encrypted_notes re-encrypted with enc_key
/// - HMAC-SHA256 integrity digest (version 3)
/// - Settings + groups
pub fn create_v1_0_5_digest_v3(entry_count: usize) -> DbFixture {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("fixture_v1.0.5_dv3.db");
    let db = database::init_database(&db_path).expect("init db");

    let password = FIXTURE_PASSWORD;
    let salt = crypto::kdf::generate_salt();
    // Use fixed KDF params instead of adaptive benchmarking. The adaptive
    // function measures wall-clock time to pick params, which produces
    // non-deterministic results under parallel test load — causing the
    // re-derived mac_key in verification tests to differ from the one used
    // to build the fixture.
    let params = crypto::kdf::AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        crypto::kdf::derive_key_with_params(password, &salt, &params).expect("derive key");
    let verification =
        crypto::create_verification_header(&master_key, salt, params).expect("create verification");
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);

    database::save_verification_data(&db, &verification).expect("save verification");

    // Create synthetic entries with v1.0.5 encryption
    for i in 0..entry_count {
        let mut entry = database::PasswordEntry::new(
            format!("Fixture Entry {}", i),
            Some(format!("https://fixture-{}.example.test", i)),
            format!("fixture_user_{}@example.test", i),
        );

        // Encrypt password with enc_key (v1.0.5 format)
        let enc_pwd = crypto::encrypt(&enc_key, format!("fixture-password-{}", i).as_bytes())
            .expect("encrypt password");
        entry.encrypted_password =
            bincode::serialize(&enc_pwd).expect("serialize encrypted password");

        // Some entries have notes
        if i % 3 == 0 {
            let enc_notes = crypto::encrypt(&enc_key, format!("Notes for entry {}", i).as_bytes())
                .expect("encrypt notes");
            entry.encrypted_notes =
                Some(bincode::serialize(&enc_notes).expect("serialize encrypted notes"));
        }

        // Some entries have tags
        if i % 2 == 0 {
            entry.tags = vec![format!("tag{}", i % 3), "fixture".to_string()];
        }

        // Some entries have a group
        if i % 4 == 0 {
            entry.group_id = Some("group-0".to_string());
        }

        database::save_entry(&db, &enc_key, &entry).expect("save entry");
    }

    // Create a group
    let group = database::Group::new("Fixture Group".to_string());
    // Override ID so entries can reference it
    let mut group_with_id = group;
    group_with_id.id = "group-0".to_string();
    database::save_group(&db, &enc_key, &group_with_id).expect("save group");

    // Save settings
    let settings = database::Settings::default();
    database::save_settings(&db, &settings).expect("save settings");

    // Establish integrity digest baseline
    database::integrity::refresh_digest(&db, &mac_key).expect("refresh digest");

    // Verify the fixture is correct
    assert!(
        database::integrity::has_digest(&db).expect("check digest"),
        "fixture must have a digest"
    );
    assert!(
        !database::integrity::needs_digest_rebuild(&db).expect("check rebuild"),
        "fixture digest version must be current"
    );
    assert!(
        database::integrity::verify_integrity(&db, &mac_key).expect("verify"),
        "fixture must pass integrity check"
    );

    let count = database::count_entries(&db).expect("count");
    assert_eq!(count, entry_count, "fixture entry count mismatch");

    DbFixture {
        dir,
        db_path,
        db,
        password,
        salt,
    }
}

/// Create a pre-v1.0.5 database (no digest, plaintext bincode blobs, no HKDF).
///
/// This simulates a database created by v1.0.4 or earlier:
/// - Entries stored as raw `bincode::serialize(PasswordEntry)` (no outer seal)
/// - `encrypted_password` encrypted with master_key (not enc_key)
/// - No integrity digest stored
/// - No HKDF subkey derivation
pub fn create_pre_v1_0_5(entry_count: usize) -> (TempDir, std::path::PathBuf, [u8; 16]) {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("fixture_pre_v1.0.5.db");

    // Use redb directly to avoid the v1.0.5 init_database creating a META table.
    // Pre-v1.0.5 databases did not have the meta table (it was added in v1.0.5).
    // However, init_database is idempotent for table creation, so we use it but
    // then verify that no digest exists.
    let db = database::init_database(&db_path).expect("init db");

    let password = FIXTURE_PASSWORD;
    let salt = crypto::kdf::generate_salt();
    let (master_key, params) = crypto::kdf::derive_key(password, &salt).expect("derive key");
    let verification =
        crypto::create_verification_header(&master_key, salt, params).expect("create verification");

    database::save_verification_data(&db, &verification).expect("save verification");

    // Create entries in pre-v1.0.5 format:
    // - encrypted_password encrypted with master_key (NOT enc_key)
    // - Stored as raw bincode(PasswordEntry) — NOT seal_entry
    for i in 0..entry_count {
        let mut entry = database::PasswordEntry::new(
            format!("Legacy Entry {}", i),
            Some(format!("https://legacy-{}.example.test", i)),
            format!("legacy_user_{}@example.test", i),
        );

        // Encrypt password with master_key (v1.0.4 behavior)
        let enc_pwd = crypto::encrypt(&master_key, format!("legacy-password-{}", i).as_bytes())
            .expect("encrypt password");
        entry.encrypted_password =
            bincode::serialize(&enc_pwd).expect("serialize encrypted password");

        // Store as raw bincode (pre-v1.0.5 — no outer seal_entry)
        let raw_blob = bincode::serialize(&entry).expect("serialize entry");

        let write_txn = db.begin_write().expect("begin write");
        {
            let mut table = write_txn
                .open_table(database::ENTRIES_TABLE)
                .expect("open entries");
            table
                .insert(entry.id.as_str(), raw_blob.as_slice())
                .expect("insert");
        }
        write_txn.commit().expect("commit");
    }

    // Verify NO digest exists (pre-v1.0.5)
    assert!(
        !database::integrity::has_digest(&db).expect("check digest"),
        "pre-v1.0.5 fixture must NOT have a digest"
    );

    // Close the database by dropping it so the file can be reopened later
    drop(db);

    (dir, db_path, salt)
}

/// Create a backup-v1 fixture (`.pvault` format).
///
/// Returns the JSON string of a `VaultBackup` with the given number of entries.
/// The backup uses a fixed password and synthetic data.
pub fn create_backup_v1(entry_count: usize) -> (String, &'static str) {
    use crate::{BackupPayload, ExportEntry, VaultBackup};
    use base64::Engine;

    let password = FIXTURE_PASSWORD;

    // Build plaintext payload
    let mut entries = Vec::new();
    for i in 0..entry_count {
        entries.push(ExportEntry {
            id: format!("backup-entry-{}", i),
            title: format!("Backup Fixture Entry {}", i),
            url: Some(format!("https://backup-fixture-{}.example.test", i)),
            username: format!("backup_user_{}@example.test", i),
            password: zeroize::Zeroizing::new(format!("backup-password-{}", i)),
            notes: if i % 2 == 0 {
                Some(zeroize::Zeroizing::new(format!("Backup notes {}", i)))
            } else {
                None
            },
            tags: vec!["backup-fixture".to_string()],
            group_id: None,
            created_at: 1700000000 + i as i64,
            updated_at: 1700000000 + i as i64,
        });
    }

    let payload = BackupPayload {
        entries,
        groups: vec![database::Group::new("Backup Fixture Group".to_string())],
        settings: database::Settings::default(),
    };

    let payload_json = serde_json::to_vec(&payload).expect("serialize payload");

    // Encrypt with export password
    let salt = crypto::kdf::generate_salt();
    let (export_key, params) = crypto::kdf::derive_key(password, &salt).expect("derive key");
    let encrypted = crypto::encrypt(&export_key, &payload_json).expect("encrypt");

    let b64 = base64::engine::general_purpose::STANDARD;

    let backup = VaultBackup {
        version: 1,
        created_at: chrono::Utc::now().timestamp(),
        magic: None,
        kdf_name: None,
        cipher_name: None,
        salt: b64.encode(salt),
        kdf_memory: params.m_cost,
        kdf_iterations: params.t_cost,
        kdf_parallelism: params.p_cost,
        nonce: b64.encode(&encrypted.nonce),
        data: b64.encode(&encrypted.ciphertext),
    };

    let json = serde_json::to_string_pretty(&backup).expect("serialize backup");
    (json, password)
}

// ---------------------------------------------------------------------------
// Fixture verification tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_v1_0_5_fixture_small() {
        let fixture = create_v1_0_5_digest_v3(3);
        assert_eq!(database::count_entries(&fixture.db).unwrap(), 3);
        // Recompute mac_key from fixture credentials using the same fixed params
        let salt = fixture.salt;
        let (master_key, _) = crypto::kdf::derive_key_with_params(
            FIXTURE_PASSWORD,
            &salt,
            &crypto::kdf::AdaptiveParams {
                m_cost: 16384,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let (_, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);
        assert!(database::integrity::verify_integrity(&fixture.db, &mac_key).unwrap());
    }

    #[test]
    fn test_v1_0_5_fixture_medium() {
        let fixture = create_v1_0_5_digest_v3(50);
        assert_eq!(database::count_entries(&fixture.db).unwrap(), 50);
    }

    #[test]
    fn test_pre_v1_0_5_fixture() {
        let (dir, db_path, _salt) = create_pre_v1_0_5(5);
        let db = database::init_database(&db_path).unwrap();
        assert!(!database::integrity::has_digest(&db).unwrap());
        assert_eq!(database::count_entries(&db).unwrap(), 5);
        drop(dir);
    }

    #[test]
    fn test_backup_v1_fixture_round_trip() {
        let (json, password) = create_backup_v1(3);
        let backup: crate::VaultBackup = serde_json::from_str(&json).unwrap();

        // Verify we can decrypt it
        let b64 = base64::engine::general_purpose::STANDARD;
        let salt = b64.decode(&backup.salt).unwrap();
        let salt_array: [u8; 16] = salt.try_into().unwrap();

        let (key, _) = crypto::kdf::derive_key_with_params(
            password,
            &salt_array,
            &crypto::kdf::AdaptiveParams {
                m_cost: backup.kdf_memory,
                t_cost: backup.kdf_iterations,
                p_cost: backup.kdf_parallelism,
            },
        )
        .unwrap();

        let nonce = b64.decode(&backup.nonce).unwrap();
        let ciphertext = b64.decode(&backup.data).unwrap();
        let payload_bytes =
            crypto::decrypt(&key, &crypto::EncryptedData { nonce, ciphertext }).unwrap();
        let payload: crate::BackupPayload = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(payload.entries.len(), 3);
        assert_eq!(payload.entries[0].title, "Backup Fixture Entry 0");
    }
}
