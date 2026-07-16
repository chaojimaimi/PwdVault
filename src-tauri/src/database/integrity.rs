//! Database integrity protection
//!
//! Maintains a full-database HMAC over all stored entries so that tampering
//! (record swap, rollback, partial deletion) can be detected on unlock.

use hmac::{Hmac, Mac};
use redb::{Database, ReadableTable, TableDefinition};
use sha2::Sha256;

use super::{DatabaseError, ENTRIES_TABLE, GROUPS_TABLE, SETTINGS_TABLE, VAULT_TABLE};

pub const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const DB_DIGEST_KEY: &str = "db_digest";
const DB_DIGEST_VERSION_KEY: &str = "db_digest_version";
const SCHEMA_VERSION_KEY: &str = "schema_version";

/// Schema versions
pub const SCHEMA_VERSION_LATEST: u32 = 1;

/// Digest computation version.
///
/// v1: covers only entries table (early v1.0.5 builds).
/// v2: covers all four user-data tables (entries, groups, settings, vault)
///     with domain-prefixed tags to prevent cross-table record swapping.
/// v3: same coverage as v2, but signals that the inner encrypted_password /
///     encrypted_notes fields have been re-encrypted from the v1.0.4
///     master_key to the v1.0.5 enc_key (HKDF-derived subkey). Databases
///     tagged with v1/v2 have inner fields still encrypted with master_key
///     and must be migrated.
/// v4: same coverage as v3, but entry/group records now use AES-GCM AAD
///     (record format v2). Records sealed with AAD cannot be swapped between
///     tables or ids. (§5.1.4)
///
/// When the stored version does not match `DB_DIGEST_VERSION`, the digest was
/// computed by an incompatible older build and must be re-established rather
/// than treated as a tampering detection.
const DB_DIGEST_VERSION: u32 = 4;

type HmacSha256 = Hmac<Sha256>;

/// Read the current schema version from meta (returns 0 if missing).
pub fn get_schema_version(db: &Database) -> Result<u32, DatabaseError> {
    let txn = db.begin_read()?;
    let table = txn.open_table(META_TABLE)?;
    let value = table
        .get(SCHEMA_VERSION_KEY)?
        .map(|v| {
            let bytes = v.value();
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[..4.min(bytes.len())]);
            u32::from_le_bytes(buf)
        })
        .unwrap_or(0);
    Ok(value)
}

/// Set the schema version in meta.
pub fn set_schema_version(db: &Database, version: u32) -> Result<(), DatabaseError> {
    let txn = db.begin_write()?;
    {
        let mut table = txn.open_table(META_TABLE)?;
        table.insert(SCHEMA_VERSION_KEY, version.to_le_bytes().as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Compute a deterministic HMAC over all user-data tables (entries, groups,
/// settings, verification). Covers every table that holds vault data so that
/// tampering with auto_lock_secs, group names, or KDF params is detectable.
///
/// Each record is prefixed with a domain tag so that a (key, value) pair
/// moved between tables cannot silently pass verification.
pub fn compute_db_digest(db: &Database, mac_key: &[u8; 32]) -> Result<[u8; 32], DatabaseError> {
    let txn = db.begin_read()?;
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC key length is valid");

    // Entries
    {
        let table = txn.open_table(ENTRIES_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"entry:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }

    // Groups
    {
        let table = txn.open_table(GROUPS_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"group:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }

    // Settings (single row keyed "current")
    {
        let table = txn.open_table(SETTINGS_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"settings:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }

    // Verification data (salt, KDF params, encrypted header)
    {
        let table = txn.open_table(VAULT_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"vault:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&mac.finalize().into_bytes());
    Ok(digest)
}

/// Check whether a digest has been stored. Databases created before v1.0.5
/// have no digest; `verify_integrity` passes them (migration handled by caller).
pub fn has_digest(db: &Database) -> Result<bool, DatabaseError> {
    let txn = db.begin_read()?;
    let table = txn.open_table(META_TABLE)?;
    Ok(table.get(DB_DIGEST_KEY)?.is_some())
}

/// Check whether the stored digest was computed by a compatible build.
///
/// Returns `true` when the stored digest version does not match the current
/// `DB_DIGEST_VERSION`, meaning it must be re-established via `refresh_digest`
/// rather than trusted for tamper detection. Databases without any digest
/// return `false` (they go through the normal migration path instead).
pub fn needs_digest_rebuild(db: &Database) -> Result<bool, DatabaseError> {
    let txn = db.begin_read()?;
    let table = txn.open_table(META_TABLE)?;
    if table.get(DB_DIGEST_KEY)?.is_none() {
        return Ok(false);
    }
    let stored_version = table.get(DB_DIGEST_VERSION_KEY)?.map(|v| {
        let bytes = v.value();
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[..4.min(bytes.len())]);
        u32::from_le_bytes(buf)
    });
    Ok(stored_version != Some(DB_DIGEST_VERSION))
}

/// Verify the stored db_digest against a freshly computed one.
///
/// Returns `true` when no digest is stored (pre-v1.0.5 database). The caller
/// is responsible for establishing the baseline via `refresh_digest` after
/// migration.
pub fn verify_integrity(db: &Database, mac_key: &[u8; 32]) -> Result<bool, DatabaseError> {
    let txn = db.begin_read()?;
    let table = txn.open_table(META_TABLE)?;
    let stored_opt = table.get(DB_DIGEST_KEY)?;

    // No digest stored — database predates integrity protection (v1.0.4 or
    // earlier). Pass verification; caller establishes the baseline.
    if stored_opt.is_none() {
        return Ok(true);
    }

    let stored = {
        let guard = stored_opt.unwrap();
        let bytes = guard.value();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[..32.min(bytes.len())]);
        digest
    };
    drop(txn);

    let actual = compute_db_digest(db, mac_key)?;
    Ok(stored == actual)
}

/// Recompute and store the db_digest after writes.
///
/// The digest is computed and stored within a SINGLE write transaction so
/// that no concurrent write can land between the read and the write, which
/// would otherwise leave the stored digest stale and cause a spurious
/// integrity failure on the next unlock.
pub fn refresh_digest(db: &Database, mac_key: &[u8; 32]) -> Result<(), DatabaseError> {
    let txn = db.begin_write()?;
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC key length is valid");

    // Compute digest by iterating all user-data tables within the same txn.
    {
        let table = txn.open_table(ENTRIES_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"entry:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }
    {
        let table = txn.open_table(GROUPS_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"group:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }
    {
        let table = txn.open_table(SETTINGS_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"settings:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }
    {
        let table = txn.open_table(VAULT_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"vault:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&mac.finalize().into_bytes());

    {
        let mut table = txn.open_table(META_TABLE)?;
        table.insert(DB_DIGEST_KEY, digest.as_slice())?;
        table.insert(
            DB_DIGEST_VERSION_KEY,
            DB_DIGEST_VERSION.to_le_bytes().as_slice(),
        )?;
    }
    txn.commit()?;
    Ok(())
}

/// Compute the HMAC digest using an existing `WriteTransaction`.
///
/// This is the core digest computation extracted from `refresh_digest` so it
/// can be called within a caller-owned transaction (§5.1.2 VaultWriteTxn).
/// The caller is responsible for committing the transaction afterward.
pub fn compute_digest_from_txn(
    txn: &redb::WriteTransaction,
    mac_key: &[u8; 32],
) -> Result<[u8; 32], DatabaseError> {
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC key length is valid");

    {
        let table = txn.open_table(ENTRIES_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"entry:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }
    {
        let table = txn.open_table(GROUPS_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"group:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }
    {
        let table = txn.open_table(SETTINGS_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"settings:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }
    {
        let table = txn.open_table(VAULT_TABLE)?;
        for result in table.iter()? {
            let (k, v) = result?;
            mac.update(b"vault:");
            mac.update(k.value().as_bytes());
            mac.update(v.value());
        }
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&mac.finalize().into_bytes());
    Ok(digest)
}

/// Recompute and store the digest within a caller-owned `WriteTransaction`.
///
/// Unlike `refresh_digest`, this does NOT open its own transaction or commit.
/// The caller must commit the transaction afterward. This allows business
/// writes and the digest update to be in the SAME transaction (§5.1.2).
pub fn refresh_digest_in_txn(
    txn: &redb::WriteTransaction,
    mac_key: &[u8; 32],
) -> Result<(), DatabaseError> {
    let digest = compute_digest_from_txn(txn, mac_key)?;

    {
        let mut table = txn.open_table(META_TABLE)?;
        table.insert(DB_DIGEST_KEY, digest.as_slice())?;
        table.insert(
            DB_DIGEST_VERSION_KEY,
            DB_DIGEST_VERSION.to_le_bytes().as_slice(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{init_database, PasswordEntry};
    use tempfile::TempDir;

    #[test]
    fn test_integrity_digest_changes_on_mutation() {
        let temp = TempDir::new().unwrap();
        let db = init_database(&temp.path().join("t.db")).unwrap();
        let mac_key = [1u8; 32];

        let digest1 = compute_db_digest(&db, &mac_key).unwrap();

        let entry = PasswordEntry::new("t".into(), None, "u".into());
        {
            let txn = db.begin_write().unwrap();
            {
                let mut table = txn.open_table(ENTRIES_TABLE).unwrap();
                table
                    .insert(entry.id.as_str(), entry.encrypted_password.as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let digest2 = compute_db_digest(&db, &mac_key).unwrap();
        assert_ne!(digest1, digest2);

        refresh_digest(&db, &mac_key).unwrap();
        assert!(verify_integrity(&db, &mac_key).unwrap());
    }
}
