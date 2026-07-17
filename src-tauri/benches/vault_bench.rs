//! Criterion benchmarks for vault data operations (§5.6.2, §5.6.6-3).
//!
//! Run with: `cargo bench` (from src-tauri/).
//! Reports are written to `target/criterion/`.
//!
//! Measured operations:
//!   - list_all_entries_bulk: single-read-txn bulk scan + decrypt
//!   - compute_db_digest: HMAC over the full tables (the per-mutation cost)
//!   - create_entry via VaultStore::write: business write + digest refresh
//!
//! Scale tiers: 100 / 500 / 1000 entries (kept bounded so seeding finishes
//! quickly; the digest/list costs are linear, so larger tiers can be
//! extrapolated or added once seeding is amortized).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pwdvault_infrastructure::database::{self, PasswordEntry};
use pwdvault_infrastructure::database::integrity;
use pwdvault_infrastructure::database::vault_store::VaultStore;
use pwdvault_infrastructure::crypto;
use redb::Database;
use tempfile::TempDir;

const SCALE_TIERS: &[usize] = &[100, 500, 1000];

/// Build a test database populated with `n` encrypted entries and return
/// (db, enc_key, mac_key, temp_dir). The temp dir keeps the db file alive.
///
/// Seeding uses raw write transactions (no per-insert digest refresh) so the
/// O(N) seed does not become O(N²). The final seed transaction writes the
/// digest once so `compute_db_digest` and `verify_integrity` work.
fn build_db(n: usize) -> (Database, [u8; 32], [u8; 32], TempDir) {
    let temp = TempDir::new().expect("create temp dir");
    let db_path = temp.path().join("bench.db");
    let db = database::init_database(&db_path).expect("init db");

    let enc_key = [0x42u8; 32];
    let mac_key = [0x84u8; 32];

    // Seed in batches of 100 entries per raw transaction to avoid the
    // per-insert digest refresh that VaultStore::write would trigger.
    for batch_start in (0..n).step_by(100) {
        let txn = db.begin_write().expect("begin seed txn");
        for i in batch_start..(batch_start + 100).min(n) {
            let mut entry = PasswordEntry::new(
                format!("entry-{}", i),
                Some(format!("https://example.com/{}", i)),
                format!("user{}", i),
            );
            entry.encrypted_password =
                crypto::encrypt(&enc_key, b"bench-password")
                    .ok()
                    .and_then(|d| bincode::serialize(&d).ok())
                    .unwrap_or_default();
            database::vault_store::save_entry_in_txn(&txn, &enc_key, &entry).expect("seed entry");
        }
        txn.commit().expect("commit seed batch");
    }

    // Write the digest once so the seeded DB is in a consistent state.
    integrity::refresh_digest(&db, &mac_key).expect("seed digest");

    (db, enc_key, mac_key, temp)
}

fn bench_list_all_entries_bulk(c: &mut Criterion) {
    let mut group = c.benchmark_group("list_all_entries_bulk");
    for &n in SCALE_TIERS {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let (db, enc_key, _mac_key, _temp) = build_db(n);
            b.iter(|| {
                database::list_all_entries_bulk(&db, &enc_key, None).expect("bulk list");
            });
        });
    }
    group.finish();
}

fn bench_compute_db_digest(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_db_digest");
    for &n in SCALE_TIERS {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let (db, _enc_key, mac_key, _temp) = build_db(n);
            b.iter(|| {
                integrity::compute_db_digest(&db, &mac_key).expect("compute digest");
            });
        });
    }
    group.finish();
}

fn bench_create_entry_with_digest(c: &mut Criterion) {
    // Measures the full mutation path: business write + digest refresh in one
    // transaction. This is the per-keystroke-irrelevant but per-CRUD-relevant
    // cost that §5.6.2 wants bounded at 5k with <20% regression.
    let mut group = c.benchmark_group("create_entry_with_digest");
    for &n in SCALE_TIERS {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let (db, enc_key, mac_key, _temp) = build_db(n);
            let mut counter = 0usize;
            b.iter(|| {
                let entry = PasswordEntry::new(
                    format!("new-{}", counter),
                    None,
                    format!("new-user-{}", counter),
                );
                counter += 1;
                let store = VaultStore::new(&db);
                store
                    .write(&mac_key, |txn| {
                        database::vault_store::save_entry_in_txn(txn, &enc_key, &entry)?;
                        Ok(())
                    })
                    .expect("create entry");
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_list_all_entries_bulk,
    bench_compute_db_digest,
    bench_create_entry_with_digest,
);
criterion_main!(benches);
