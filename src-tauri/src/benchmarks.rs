//! Performance baseline benchmarks.
//!
//! Establishes baseline timing data for vault operations at different scale:
//! - 100 entries (small vault)
//! - 1,000 entries (typical vault)
//! - 5,000 entries (large vault)
//! - 10,000 entries (stress vault)
//!
//! These tests are marked `#[ignore]` so they don't run in normal `cargo test`.
//! Run them explicitly with: `cargo test -- --ignored benchmarks`
//!
//! Results should be recorded in docs/PERFORMANCE-BASELINE.md after each run.

#![cfg(test)]

use std::sync::Arc;
use std::time::Instant;

use crate::crypto;
use crate::database;
use crate::service;

/// Entry counts for benchmark scale tiers.
const SCALE_TIERS: &[usize] = &[100, 1000, 5000, 10000];

/// Set up a fully unlocked AppState with `count` entries.
fn setup_vault_with_entries(count: usize) -> (Arc<crate::AppState>, tempfile::TempDir) {
    let temp = tempfile::TempDir::new().expect("create temp dir");
    let db_path = temp.path().join("bench_vault.db");
    let db = Arc::new(database::init_database(&db_path).expect("init db"));

    let state = Arc::new(crate::AppState::default());
    *state.database.lock().expect("db lock") = Some(db.clone());

    // Initialize vault
    let salt = crypto::kdf::generate_salt();
    // Use minimal KDF for benchmark speed — we're measuring DB performance, not KDF
    let (master_key, params) = crypto::kdf::derive_key_with_params(
        "benchmark-password",
        &salt,
        &crypto::kdf::AdaptiveParams {
            m_cost: 8192, // 8 MB — minimal for tests
            t_cost: 1,
            p_cost: 1,
        },
    )
    .expect("derive key");

    let verification =
        crypto::create_verification_header(&master_key, salt, params).expect("create verification");
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);

    database::save_verification_data(&db, &verification).expect("save verification");
    *state.verification_data.lock().expect("v lock") = Some(verification);
    state.keystore.set_key(enc_key).expect("set key");
    *state.mac_key.lock().expect("mac key lock") = Some(mac_key);
    state.touch_activity();

    // Bulk insert entries directly (bypass service layer for speed)
    for i in 0..count {
        let mut entry = database::PasswordEntry::new(
            format!("Benchmark Entry {}", i),
            Some(format!("https://bench-{}.example.test", i)),
            format!("bench_user_{}@example.test", i),
        );
        let enc_pwd = crypto::encrypt(&enc_key, format!("bench-pwd-{}", i).as_bytes())
            .expect("encrypt password");
        entry.encrypted_password =
            bincode::serialize(&enc_pwd).expect("serialize encrypted password");

        if i % 3 == 0 {
            let enc_notes = crypto::encrypt(&enc_key, format!("Notes for {}", i).as_bytes())
                .expect("encrypt notes");
            entry.encrypted_notes =
                Some(bincode::serialize(&enc_notes).expect("serialize encrypted notes"));
        }

        entry.tags = vec![format!("tag{}", i % 5), "benchmark".to_string()];

        database::save_entry(&db, &enc_key, &entry).expect("save entry");
    }

    // Establish digest
    database::integrity::refresh_digest(&db, &mac_key).expect("refresh digest");

    let actual = database::count_entries(&db).expect("count");
    assert_eq!(actual, count, "setup failed: expected {} entries", count);

    (state, temp)
}

/// Benchmark: list all entries (metadata only, no secrets).
fn bench_list_all_entries(state: &Arc<crate::AppState>) -> std::time::Duration {
    let start = Instant::now();
    let entries = service::list_all_entries(state).expect("list entries");
    let elapsed = start.elapsed();
    assert!(!entries.is_empty(), "entries should not be empty");
    elapsed
}

/// Benchmark: get entry count.
fn bench_count_entries(state: &Arc<crate::AppState>) -> std::time::Duration {
    let start = Instant::now();
    let _count = service::get_entry_count(state).expect("count");
    start.elapsed()
}

/// Benchmark: digest computation (integrity check).
fn bench_compute_digest(state: &Arc<crate::AppState>) -> std::time::Duration {
    let db = service::vault::get_db(state).expect("get db");
    let mac_key = service::vault::get_mac_key(state).expect("get mac key");
    let start = Instant::now();
    let _digest = database::integrity::compute_db_digest(&db, &mac_key).expect("compute digest");
    start.elapsed()
}

/// Benchmark: create a single entry.
fn bench_create_entry(state: &Arc<crate::AppState>) -> std::time::Duration {
    let request = crate::CreateEntryRequest {
        title: "Bench Create".to_string(),
        url: Some("https://bench-create.example.test".to_string()),
        username: "bench_create_user".to_string(),
        password: zeroize::Zeroizing::new("bench-create-pwd".to_string()),
        notes: None,
        tags: vec!["bench".to_string()],
        group_id: None,
    };
    let start = Instant::now();
    let _ = service::create_entry(state, request).expect("create entry");
    start.elapsed()
}

/// Run benchmarks for a given scale tier and print results.
fn run_scale_benchmark(count: usize) {
    println!("\n=== Benchmark scale: {} entries ===", count);

    let (state, _temp) = setup_vault_with_entries(count);

    // Run each benchmark 3 times and take the median
    for (label, f) in [
        (
            "count_entries",
            bench_count_entries as fn(&Arc<crate::AppState>) -> std::time::Duration,
        ),
        (
            "list_all_entries",
            bench_list_all_entries as fn(&Arc<crate::AppState>) -> std::time::Duration,
        ),
        (
            "compute_digest",
            bench_compute_digest as fn(&Arc<crate::AppState>) -> std::time::Duration,
        ),
    ] {
        let mut times = Vec::new();
        for _ in 0..3 {
            times.push(f(&state));
        }
        times.sort();
        let median = times[times.len() / 2];
        println!(
            "  {:20}: p50 = {:.2}ms",
            label,
            median.as_secs_f64() * 1000.0
        );
    }

    // create_entry changes the DB, so run it once (it adds an extra entry)
    let create_time = bench_create_entry(&state);
    println!(
        "  {:20}: {:.2}ms (1 run)",
        "create_entry",
        create_time.as_secs_f64() * 1000.0
    );
}

#[test]
#[ignore = "benchmark — run with: cargo test -- --ignored benchmarks"]
fn benchmarks_all_scales() {
    println!("\n============================================================");
    println!("PwdVault Performance Baseline");
    println!(
        "Date: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("============================================================");

    for &count in SCALE_TIERS {
        run_scale_benchmark(count);
    }

    println!("\n============================================================");
    println!("Record these results in docs/PERFORMANCE-BASELINE.md");
    println!("============================================================");
}

/// Quick sanity benchmark that runs in normal test mode (small scale).
#[test]
fn benchmark_sanity_check() {
    let (state, _temp) = setup_vault_with_entries(50);
    let start = Instant::now();
    let entries = service::list_all_entries(&state).expect("list");
    let elapsed = start.elapsed();

    assert_eq!(entries.len(), 50);
    // On any modern machine, listing 50 entries should be under 500ms
    // even with the current per-entry transaction overhead.
    assert!(
        elapsed.as_millis() < 500,
        "listing 50 entries took {}ms — regression?",
        elapsed.as_millis()
    );

    println!(
        "\n[sanity] list 50 entries: {:.2}ms",
        elapsed.as_secs_f64() * 1000.0
    );
}
