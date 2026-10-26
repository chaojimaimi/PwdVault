//! v1.6.0 (D5): conflict counting through the ENGINE — the unit-level
//! criteria matrix lives in merge.rs's own tests; this file pins the
//! end-to-end path (merge → `SyncState.last_conflict_count` →
//! `SyncStatusResponse.conflict_count`) against the mock cloud backend.

use std::time::Duration;

use zeroize::Zeroizing;

use super::backend::MockCloudBackend;
use super::engine::{sync_connect_with_backend, sync_now_with_backend};
use super::tests_engine::{create_entry_titled, test_config, test_state};

/// Second-granularity timestamps: the delete-then-edit ordering below must
/// be STRICT, so the edit waits out the same-second window.
const CLOCK_RESOLUTION_GUARD: Duration = Duration::from_millis(1100);

fn update_entry_title(state: &std::sync::Arc<crate::AppState>, id: &str, title: &str) {
    crate::update_entry(
        state,
        id.to_string(),
        crate::UpdateEntryRequest {
            url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
            title: title.to_string(),
            url: None,
            username: "user-delta".to_string(),
            password: None,
            notes: None,
            update_notes: false,
            tags: vec![],
            group_id: None,
            totp_secret: None,
            custom_fields: None,
        },
    )
    .unwrap();
}

/// The full D5 scenario, end to end: A deletes and publishes; B edits AFTER
/// the deletion landed and syncs — the LWW merge revives B's edit and counts
/// exactly ONE conflict, surfaced in the status payload AND the persisted
/// `SyncState` row. The follow-up no-change cycle resets the count to 0
/// (per-cycle semantics, not cumulative).
#[test]
fn delete_then_modify_counts_one_conflict_and_resets_next_cycle() {
    let (device_a, _dir_a) = test_state();
    let (device_b, _dir_b) = test_state();
    let cloud = MockCloudBackend::new();

    // A creates and bootstraps the cloud (rev 1 carries "delta").
    let delta = create_entry_titled(&device_a, "delta");
    let status = sync_connect_with_backend(
        &device_a,
        &cloud.handle(),
        test_config(),
        Zeroizing::new("container-passphrase".to_string()),
        None,
    )
    .unwrap();
    assert_eq!(status.conflict_count, 0, "plain bootstrap counts nothing");

    // B joins (pulls delta).
    sync_connect_with_backend(
        &device_b,
        &cloud.handle(),
        test_config(),
        Zeroizing::new("container-passphrase".to_string()),
        None,
    )
    .unwrap();

    // A deletes and publishes the tombstone.
    crate::remove_entry(&device_a, delta.clone()).unwrap();
    let status = sync_now_with_backend(&device_a, &cloud.handle()).unwrap();
    assert_eq!(
        status.conflict_count, 0,
        "publishing a tombstone is not a conflict"
    );

    // B edits strictly AFTER the deletion moment (see CLOCK_RESOLUTION_GUARD).
    std::thread::sleep(CLOCK_RESOLUTION_GUARD);
    update_entry_title(&device_b, &delta, "delta-edited-after-delete");

    // B's cycle: local live edit (updated_at > tombstone deleted_at) vs the
    // remote tombstone → the edit revives and the conflict is counted.
    let status = sync_now_with_backend(&device_b, &cloud.handle()).unwrap();
    assert_eq!(
        status.conflict_count, 1,
        "delete-then-modify must count exactly one conflict"
    );
    // The persisted row backs the status payload (same value, not a
    // transient field).
    let persisted = crate::service::sync_status(&device_b).unwrap();
    assert_eq!(persisted.conflict_count, 1);
    // B's edit survived the arbitration.
    let titles: Vec<String> = crate::list_all_entries(&device_b)
        .unwrap()
        .into_iter()
        .map(|entry| entry.title)
        .collect();
    assert_eq!(titles, vec!["delta-edited-after-delete".to_string()]);

    // The follow-up cycle (nothing changed) merges tombstone-vs-tombstone /
    // identical content — 0 conflicts. Per-cycle, not cumulative.
    let status = sync_now_with_backend(&device_b, &cloud.handle()).unwrap();
    assert_eq!(
        status.conflict_count, 0,
        "a no-change cycle must reset the conflict count"
    );
}

/// Sequential edits (different timestamps, both live) propagate through the
/// engine with ZERO conflicts — the anti-noise guarantee that keeps the D5
/// counter meaningful.
#[test]
fn sequential_edits_propagate_without_conflicts() {
    let (device_a, _dir_a) = test_state();
    let (device_b, _dir_b) = test_state();
    let cloud = MockCloudBackend::new();

    let alpha = create_entry_titled(&device_a, "alpha");
    sync_connect_with_backend(
        &device_a,
        &cloud.handle(),
        test_config(),
        Zeroizing::new("container-passphrase".to_string()),
        None,
    )
    .unwrap();
    sync_connect_with_backend(
        &device_b,
        &cloud.handle(),
        test_config(),
        Zeroizing::new("container-passphrase".to_string()),
        None,
    )
    .unwrap();

    // B renames and publishes; A's next cycle pulls the rename — plain LWW,
    // no conflict anywhere.
    std::thread::sleep(CLOCK_RESOLUTION_GUARD);
    update_entry_title(&device_b, &alpha, "alpha-renamed");
    let status = sync_now_with_backend(&device_b, &cloud.handle()).unwrap();
    assert_eq!(status.conflict_count, 0);
    let status = sync_now_with_backend(&device_a, &cloud.handle()).unwrap();
    assert_eq!(status.conflict_count, 0);
    assert_eq!(
        sync_now_with_backend(&device_b, &cloud.handle())
            .unwrap()
            .conflict_count,
        0
    );
    let titles: Vec<String> = crate::list_all_entries(&device_a)
        .unwrap()
        .into_iter()
        .map(|entry| entry.title)
        .collect();
    assert_eq!(titles, vec!["alpha-renamed".to_string()]);
}

/// The stale-copy deletion propagation pin, at engine granularity: A
/// deletes; B (whose copy predates the deletion) does NOTHING and syncs —
/// the tombstone propagates over B's stale live copy and NOTHING is counted
/// (this is the XOR-trap case the D5 wording exists to prevent).
#[test]
fn stale_copy_deletion_propagation_counts_nothing() {
    let (device_a, _dir_a) = test_state();
    let (device_b, _dir_b) = test_state();
    let cloud = MockCloudBackend::new();

    let beta = create_entry_titled(&device_a, "beta");
    sync_connect_with_backend(
        &device_a,
        &cloud.handle(),
        test_config(),
        Zeroizing::new("container-passphrase".to_string()),
        None,
    )
    .unwrap();
    sync_connect_with_backend(
        &device_b,
        &cloud.handle(),
        test_config(),
        Zeroizing::new("container-passphrase".to_string()),
        None,
    )
    .unwrap();

    // A deletes and publishes; B just syncs its untouched stale copy.
    crate::remove_entry(&device_a, beta).unwrap();
    sync_now_with_backend(&device_a, &cloud.handle()).unwrap();
    std::thread::sleep(CLOCK_RESOLUTION_GUARD);
    let status = sync_now_with_backend(&device_b, &cloud.handle()).unwrap();
    assert_eq!(
        status.conflict_count, 0,
        "stale-copy deletion propagation is ordinary sync, not a conflict"
    );
    // And the deletion landed on B.
    assert!(crate::list_all_entries(&device_b).unwrap().is_empty());
}
