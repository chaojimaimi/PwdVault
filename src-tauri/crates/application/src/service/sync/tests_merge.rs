//! v1.6.0 (WP3): merge-engine test suite, moved VERBATIM from merge.rs's
//! former `mod tests` when the D5 conflict-counting doc + tests pushed that
//! file past the 800-line ceiling (test-module-only move — zero behavior
//! change; the v1.5.0 commit-gate playbook).

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::container::entry_fingerprint;
use super::merge::{merge_entries, merge_groups, merge_snapshots, snapshots_equivalent};
use super::{SyncEntry, SyncGroup, SyncSnapshot};

fn sync_entry(id: &str) -> SyncEntry {
    SyncEntry {
        url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
        id: id.to_string(),
        title: format!("Title {id}"),
        url: None,
        username: format!("user-{id}"),
        password: Some("pw".to_string()),
        notes: None,
        totp_secret: None,
        tags: vec![],
        group_id: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        deleted_at: None,
        custom_fields: vec![],
    }
}

fn sync_group(id: &str) -> SyncGroup {
    SyncGroup {
        id: id.to_string(),
        name: format!("Group {id}"),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        deleted_at: None,
    }
}

fn sorted(mut entries: Vec<SyncEntry>) -> Vec<SyncEntry> {
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    entries
}

// ------------------------------------------------------------------
// Designated conflict cases (P3.6 item 2)
// ------------------------------------------------------------------

/// Both devices concurrently modify DIFFERENT entries: both changes
/// survive the union, and no conflict is counted (independent rows).
#[test]
fn concurrent_edits_to_different_entries_both_survive() {
    let mut a = sync_entry("e1");
    a.updated_at = 100;
    a.title = "A-edit".to_string();
    let mut b = sync_entry("e2");
    b.updated_at = 200;
    b.title = "B-edit".to_string();

    let (merged, conflicts) = merge_entries(&[a.clone()], &[b.clone()]);
    let (merged_ba, conflicts_ba) = merge_entries(&[b], &[a]);
    assert_eq!(merged, merged_ba);
    assert_eq!(conflicts, conflicts_ba);
    assert_eq!(conflicts, 0);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].title, "A-edit");
    assert_eq!(merged[1].title, "B-edit");
}

/// Same entry modified at two points in time (LWW): the later edit wins,
/// in both argument orders — and NO conflict is counted (D5: sequential
/// edits are LWW design behavior, not ambiguity).
#[test]
fn sequential_edits_to_same_entry_take_the_newer_one() {
    let mut older = sync_entry("e1");
    older.updated_at = 100;
    older.username = "old".to_string();
    let mut newer = sync_entry("e1");
    newer.updated_at = 200;
    newer.username = "new".to_string();

    let (merged, conflicts) = merge_entries(&[older.clone()], &[newer.clone()]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].username, "new");
    assert_eq!(merged[0].updated_at, 200);
    let (merged_ba, conflicts_ba) = merge_entries(&[newer], &[older]);
    assert_eq!(merged, merged_ba);
    assert_eq!(conflicts, 0);
    assert_eq!(conflicts_ba, 0);
}

/// One side deletes, the other modifies — decided in BOTH directions:
/// a deletion at least as recent as the modification stands; an older
/// deletion loses and the modification revives the entry.
///
/// Conflict counts (D5): the deletion propagation case (edit ≤ deletion
/// moment) counts NOTHING; the edit-after-delete case counts exactly one
/// in both argument orders (criterion 1, the `>=` branch where the
/// tombstone wins LWW stays silent — only the None and revival branches
/// carry a real "edit after delete").
#[test]
fn delete_and_modify_arbitrate_symmetrically_both_ways() {
    // Tombstone (300) vs modification (200): deletion wins — and this is
    // STALE-COPY PROPAGATION (edit predates the deletion), not a
    // conflict. Negative regression pin for the D5 `<=` clause.
    let mut edited = sync_entry("e1");
    edited.updated_at = 200;
    edited.username = "edited".to_string();
    let mut deleted = sync_entry("e1");
    deleted.updated_at = 300;
    deleted.deleted_at = Some(300);

    let (delete_first, conflicts) = merge_entries(&[deleted.clone()], &[edited.clone()]);
    let (delete_first_ba, conflicts_ba) = merge_entries(&[edited], &[deleted]);
    assert_eq!(delete_first, delete_first_ba);
    assert_eq!(
        conflicts, 0,
        "stale-copy deletion propagation is not a conflict"
    );
    assert_eq!(conflicts_ba, 0);
    assert_eq!(delete_first.len(), 1);
    assert_eq!(delete_first[0].deleted_at, Some(300));

    // Tombstone (300) vs modification (400): modification wins, live —
    // a REAL edit after the deletion, counted exactly once either way
    // (the LWW "live wins" branch, D5 criterion 1).
    let mut edited = sync_entry("e1");
    edited.updated_at = 400;
    edited.username = "edited".to_string();
    let mut deleted = sync_entry("e1");
    deleted.updated_at = 300;
    deleted.deleted_at = Some(300);

    let (merged, conflicts) = merge_entries(&[deleted.clone()], &[edited.clone()]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].deleted_at, None);
    assert_eq!(merged[0].username, "edited");
    assert_eq!(conflicts, 1);
    assert_eq!(merge_entries(&[edited], &[deleted]).1, 1);
}

/// REVIVAL BRANCH (D5 criterion 1 covers it): a tombstone whose
/// `deleted_at` predates the live side's `updated_at` while its
/// (invariant-violating) `updated_at` still wins LWW — only corrupt or
/// foreign data reaches this branch (the remove_entry invariant stamps
/// updated_at = deleted_at) — still counts as a delete-then-modify
/// conflict.
#[test]
fn revival_branch_counts_as_delete_then_modify_conflict() {
    let mut edited = sync_entry("e1");
    edited.updated_at = 200;
    edited.username = "edited".to_string();
    let mut foreign_tombstone = sync_entry("e1");
    foreign_tombstone.updated_at = 300; // wins LWW...
    foreign_tombstone.deleted_at = Some(100); // ...but the deletion is older → revival
    assert!(foreign_tombstone.deleted_at.unwrap() < edited.updated_at);

    let (merged, conflicts) = merge_entries(&[foreign_tombstone.clone()], &[edited.clone()]);
    assert_eq!(merged.len(), 1);
    assert_eq!(
        merged[0].deleted_at, None,
        "the live edit revives the entry"
    );
    assert_eq!(merged[0].username, "edited");
    assert_eq!(conflicts, 1);
    assert_eq!(merge_entries(&[edited], &[foreign_tombstone]).1, 1);
}

/// Equal `updated_at` resolves via the content fingerprint, and the
/// verdict is identical under argument swap (review P1: the tiebreak
/// must not depend on parameter position). D5: the forced tiebreak on
/// divergent live content IS a conflict (criterion 2) — counted once,
/// symmetrically.
#[test]
fn equal_updated_at_uses_fingerprint_tiebreak_symmetrically() {
    let mut a = sync_entry("e1");
    a.title = "aaa".to_string();
    let mut b = sync_entry("e1");
    b.title = "bbb".to_string();
    let fingerprint_a = entry_fingerprint(&a);
    let fingerprint_b = entry_fingerprint(&b);
    assert_ne!(fingerprint_a, fingerprint_b);

    let (merged, conflicts) = merge_entries(&[a.clone()], &[b.clone()]);
    let (merged_ba, conflicts_ba) = merge_entries(&[b], &[a.clone()]);
    assert_eq!(merged, merged_ba);
    assert_eq!(
        conflicts, 1,
        "timestamp collision on diverged content counts"
    );
    assert_eq!(conflicts_ba, 1);
    let expected = if fingerprint_a > fingerprint_b {
        "aaa"
    } else {
        "bbb"
    };
    assert_eq!(merged[0].title, expected);

    // Identical content re-added on both devices (same fingerprint) is
    // idempotent — NOT a conflict despite the equal timestamps.
    let (merged, conflicts) = merge_entries(&[a.clone()], &[a.clone()]);
    assert_eq!(merged.len(), 1);
    assert_eq!(conflicts, 0, "idempotent duplicate adds never count");
}

/// Both sides tombstoned: the deletions converge and NOTHING is counted
/// (D5 negative pin), regardless of which deletion is newer.
#[test]
fn both_sides_deleted_never_counts() {
    let mut deleted_old = sync_entry("e1");
    deleted_old.updated_at = 100;
    deleted_old.deleted_at = Some(100);
    let mut deleted_new = sync_entry("e1");
    deleted_new.updated_at = 300;
    deleted_new.deleted_at = Some(300);

    let (merged, conflicts) = merge_entries(&[deleted_old.clone()], &[deleted_new.clone()]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].deleted_at, Some(300));
    assert_eq!(conflicts, 0);
    assert_eq!(merge_entries(&[deleted_new], &[deleted_old]).1, 0);

    // Groups follow the same verdict.
    let mut g_deleted_old = sync_group("g1");
    g_deleted_old.updated_at = 100;
    g_deleted_old.deleted_at = Some(100);
    let mut g_deleted_new = sync_group("g1");
    g_deleted_new.updated_at = 300;
    g_deleted_new.deleted_at = Some(300);
    assert_eq!(merge_groups(&[g_deleted_old], &[g_deleted_new]).1, 0);
}

/// Equal-timestamp tombstone-vs-live is STALE PROPAGATION by definition
/// (the D5 `<=` clause): remove_entry stamps updated_at = deleted_at, so
/// a peer copy last written at exactly the deletion moment is a copy,
/// not an edit — not counted, whichever side the fingerprint tiebreak
/// picks as the LWW winner.
#[test]
fn equal_timestamp_tombstone_vs_live_is_propagation_not_conflict() {
    let mut edited_at_deletion = sync_entry("e1");
    edited_at_deletion.updated_at = 300;
    edited_at_deletion.username = "same-second-copy".to_string();
    let mut deleted = sync_entry("e1");
    deleted.updated_at = 300;
    deleted.deleted_at = Some(300);
    assert_ne!(
        entry_fingerprint(&edited_at_deletion),
        entry_fingerprint(&deleted),
        "the scenario is meaningless if the fingerprints collide"
    );

    let (merged, conflicts) = merge_entries(&[deleted.clone()], &[edited_at_deletion.clone()]);
    assert_eq!(merged.len(), 1);
    assert_eq!(conflicts, 0);
    assert_eq!(merge_entries(&[edited_at_deletion], &[deleted]).1, 0);
}

/// Group removal does not cascade: the tombstoned group travels in the
/// merge result while entries keep their (hanging) group_id — the UI
/// renders those as ungrouped. Group renames arbitrate by the same LWW;
/// rename-vs-delete follows the D5 counts (rename after delete counts,
/// stale rename does not).
#[test]
fn group_tombstone_does_not_cascade_and_lww_applies() {
    let mut renamed = sync_group("g1");
    renamed.updated_at = 1_700_000_200;
    renamed.name = "Renamed".to_string();
    let mut deleted = sync_group("g1");
    deleted.updated_at = 1_700_000_300;
    deleted.deleted_at = Some(1_700_000_300);

    let (merged, conflicts) = merge_groups(&[renamed], &[deleted.clone()]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].deleted_at, Some(1_700_000_300));
    assert_eq!(
        conflicts, 0,
        "stale rename vs newer deletion propagates silently"
    );

    // The revival direction: rename strictly after the deletion counts.
    let mut late_rename = sync_group("g1");
    late_rename.updated_at = 1_700_000_400;
    late_rename.name = "Late rename".to_string();
    let (merged, conflicts) = merge_groups(&[deleted.clone()], &[late_rename]);
    assert_eq!(merged[0].deleted_at, None);
    assert_eq!(merged[0].name, "Late rename");
    assert_eq!(conflicts, 1);

    let mut entry = sync_entry("e1");
    entry.group_id = Some("g1".to_string());
    let (groups, _) = merge_groups(&[sync_group("g1")], &[deleted]);
    let (entries, _) = merge_entries(&[entry.clone()], &[entry]);
    assert!(groups.iter().all(|group| group.deleted_at.is_some()));
    assert_eq!(entries[0].group_id.as_deref(), Some("g1"));
}

/// Anti-echo: `changed` compares the merged content against the REMOTE
/// snapshot only. Identical content in a different envelope (rev /
/// device_id / generated_at) must NOT trigger an upload.
#[test]
fn snapshot_merge_changed_flag_suppresses_echo() {
    let mut local = sample_snapshot();
    let mut remote = sample_snapshot();
    remote.rev += 6;
    remote.device_id = "device-b".to_string();
    remote.generated_at += 60;

    let merged = merge_snapshots(&local, &remote);
    assert!(!merged.changed);
    assert!(snapshots_equivalent(
        &SyncSnapshot {
            rev: 0,
            device_id: String::new(),
            generated_at: 0,
            entries: merged.entries.clone(),
            groups: merged.groups.clone(),
        },
        &remote
    ));

    // A local-only change makes an upload necessary.
    let mut extra = sync_entry("e-extra");
    extra.updated_at = 1_700_000_999;
    local.entries.push(extra);
    let merged = merge_snapshots(&local, &remote);
    assert!(merged.changed);
    assert_eq!(merged.entries.len(), 3);
}

/// The normalized equivalence ignores envelope metadata but detects any
/// content difference.
#[test]
fn snapshots_equivalent_ignores_envelope_and_detects_content_changes() {
    let mut a = sample_snapshot();
    let mut b = sample_snapshot();
    b.rev += 1;
    b.device_id = "other".to_string();
    b.generated_at += 5;
    assert!(snapshots_equivalent(&a, &b));

    a.entries[0].username = "changed".to_string();
    assert!(!snapshots_equivalent(&a, &b));
    a.entries[0].username = b.entries[0].username.clone();
    a.groups.push(sync_group("g-new"));
    assert!(!snapshots_equivalent(&a, &b));
}

// ------------------------------------------------------------------
// Property tests (P3.6 item 2): commutativity / idempotence / lossless
// union over 100 pseudo-random scenarios from FIXED seeds — no true
// randomness, failures reproduce exactly.
// ------------------------------------------------------------------

fn gen_entry(rng: &mut StdRng, id: &str) -> SyncEntry {
    let updated_at = 1_700_000_000i64 + rng.gen_range(0..86_400);
    let tags = (0..rng.gen_range(0..3usize))
        .map(|i| format!("tag-{}-{i}", rng.gen_range(0..20)))
        .collect();
    SyncEntry {
        url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
        id: id.to_string(),
        title: format!("title-{}", rng.gen_range(0..500)),
        url: rng
            .gen_bool(0.7)
            .then(|| format!("https://{}.example", rng.gen_range(0..500))),
        username: format!("user-{}", rng.gen_range(0..500)),
        password: rng
            .gen_bool(0.9)
            .then(|| format!("pw-{}", rng.gen_range(0..10_000))),
        notes: rng
            .gen_bool(0.3)
            .then(|| format!("notes-{}", rng.gen_range(0..1_000))),
        totp_secret: rng
            .gen_bool(0.2)
            .then(|| format!("JBSW{}", rng.gen_range(0..1_000))),
        tags,
        group_id: rng
            .gen_bool(0.5)
            .then(|| format!("group-{}", rng.gen_range(0..5))),
        created_at: updated_at - rng.gen_range(0..10_000),
        updated_at,
        deleted_at: None,
        custom_fields: vec![],
    }
}

/// Randomly diverge one device's copy: each entry may be edited (bumping
/// updated_at), tombstoned (deleted_at == updated_at — the remove_entry
/// invariant), or dropped (the device never saw it).
fn diverge_entries(rng: &mut StdRng, entries: Vec<SyncEntry>) -> Vec<SyncEntry> {
    let mut diverged = Vec::new();
    for mut entry in entries {
        if !rng.gen_bool(0.9) {
            continue;
        }
        match rng.gen_range(0..4u8) {
            0 => {
                entry.updated_at += rng.gen_range(1..3_600);
                entry.title = format!("edited-{}", rng.gen_range(0..500));
            }
            1 => {
                let deleted_at = entry.updated_at + rng.gen_range(1..3_600);
                entry.updated_at = deleted_at;
                entry.deleted_at = Some(deleted_at);
            }
            _ => {}
        }
        diverged.push(entry);
    }
    diverged
}

#[test]
fn entry_merge_properties_hold_over_100_seeded_scenarios() {
    let mut rng = StdRng::seed_from_u64(0x50CF_5EED_0001);
    for scenario in 0..100 {
        let universe: Vec<SyncEntry> = (0..rng.gen_range(4..20usize))
            .map(|i| gen_entry(&mut rng, &format!("e-{scenario}-{i}")))
            .collect();
        let local = diverge_entries(&mut rng, universe.clone());
        let remote = diverge_entries(&mut rng, universe);

        // Commutativity — including the fingerprint tiebreak path, and
        // the D5 conflict count must be swap-invariant too (the verdict
        // is a pure function of the unordered pair).
        let (ab, conflicts_ab) = merge_entries(&local, &remote);
        let (ba, conflicts_ba) = merge_entries(&remote, &local);
        assert_eq!(ab, ba, "scenario {scenario}: merge(a,b) != merge(b,a)");
        assert_eq!(
            conflicts_ab, conflicts_ba,
            "scenario {scenario}: conflict count not symmetric"
        );

        // Idempotence, and self-merge identity (inputs are sets). A
        // self-merge never conflicts: identical content on both sides
        // falls into the equal-fingerprint / both-deleted non-cases.
        let (remerged, remerge_conflicts) = merge_entries(&ab, &ab);
        assert_eq!(remerged, ab, "scenario {scenario}: not idempotent");
        assert_eq!(
            remerge_conflicts, 0,
            "scenario {scenario}: self-merge counted conflicts"
        );
        let (identity, identity_conflicts) = merge_entries(&local, &local);
        assert_eq!(
            identity,
            sorted(local.clone()),
            "scenario {scenario}: merge(x,x) != x"
        );
        assert_eq!(identity_conflicts, 0);

        // Union preservation: every live input entry survives — live with
        // a monotone updated_at, or as the tombstone that outlived it —
        // and no phantom ids appear.
        for entry in local
            .iter()
            .chain(&remote)
            .filter(|e| e.deleted_at.is_none())
        {
            let merged = ab
                .iter()
                .find(|m| m.id == entry.id)
                .unwrap_or_else(|| panic!("scenario {scenario}: live entry {} lost", entry.id));
            if merged.deleted_at.is_none() {
                assert!(
                    merged.updated_at >= entry.updated_at,
                    "scenario {scenario}: {} regressed updated_at",
                    entry.id
                );
            }
        }
        for merged in &ab {
            assert!(
                local.iter().chain(&remote).any(|e| e.id == merged.id),
                "scenario {scenario}: phantom entry {}",
                merged.id
            );
        }
    }
}

fn gen_group(rng: &mut StdRng, id: &str) -> SyncGroup {
    let updated_at = 1_700_000_000i64 + rng.gen_range(0..86_400);
    SyncGroup {
        id: id.to_string(),
        name: format!("group-name-{}", rng.gen_range(0..200)),
        created_at: updated_at - rng.gen_range(0..10_000),
        updated_at,
        deleted_at: None,
    }
}

fn diverge_groups(rng: &mut StdRng, groups: Vec<SyncGroup>) -> Vec<SyncGroup> {
    let mut diverged = Vec::new();
    for mut group in groups {
        if !rng.gen_bool(0.9) {
            continue;
        }
        match rng.gen_range(0..4u8) {
            0 => {
                group.updated_at += rng.gen_range(1..3_600);
                group.name = format!("renamed-{}", rng.gen_range(0..200));
            }
            1 => {
                let deleted_at = group.updated_at + rng.gen_range(1..3_600);
                group.updated_at = deleted_at;
                group.deleted_at = Some(deleted_at);
            }
            _ => {}
        }
        diverged.push(group);
    }
    diverged
}

#[test]
fn group_merge_properties_hold_over_100_seeded_scenarios() {
    let mut rng = StdRng::seed_from_u64(0x50CF_5EED_0002);
    for scenario in 0..100 {
        let universe: Vec<SyncGroup> = (0..rng.gen_range(2..8usize))
            .map(|i| gen_group(&mut rng, &format!("g-{scenario}-{i}")))
            .collect();
        let local = diverge_groups(&mut rng, universe.clone());
        let remote = diverge_groups(&mut rng, universe);

        let (ab, conflicts_ab) = merge_groups(&local, &remote);
        let (ba, conflicts_ba) = merge_groups(&remote, &local);
        assert_eq!(ab, ba, "scenario {scenario}: merge(a,b) != merge(b,a)");
        assert_eq!(
            conflicts_ab, conflicts_ba,
            "scenario {scenario}: conflict count not symmetric"
        );
        let (remerged, remerge_conflicts) = merge_groups(&ab, &ab);
        assert_eq!(remerged, ab, "scenario {scenario}: not idempotent");
        assert_eq!(remerge_conflicts, 0);
        for group in local
            .iter()
            .chain(&remote)
            .filter(|g| g.deleted_at.is_none())
        {
            assert!(
                ab.iter().any(|m| m.id == group.id),
                "scenario {scenario}: live group {} lost",
                group.id
            );
        }
    }
}

fn sample_snapshot() -> SyncSnapshot {
    let mut e2 = sync_entry("e2");
    e2.updated_at = 1_700_000_200;
    SyncSnapshot {
        rev: 1,
        device_id: "device-a".to_string(),
        generated_at: 1_700_000_000,
        entries: vec![sync_entry("e1"), e2],
        groups: vec![sync_group("g1")],
    }
}
