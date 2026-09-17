//! D3 merge engine: 2-way last-writer-wins with tombstone arbitration.
//!
//! Pure functions over the sync domain types — no database, no keys, no
//! clock. The sync engine (P3.3, next batch) feeds the local rows (converted
//! via [`super::entries_to_sync`]) and the opened remote container snapshot
//! through these, then writes/uploads the result.
//!
//! Arbitration per UUID (D3):
//! 1. Present on one side only (live or tombstone) → taken as-is.
//! 2. Present on both sides: `updated_at` larger wins; on equality the
//!    lexicographically larger content fingerprint wins (symmetric and
//!    deterministic — guarantees `merge(a, b) == merge(b, a)`).
//! 3. Tombstone rule: if the winner carries `deleted_at >= loser.updated_at`
//!    the deletion stands; otherwise the loser's modification is newer than
//!    the winner's deletion, the modification wins and `deleted_at` is
//!    cleared (revival).
//!
//! Tombstones are kept forever in v1 (no GC — D3; a future 90-day GC is
//! noted as an option in the roadmap).

use std::collections::BTreeMap;

use super::container::{entry_fingerprint, group_fingerprint};
use super::{SyncEntry, SyncGroup, SyncSnapshot};

/// Merge of the local state with the remote container snapshot.
///
/// `changed` is computed against the REMOTE snapshot only, with the
/// normalized comparison of [`snapshots_equivalent`] (id-sorted, field-level
/// `PartialEq` — never serialized bytes): `false` means the remote already
/// carries the merged content, so uploading would only echo it back (D3
/// anti-echo rule). Envelope fields (rev / device_id / generated_at) are
/// ignored by the comparison.
#[derive(Debug)]
pub struct MergedSnapshot {
    pub entries: Vec<SyncEntry>,
    pub groups: Vec<SyncGroup>,
    pub changed: bool,
}

/// Merge entry sets by UUID union (D3). Output is id-sorted so both merge
/// directions produce identical orderings.
pub fn merge_entries(local: &[SyncEntry], remote: &[SyncEntry]) -> Vec<SyncEntry> {
    let mut by_id: BTreeMap<&str, SyncEntry> = BTreeMap::new();
    for entry in local {
        by_id.insert(entry.id.as_str(), entry.clone());
    }
    for entry in remote {
        match by_id.get_mut(entry.id.as_str()) {
            Some(local_entry) => {
                let merged = merge_entry_pair(local_entry, entry);
                *local_entry = merged;
            }
            None => {
                by_id.insert(entry.id.as_str(), entry.clone());
            }
        }
    }
    by_id.into_values().collect()
}

/// Merge group sets by UUID union (D3, same arbitration shape as entries).
pub fn merge_groups(local: &[SyncGroup], remote: &[SyncGroup]) -> Vec<SyncGroup> {
    let mut by_id: BTreeMap<&str, SyncGroup> = BTreeMap::new();
    for group in local {
        by_id.insert(group.id.as_str(), group.clone());
    }
    for group in remote {
        match by_id.get_mut(group.id.as_str()) {
            Some(local_group) => {
                let merged = merge_group_pair(local_group, group);
                *local_group = merged;
            }
            None => {
                by_id.insert(group.id.as_str(), group.clone());
            }
        }
    }
    by_id.into_values().collect()
}

/// Merge two full snapshots. See [`MergedSnapshot`] for the `changed`
/// (anti-echo) semantics.
pub fn merge_snapshots(local: &SyncSnapshot, remote: &SyncSnapshot) -> MergedSnapshot {
    let entries = merge_entries(&local.entries, &remote.entries);
    let groups = merge_groups(&local.groups, &remote.groups);
    let changed = !(entries_equivalent(&entries, &remote.entries)
        && groups_equivalent(&groups, &remote.groups));
    MergedSnapshot {
        entries,
        groups,
        changed,
    }
}

/// Normalized snapshot equality: id-sorted, field-level `PartialEq`
/// (review P3: never a serialized-byte comparison). Envelope metadata (rev,
/// device_id, generated_at) is deliberately ignored — content alone defines
/// equivalence for the anti-echo check.
pub fn snapshots_equivalent(a: &SyncSnapshot, b: &SyncSnapshot) -> bool {
    entries_equivalent(&a.entries, &b.entries) && groups_equivalent(&a.groups, &b.groups)
}

/// D3 arbitration for one entry present on both sides.
fn merge_entry_pair(local: &SyncEntry, remote: &SyncEntry) -> SyncEntry {
    let (winner, loser) = lww(local, remote, |entry| entry.updated_at, entry_fingerprint);
    match winner.deleted_at {
        // The winner's deletion is at least as recent as the loser's last
        // modification → the deletion stands.
        Some(deleted_at) if deleted_at >= loser.updated_at => winner.clone(),
        // The loser carries a modification newer than the winner's deletion
        // → the modification wins and the entry revives.
        Some(_) => {
            let mut revived = loser.clone();
            revived.deleted_at = None;
            revived
        }
        // Live modification wins as-is.
        None => winner.clone(),
    }
}

/// D3 arbitration for one group present on both sides (same rule shape as
/// [`merge_entry_pair`]; groups carry tombstones but no secrets).
fn merge_group_pair(local: &SyncGroup, remote: &SyncGroup) -> SyncGroup {
    let (winner, loser) = lww(local, remote, |group| group.updated_at, group_fingerprint);
    match winner.deleted_at {
        Some(deleted_at) if deleted_at >= loser.updated_at => winner.clone(),
        Some(_) => {
            let mut revived = loser.clone();
            revived.deleted_at = None;
            revived
        }
        None => winner.clone(),
    }
}

/// Last-writer-wins with the symmetric fingerprint tiebreak; returns
/// `(winner, loser)`. The tiebreak agrees under argument swap, which is what
/// makes `merge(a, b) == merge(b, a)` hold even on timestamp collisions.
fn lww<'a, T>(
    local: &'a T,
    remote: &'a T,
    updated_at: impl Fn(&T) -> i64,
    fingerprint: impl Fn(&T) -> [u8; 32],
) -> (&'a T, &'a T) {
    if updated_at(local) != updated_at(remote) {
        if updated_at(local) > updated_at(remote) {
            (local, remote)
        } else {
            (remote, local)
        }
    } else if fingerprint(local) >= fingerprint(remote) {
        (local, remote)
    } else {
        (remote, local)
    }
}

/// Group-independent equivalence of two id-keyed item lists (order ignored,
/// field-level `PartialEq` on the values).
fn maps_equivalent<'a, V: PartialEq + 'a>(
    a: impl Iterator<Item = (&'a str, &'a V)>,
    b: impl Iterator<Item = (&'a str, &'a V)>,
) -> bool {
    let left: BTreeMap<&str, &V> = a.collect();
    let right: BTreeMap<&str, &V> = b.collect();
    left.len() == right.len()
        && left
            .iter()
            .all(|(id, value)| right.get(id).is_some_and(|other| value == other))
}

fn entries_equivalent(a: &[SyncEntry], b: &[SyncEntry]) -> bool {
    maps_equivalent(
        a.iter().map(|entry| (entry.id.as_str(), entry)),
        b.iter().map(|entry| (entry.id.as_str(), entry)),
    )
}

fn groups_equivalent(a: &[SyncGroup], b: &[SyncGroup]) -> bool {
    maps_equivalent(
        a.iter().map(|group| (group.id.as_str(), group)),
        b.iter().map(|group| (group.id.as_str(), group)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn sync_entry(id: &str) -> SyncEntry {
        SyncEntry {
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
    /// survive the union.
    #[test]
    fn concurrent_edits_to_different_entries_both_survive() {
        let mut a = sync_entry("e1");
        a.updated_at = 100;
        a.title = "A-edit".to_string();
        let mut b = sync_entry("e2");
        b.updated_at = 200;
        b.title = "B-edit".to_string();

        let merged = merge_entries(&[a.clone()], &[b.clone()]);
        assert_eq!(merged, merge_entries(&[b], &[a]));
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].title, "A-edit");
        assert_eq!(merged[1].title, "B-edit");
    }

    /// Same entry modified at two points in time (LWW): the later edit wins,
    /// in both argument orders.
    #[test]
    fn sequential_edits_to_same_entry_take_the_newer_one() {
        let mut older = sync_entry("e1");
        older.updated_at = 100;
        older.username = "old".to_string();
        let mut newer = sync_entry("e1");
        newer.updated_at = 200;
        newer.username = "new".to_string();

        let merged = merge_entries(&[older.clone()], &[newer.clone()]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].username, "new");
        assert_eq!(merged[0].updated_at, 200);
        assert_eq!(merged, merge_entries(&[newer], &[older]));
    }

    /// One side deletes, the other modifies — decided in BOTH directions:
    /// a deletion at least as recent as the modification stands; an older
    /// deletion loses and the modification revives the entry.
    #[test]
    fn delete_and_modify_arbitrate_symmetrically_both_ways() {
        // Tombstone (300) vs modification (200): deletion wins.
        let mut edited = sync_entry("e1");
        edited.updated_at = 200;
        edited.username = "edited".to_string();
        let mut deleted = sync_entry("e1");
        deleted.updated_at = 300;
        deleted.deleted_at = Some(300);

        let delete_first = merge_entries(&[deleted.clone()], &[edited.clone()]);
        assert_eq!(delete_first, merge_entries(&[edited], &[deleted]));
        assert_eq!(delete_first.len(), 1);
        assert_eq!(delete_first[0].deleted_at, Some(300));

        // Tombstone (300) vs modification (400): modification wins, live.
        let mut edited = sync_entry("e1");
        edited.updated_at = 400;
        edited.username = "edited".to_string();
        let mut deleted = sync_entry("e1");
        deleted.updated_at = 300;
        deleted.deleted_at = Some(300);

        let merged = merge_entries(&[deleted], &[edited]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].deleted_at, None);
        assert_eq!(merged[0].username, "edited");
    }

    /// Equal `updated_at` resolves via the content fingerprint, and the
    /// verdict is identical under argument swap (review P1: the tiebreak
    /// must not depend on parameter position).
    #[test]
    fn equal_updated_at_uses_fingerprint_tiebreak_symmetrically() {
        let mut a = sync_entry("e1");
        a.title = "aaa".to_string();
        let mut b = sync_entry("e1");
        b.title = "bbb".to_string();
        let fingerprint_a = entry_fingerprint(&a);
        let fingerprint_b = entry_fingerprint(&b);
        assert_ne!(fingerprint_a, fingerprint_b);

        let merged = merge_entries(&[a.clone()], &[b.clone()]);
        assert_eq!(merged, merge_entries(&[b], &[a]));
        let expected = if fingerprint_a > fingerprint_b {
            "aaa"
        } else {
            "bbb"
        };
        assert_eq!(merged[0].title, expected);
    }

    /// Group removal does not cascade: the tombstoned group travels in the
    /// merge result while entries keep their (hanging) group_id — the UI
    /// renders those as ungrouped. Group renames arbitrate by the same LWW.
    #[test]
    fn group_tombstone_does_not_cascade_and_lww_applies() {
        let mut renamed = sync_group("g1");
        renamed.updated_at = 1_700_000_200;
        renamed.name = "Renamed".to_string();
        let mut deleted = sync_group("g1");
        deleted.updated_at = 1_700_000_300;
        deleted.deleted_at = Some(1_700_000_300);

        let merged = merge_groups(&[renamed], &[deleted.clone()]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].deleted_at, Some(1_700_000_300));

        let mut entry = sync_entry("e1");
        entry.group_id = Some("g1".to_string());
        let groups = merge_groups(&[sync_group("g1")], &[deleted]);
        let entries = merge_entries(&[entry.clone()], &[entry]);
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

            // Commutativity — including the fingerprint tiebreak path.
            let ab = merge_entries(&local, &remote);
            let ba = merge_entries(&remote, &local);
            assert_eq!(ab, ba, "scenario {scenario}: merge(a,b) != merge(b,a)");

            // Idempotence, and self-merge identity (inputs are sets).
            assert_eq!(
                merge_entries(&ab, &ab),
                ab,
                "scenario {scenario}: not idempotent"
            );
            assert_eq!(
                merge_entries(&local, &local),
                sorted(local.clone()),
                "scenario {scenario}: merge(x,x) != x"
            );

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

            let ab = merge_groups(&local, &remote);
            assert_eq!(
                ab,
                merge_groups(&remote, &local),
                "scenario {scenario}: merge(a,b) != merge(b,a)"
            );
            assert_eq!(
                merge_groups(&ab, &ab),
                ab,
                "scenario {scenario}: not idempotent"
            );
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
}
