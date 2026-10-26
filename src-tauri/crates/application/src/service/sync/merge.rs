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
//!
//! # Conflict counting (v1.6.0 D5)
//!
//! One merged pair counts as a conflict — LWW resolved a genuine ambiguity
//! by discarding one side's data — if and only if:
//!
//! 1. **Delete-then-modify**: one side is a tombstone, the other is live,
//!    AND the live side's `updated_at` is strictly greater than the
//!    tombstone's `deleted_at` (the edit happened after the deletion — LWW
//!    discarded a real edit or revived a real deletion).
//! 2. **Timestamp collision with diverged content** (both sides live):
//!    equal `updated_at` and different fingerprints (the tiebreak was forced
//!    to arbitrate a genuine ambiguity).
//!
//! Deliberately NOT counted: two live sides with different timestamps
//! (sequential edits are LWW design behavior); identical fingerprints
//! (idempotent re-adds); both sides deleted (convergence); and **stale-copy
//! deletion propagation** — a live side whose `updated_at` is ≤ the
//! tombstone's `deleted_at`. That last case is the reason the comparison is
//! STRICT: `remove_entry` stamps the tombstone with
//! `updated_at = deleted_at`, so a peer's outdated live copy (last written
//! no later than the deletion moment) travels through the `>=` branch as
//! ordinary deletion propagation; a non-strict comparison would report
//! hundreds of phantom conflicts per bulk trash cleanup. The `==` boundary
//! (same-second tombstone-vs-live) is propagation by this definition — the
//! two cases are indistinguishable without a three-way baseline, which is a
//! declared non-goal.
//!
//! **Known blind spot** (recorded honestly): "modify-before-delete" — an
//! edit that predates a later deletion and is discarded when the deletion
//! propagates — is indistinguishable from stale-copy propagation in a 2-way
//! merge without a snapshot baseline, and is NOT counted either.
//!
//! The D5 criteria matrix and the symmetry/idempotence property tests live
//! in [`super::tests_merge`] (moved there in v1.6.0 when this file hit the
//! 800-line ceiling); the engine-level propagation pins live in
//! [`super::tests_conflicts`].

use std::collections::BTreeMap;

use zeroize::{Zeroize, ZeroizeOnDrop};

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
///
/// SEC-M3: defined in this file (mod.rs only re-exports it) and part of the
/// plaintext domain — dropped merges wipe their `SyncEntry`/`SyncGroup`
/// contents. Never debug-log it, and take fields with `mem::take` instead of
/// moving them out.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct MergedSnapshot {
    pub entries: Vec<SyncEntry>,
    pub groups: Vec<SyncGroup>,
    pub changed: bool,
    /// v1.6.0 (D5): pairs where LWW resolved a genuine ambiguity (see the
    /// module-level "Conflict counting" section for the exact criteria).
    /// `u32` zeroizes like the rest of the struct; the engine persists the
    /// per-cycle count into `SyncState.last_conflict_count`.
    pub conflicts: u32,
}

/// Merge entry sets by UUID union (D3). Output is id-sorted so both merge
/// directions produce identical orderings. Returns the merged rows plus the
/// D5 conflict count (entries arbitrated by a genuine LWW ambiguity).
pub fn merge_entries(local: &[SyncEntry], remote: &[SyncEntry]) -> (Vec<SyncEntry>, u32) {
    let mut by_id: BTreeMap<&str, SyncEntry> = BTreeMap::new();
    for entry in local {
        by_id.insert(entry.id.as_str(), entry.clone());
    }
    let mut conflicts = 0u32;
    for entry in remote {
        match by_id.get_mut(entry.id.as_str()) {
            Some(local_entry) => {
                let (merged, conflict) = merge_entry_pair(local_entry, entry);
                conflicts += u32::from(conflict);
                *local_entry = merged;
            }
            None => {
                by_id.insert(entry.id.as_str(), entry.clone());
            }
        }
    }
    (by_id.into_values().collect(), conflicts)
}

/// Merge group sets by UUID union (D3, same arbitration shape as entries).
/// Returns the merged rows plus the D5 conflict count.
pub fn merge_groups(local: &[SyncGroup], remote: &[SyncGroup]) -> (Vec<SyncGroup>, u32) {
    let mut by_id: BTreeMap<&str, SyncGroup> = BTreeMap::new();
    for group in local {
        by_id.insert(group.id.as_str(), group.clone());
    }
    let mut conflicts = 0u32;
    for group in remote {
        match by_id.get_mut(group.id.as_str()) {
            Some(local_group) => {
                let (merged, conflict) = merge_group_pair(local_group, group);
                conflicts += u32::from(conflict);
                *local_group = merged;
            }
            None => {
                by_id.insert(group.id.as_str(), group.clone());
            }
        }
    }
    (by_id.into_values().collect(), conflicts)
}

/// Merge two full snapshots. See [`MergedSnapshot`] for the `changed`
/// (anti-echo) and `conflicts` (D5) semantics.
pub fn merge_snapshots(local: &SyncSnapshot, remote: &SyncSnapshot) -> MergedSnapshot {
    let (entries, entry_conflicts) = merge_entries(&local.entries, &remote.entries);
    let (groups, group_conflicts) = merge_groups(&local.groups, &remote.groups);
    let changed = !(entries_equivalent(&entries, &remote.entries)
        && groups_equivalent(&groups, &remote.groups));
    MergedSnapshot {
        entries,
        groups,
        changed,
        conflicts: entry_conflicts.saturating_add(group_conflicts),
    }
}

/// Normalized snapshot equality: id-sorted, field-level `PartialEq`
/// (review P3: never a serialized-byte comparison). Envelope metadata (rev,
/// device_id, generated_at) is deliberately ignored — content alone defines
/// equivalence for the anti-echo check.
pub fn snapshots_equivalent(a: &SyncSnapshot, b: &SyncSnapshot) -> bool {
    entries_equivalent(&a.entries, &b.entries) && groups_equivalent(&a.groups, &b.groups)
}

/// D5 conflict verdict for one pair present on both sides. A pure function of
/// the UNORDERED pair — it never inspects which side won the LWW — so the
/// count is identical under argument swap (pinned by the property tests).
///
/// `same_content` is the precomputed fingerprint equality (fingerprints are
/// typed per row kind, so the callers pass the comparison instead of this
/// core reaching into both fingerprint functions).
fn pair_is_conflict(
    a_updated_at: i64,
    a_deleted_at: Option<i64>,
    b_updated_at: i64,
    b_deleted_at: Option<i64>,
    same_content: bool,
) -> bool {
    match (a_deleted_at, b_deleted_at) {
        // Both tombstones: two copies of the same deletion converge — never
        // a conflict.
        (Some(_), Some(_)) => false,
        // Both live: only the forced tiebreak (equal timestamps, divergent
        // content) counts. Sequential edits and identical re-adds are LWW
        // design behavior, not data loss.
        (None, None) => a_updated_at == b_updated_at && !same_content,
        // One tombstone, one live: conflict iff the live side was modified
        // STRICTLY after the deletion moment. `<=` is stale-copy deletion
        // propagation (see the module docs — remove_entry stamps
        // updated_at = deleted_at), which must stay silent.
        (Some(tombstone_deleted_at), None) => b_updated_at > tombstone_deleted_at,
        (None, Some(tombstone_deleted_at)) => a_updated_at > tombstone_deleted_at,
    }
}

/// D3 arbitration for one entry present on both sides. Returns the merged
/// row plus the D5 conflict flag.
fn merge_entry_pair(local: &SyncEntry, remote: &SyncEntry) -> (SyncEntry, bool) {
    let conflict = pair_is_conflict(
        local.updated_at,
        local.deleted_at,
        remote.updated_at,
        remote.deleted_at,
        entry_fingerprint(local) == entry_fingerprint(remote),
    );
    let (winner, loser) = lww(local, remote, |entry| entry.updated_at, entry_fingerprint);
    let merged = match winner.deleted_at {
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
    };
    (merged, conflict)
}

/// D3 arbitration for one group present on both sides (same rule shape as
/// [`merge_entry_pair`]; groups carry tombstones but no secrets). Returns
/// the merged row plus the D5 conflict flag.
fn merge_group_pair(local: &SyncGroup, remote: &SyncGroup) -> (SyncGroup, bool) {
    let conflict = pair_is_conflict(
        local.updated_at,
        local.deleted_at,
        remote.updated_at,
        remote.deleted_at,
        group_fingerprint(local) == group_fingerprint(remote),
    );
    let (winner, loser) = lww(local, remote, |group| group.updated_at, group_fingerprint);
    let merged = match winner.deleted_at {
        Some(deleted_at) if deleted_at >= loser.updated_at => winner.clone(),
        Some(_) => {
            let mut revived = loser.clone();
            revived.deleted_at = None;
            revived
        }
        None => winner.clone(),
    };
    (merged, conflict)
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
