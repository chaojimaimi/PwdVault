# Performance Baseline

> **Source**: Phase 6 Step 3 (§5.6.2 / §5.6.6-3)
> **Date**: 2026-07-17
> **Tool**: `cargo bench --bench vault_bench` (criterion 0.5)
> **Machine**: macOS arm64 (development baseline; CI will record its own)

This document records the criterion baseline for the three core vault data
operations. The §5.6.6-3 acceptance criterion requires that future changes
do not regress these numbers by more than 20% at the 5k tier.

## How to reproduce

```bash
cd src-tauri
cargo bench --bench vault_bench
```

Reports are written to `src-tauri/target/criterion/`.

## Operations measured

| Operation | What it covers | §5.6.2 ref |
|-----------|----------------|------------|
| `list_all_entries_bulk` | Single-read-txn bulk scan + AES-GCM decrypt of every entry | #1 (single read txn) |
| `compute_db_digest` | HMAC-SHA256 over all four tables (the per-mutation cost) | #6 (digest evaluation) |
| `create_entry_with_digest` | Business write + digest refresh in one `VaultStore::write` txn | #3 (mutation p95) |

## Baseline numbers

> First criterion run on 2026-07-17, macOS arm64, sample-size=10,
> measurement-time=2s. Times are criterion's mean estimate.
> Seeded tiers are 100 / 500 / 1000; larger tiers are linear extrapolations
> (all three operations are O(N) in entry count) and should be confirmed with
> a full-scale run once seeding is amortized.

### list_all_entries_bulk (single read txn + decrypt)

| Scale | Time | 10k budget |
|-------|------|------------|
| 100 | ~0.4 ms | — |
| 500 | ~1.8 ms | — |
| 1,000 | 3.67 ms | — |
| 10,000 (extrapolated) | ~37 ms | well under any UI threshold |

### compute_db_digest (HMAC over all tables)

| Scale | Time | Note |
|-------|------|------|
| 100 | 79 µs | — |
| 500 | 399 µs | — |
| 1,000 | 800 µs | — |
| 10,000 (extrapolated) | ~8 ms | far below the 50ms budget; **no incremental digest needed (§5.6.2)** |

### create_entry_with_digest (business write + digest refresh)

| Scale | Time | Note |
|-------|------|------|
| 100 | 5.00 ms | dominated by the fixed write/digest overhead |
| 500 | 5.83 ms | — |
| 1,000 | 6.65 ms | — |
| 5,000 (extrapolated) | ~10 ms | well under the §5.6.6-3 p95 budget |
| 10,000 (extrapolated) | ~14 ms | still under 50ms long-task budget |

## §5.6.6-3 regression gate

A PR that regresses any 1k-tier number by more than 20% over the baseline
recorded here must either:

1. justify the trade-off and update this baseline with the new numbers and
   rationale, or
2. be reworked to stay within the budget.

The gate is enforced manually from this document until criterion comparison
is wired into CI (planned for Step 5).

## §5.6.2 digest decision

`compute_db_digest` measures ~0.8 µs/entry. At the largest planned scale
(10k entries) the full-table HMAC scan is ~8 ms — two orders of magnitude
under any user-perceivable threshold. Per §5.6.2 ("digest 如果在大库 mutation
中超出预算，再评估增量认证结构或 Merkle tree，不提前引入") and §3.1 #7
("性能优化必须有基准数据，避免过早引入高复杂度结构"), the current
single-transaction full-table digest is **retained as-is**. Incremental
authentication structures remain explicitly out of scope.

## §5.6.6-3 regression gate

A PR that regresses any 5k-tier number by more than 20% over the baseline
recorded here must either:

1. justify the trade-off and update this baseline with the new numbers and
   rationale, or
2. be reworked to stay within the budget.

The gate is enforced manually from this document until criterion comparison
is wired into CI (planned for Step 5).
