# Phase 0 Implementation Progress

> **Document**: Release Freeze & Regression Baseline
> **Plan**: PwdVault-Comprehensive-Optimization-Plan-v1.0.5.md §5.0
> **Date**: 2026-07-16
> **Status**: ✅ Complete

---

## Summary

Phase 0 establishes the regression and testing infrastructure needed before
the substantive code changes in Phases 1–6. No database format changes,
no user-facing feature changes, and no business logic modifications were
made in this phase.

**Test results after Phase 0:**
- Rust: 94 passed, 1 ignored (benchmark) — was 81 before
- Frontend: 31 passed — was 27 before
- TypeScript: No errors

---

## Deliverables Checklist

### §5.0.1 — Optimization Content

| Item | Status | Description |
|------|--------|-------------|
| 1. Release freeze | ✅ | `release.yml` now has a `release-gate` job that runs fmt/clippy/test/audit/version-check before any build |
| 2. Fixtures | ✅ | `fixtures.rs` — pre-v1.0.5 + v1.0.5/digest-v3 database fixtures; backup-v1 fixture |
| 3a. Fault injection | ✅ | `test_infra.rs` — `FaultInjector` with committed/uncommitted data verification |
| 3b. Concurrency barriers | ✅ | `test_infra.rs` — `ConcurrencyHarness` with barrier-coordinated stress tests |
| 3c. File permissions | ✅ | `test_infra.rs` — `assert_user_only_file/dir` on Unix |
| 3d. Packaging checks | ✅ | `extensions/tests/verify_package.sh` — symlink + manifest + icon verification |
| 3e. UI multi-window | ✅ | `window-sizes.test.ts` — baseline size tier assertions |
| 4. Threat model | ✅ | `docs/SECURITY-THREAT-MODEL.md` — guarantees, out-of-scope, format history |
| 5. Performance baseline | ✅ | `benchmarks.rs` — 100/1k/5k/10k scale benchmarks (ignored by default) |

### §5.0.3 — Acceptance Criteria

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Each released DB format has a fixture | ✅ | pre-v1.0.5 + v1.0.5/dv3 in `fixtures.rs` |
| Fixtures contain no real credentials | ✅ | All use "fixture-*" synthetic data |
| Tests and perf results repeatable in CI | ✅ | `quality.yml` runs on every PR/push |
| Threat model describes supported/unsupported scenarios | ✅ | `SECURITY-THREAT-MODEL.md` §2-4 |
| Stable release flow explicitly blocked | ✅ | `release-gate` job in `release.yml` |

---

## Files Created

| File | Purpose |
|------|---------|
| `src-tauri/src/fixtures.rs` | Database/backup format test fixtures |
| `src-tauri/src/test_infra.rs` | Fault injection, concurrency, permission test harness |
| `src-tauri/src/benchmarks.rs` | Performance baseline benchmarks |
| `src/__tests__/window-sizes.test.ts` | UI window size baseline |
| `extensions/tests/verify_package.sh` | Extension packaging verification script |
| `.github/workflows/quality.yml` | PR/push quality gate workflow |
| `docs/SECURITY-THREAT-MODEL.md` | Security threat model & format evolution |
| `docs/PHASE0-PROGRESS.md` | This document |

## Files Modified

| File | Change |
|------|--------|
| `src-tauri/src/lib.rs` | Added module registrations for fixtures, test_infra, benchmarks |
| `.github/workflows/release.yml` | Replaced security-audit with comprehensive release-gate; fixed Firefox packaging (staging copy instead of `--symlinks`); wired in verify_package.sh |
| `VERSION` | Normalized from 4-part (`1.0.5.0`) to 3-part (`1.0.5`) |
| `scripts/bump-version.sh` | Updated to write 3-part VERSION (was 4-part) |
| `src-tauri/src/**/*.rs` | `cargo fmt` applied (all files reformatted to rustfmt standard) |

---

## Known Issues (Deferred to Later Phases)

1. **Pre-existing clippy warnings in unchanged files** — ~36 clippy lints exist in pre-Phase-0 code (e.g., `needless_borrows_for_generic_args`, `unnecessary_map_or`). These will be fixed in their respective phases or in a dedicated cleanup commit.
2. **Fault injection uses `drop()` not `SIGKILL`** — Current `FaultInjector` simulates crash via transaction abort (drop without commit). True crash-consistency testing (process kill) is a Phase 1 deliverable.
3. **UI window-size test is structural** — The current test asserts on constants, not rendering. Phase 4 will add visual regression tests.
4. **Windows ACL verification** — Only Unix permission checks are implemented. Windows ACL tests will be added in Phase 2.
5. **Firefox manifest `allowed_extensions` bug** — Known issue in `native_host_setup.rs`, fix scheduled for Phase 5.

---

## Code Review Findings (Resolved)

| Finding | Severity | Resolution |
|---------|----------|------------|
| Fixture test flaky under parallel load | Blocker | Switched from adaptive KDF to fixed params |
| `let key = key` clippy error | Blocker | Removed redundant local binding |
| `b64.encode(&salt)` clippy error | Blocker | Removed unnecessary borrow |
| Unused import | Blocker | Removed |
| `cargo fmt --check` fails | Blocker | Ran `cargo fmt` on entire crate |
| VERSION file 4-part vs 3-part inconsistency | Blocker | Normalized to 3-part, updated bump-version.sh |
| Firefox release zip uses `--symlinks` | Warning | Fixed to use staging copy; wired verify_package.sh |
| Clipboard guarantee overstated | Nit | Softened G8 wording in threat model |
| dv1/dv2 listed as "dev" without clarity | Nit | Clarified as "dev-only (never released)" |
| Benchmark median hardcoded to index 1 | Nit | Changed to `times.len()/2` |
