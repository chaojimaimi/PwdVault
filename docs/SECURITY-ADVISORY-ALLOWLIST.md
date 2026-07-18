# Security Advisory Allowlist

> **Source**: Phase 6 Step 5 (§5.6.4)
> **Config**: `deny.toml` `[advisories].ignore`
> **Policy**: Each ignored RUSTSEC advisory must have a reason, an owner, and
> an expiry date. Expired entries cause `cargo deny check` to fail.

## Active allowlist

| RUSTSEC ID | Package | Reason | Expiry | Owner |
|------------|---------|--------|--------|-------|
| RUSTSEC-2025-0141 | bincode 1.x | Unmaintained; used for redb value serialization and historical-format compatibility; no drop-in replacement; migration to bincode 2 or postcard planned | 2026-12-31 | backend |

## Review process

1. On each `cargo deny check` run in CI, expired entries fail the build.
2. To add a new ignore: append to `deny.toml`, add a row here, and open a PR
   explaining why the advisory cannot be fixed immediately.
3. To remove an ignore: delete from `deny.toml` and this table after the
   vulnerable dependency is upgraded or replaced.

## Known transitive warnings

`deny.toml` uses `unmaintained = "workspace"`: unmaintained direct workspace
dependencies remain blocking, while upstream/transitive warnings stay visible
in `cargo audit`. On 2026-07-18 the application lockfile reported 18
unmaintained and 2 unsound warnings inherited through Tauri/Wry (`gtk-rs` GTK3
on Linux and the old selector/urlpattern closure); the Native Host reported no
warnings. `anyhow` was upgraded to 1.0.103 to remove the independently fixable
`RUSTSEC-2026-0190`. These warning counts are recorded in each release closure
and must be reviewed whenever Tauri updates its dependency closure; actual
vulnerability findings remain release-blocking.
