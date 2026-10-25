# Security Advisory Allowlist

> **Source**: Phase 6 Step 5 (§5.6.4)
> **Config**: `deny.toml` `[advisories].ignore`
> **Policy**: Each ignored RUSTSEC advisory must have a reason, an owner, and
> an expiry date. Expired entries cause `cargo deny check` to fail.

## Active allowlist

| RUSTSEC ID | Package | Reason | Expiry | Owner |
|------------|---------|--------|--------|-------|
| RUSTSEC-2025-0141 | bincode 2.0.1 | Unmaintained — advisory is crate-level (no patched version), covers 1.x and 2.x alike, so the v1.3.0 swap to the final 2.0.1 API cannot clear it. Kept: golden byte fixtures pin the legacy disk format and a single serialization seam (`crypto::codec` bc_serialize/bc_deserialize) means a postcard migration touches one place. Re-evaluate on a real bincode CVE or the next format-level development | 2027-10-31 | backend |
| RUSTSEC-2026-0367 / 0368 / 0369 | zip 4.6.1 | Vulnerable code path is tauri-plugin-updater's update-archive extraction — symlink permission escape (`ZipStreamReader::extract`), plus SUID/SGID-bit preservation (0367) and unconfined symlink targets (0368). Exploitation requires first breaking the minisign signature chain (trust anchor is byte-pinned by golden_contract in CI) or an https downgrade. **Upstream fact (crates.io, verified 2026-10-25)**: every released tauri-plugin-updater version — the whole 2.x line incl. 2.14.0 (v1.4.0's target) and the 3.0.0-alpha.3 pre-release — pins `zip ^4`; a zip >= 9 does not exist anywhere in the plugin ecosystem, so the original "clear this with the updater bump" premise was incorrect. v1.4.0 still modernized the plugin to the 2.x latest (2.11.0 → 2.14.0, wry 0.54 → 0.57) and the allowlist rides on. Trigger: remove this entry in the next minor once any Tauri version line ships zip >= 9 | 2027-06-30 | backend |

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
