# Independent Security Audit Report

> **Date**: 2026-07-18
> **Scope**: PwdVault v1.1.1 release candidate after Phase 1-6 optimization
> **Auditor**: code-auditor agent (automated + manual code review)
> **Verdict**: ✅ **No Critical/High code findings**; release remains prerelease
> until signing, browser E2E, Windows CI, and tag alignment are complete

---

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 2 | 2 fixed |
| Low | 5 | Documented for 1.0.6 follow-up |
| Info | 4 | Positive findings (security controls confirmed) |

**Dependency scan**: cargo audit (0 vulnerabilities in both lockfiles), pnpm
audit (0 known production vulnerabilities), cargo deny passed. One direct
unmaintained dependency is explicitly allowlisted: bincode
`RUSTSEC-2025-0141`, expiry 2026-12-31. The app lockfile also reports 18
unmaintained and 2 unsound upstream/transitive warnings; the Native Host reports
none.

---

## Findings

### VULN-001 [Medium → Fixed] — toast innerHTML XSS

**Location**: `src/utils/toast.ts:112-130`
**Issue**: Pairing code interpolated via `innerHTML`, creating an XSS vector if the code source ever changes.
**Fix**: Changed to `textContent` for the code element. Static markup still uses `innerHTML` (trusted). Committed.

### VULN-002 [Medium → Fixed] — CI action/tool provenance

**Location**: `.github/workflows/release.yml:164, 210`
**Issue**: Removed/unavailable signing actions and best-effort tooling could be
mistaken for completed release controls.
**Fix**: All active actions are SHA-pinned; unavailable Windows signing and
Chrome-store upload actions remain disabled and explicitly block a signed stable
release. Quality/Release gates now run package, audit, and lint checks directly.

### VULN-003 [Low] — clipboardWrite permission (extension)

**Location**: `extensions/chrome/manifest.json:11`
**Note**: Permission is used by content script clipboard writes. Retained as functional dependency.

### VULN-004 [Low] — goToUrl protocol whitelist (extension)

**Location**: `extensions/chrome/src/popup/popup.js:330-339`
**Issue**: No protocol whitelist on user-provided URL before `chrome.tabs.create`.
**Risk**: Low (requires user to click open on a crafted entry URL).
**Planned**: Add `new URL()` + protocol check in 1.0.6.

### VULN-005 [Low] — Windows file ACL not implemented

**Location**: `src-tauri/crates/infrastructure/src/paths.rs:89-95`
**Issue**: Unix has 0700/0600; Windows relies on inherited NTFS permissions.
**Risk**: Same-machine other users could read vault.db (encrypted, but verification metadata is plaintext).
**Status**: Documented in README threat model; ACL implementation deferred per §3.3.

### VULN-006 [Low] — update URL not validated (frontend)

**Location**: `src/components/UpdateNotification.tsx:12-15`
**Issue**: `download_url` from GitHub API passed to `openUrl` without protocol/domain check.
**Risk**: Low (requires MITM on GitHub TLS).
**Planned**: Add URL whitelist in 1.0.6.

### VULN-007 [Low] — bincode 1.x unmaintained

**Location**: `deny.toml:13-16`
**Status**: Allowlisted with reason + expiry (2026-12-31). Migration to bincode 2 planned.

### VULN-008 [Medium → Fixed] — extension popup attribute injection boundary

**Location**: `extensions/chrome/src/popup/popup.js`
**Issue**: The previous `escapeHtml()` implementation escaped text nodes but did
not encode quotes when values were interpolated into HTML attributes.
**Fix**: Quote-aware escaping, escaped entry identifiers/icon text, and DOM node
replacement via parsed markup. Firefox strict `web-ext` lint reports zero
errors, warnings, and notices.

---

## Confirmed Security Controls (Positive Findings)

1. **AES-256-GCM**: OsRng nonce per encryption; AAD = table||id||version
2. **Argon2id**: 64MB/3 iterations/4 parallelism; KdfPolicy pre-derivation validation
3. **HKDF**: Separate info labels for enc_key and mac_key
4. **SecretKey**: ZeroizeOnDrop, no Copy/Clone, Debug redacted
5. **Constant-time comparison**: ct_eq for verification header and API token
6. **VaultSession**: RwLock lease mechanism; keys cleared on lock
7. **Integrity**: HMAC-SHA256 over 4 tables + per-record AAD; same-transaction digest refresh
8. **Anti-downgrade**: AEAD VaultHeader with integrity_required flag
9. **Pairing**: caller-bound, 128-bit nonce, 30s TTL, 5 attempts, rate-limited
10. **Loopback**: 127.0.0.1 only; 8 workers + 64 queue; 10MB body limit; 5s timeout
11. **HTTP parsing**: POST-only, Content-Type required, no Transfer-Encoding, header CR/LF rejection
12. **Token storage**: storage.session preferred; TRUSTED_CONTEXTS enforced
13. **Sender auth**: runtimeId check; content script command allowlist; URL match for secrets
14. **Backup v2**: AEAD over header+nonce+ciphertext; validate-before-write import
15. **CSP**: default-src 'self', no unsafe-inline/eval; connect-src loopback only
16. **Clipboard**: SHA-256 digest comparison; 30s auto-clear; user-replaced content preserved
17. **CI signing gate**: prerelease forced when any platform unsigned

---

## Conclusion

PwdVault v1.0.5 (post Phase 1-6) implements a robust security architecture
with proper cryptographic primitives, careful key lifecycle management, and
multi-layered defense-in-depth. The audit found no blocking vulnerabilities.

**Recommendation**: Code security review does not block an unsigned prerelease.
Do not promote to stable until the remaining boundaries in
`V1.1.1-RELEASE-REPORT.md` are complete. Track VULN-004/005/006/007 in the
next maintenance cycle.
