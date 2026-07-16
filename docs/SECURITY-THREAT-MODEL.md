# PwdVault Security Threat Model & Format Evolution

> **Document date**: 2026-07-16
> **Applicable version**: v1.0.5 (pre-optimization)
> **Status**: Phase 0 baseline — establishes the security boundary before
> the Comprehensive Optimization Plan is applied.

---

## 1. Purpose

This document defines:

1. **What PwdVault protects against** (security guarantees).
2. **What PwdVault does NOT protect against** (explicitly out of scope).
3. **Database and backup format evolution history** — each released format,
   how to detect it, and how migration works.
4. **Threat actors and attack surfaces** considered in the optimization plan.

---

## 2. Security Guarantees (In Scope)

| # | Guarantee | How provided |
|---|-----------|-------------|
| G1 | Vault file confidentiality at rest | AES-256-GCM on all entries and groups; only the entry/group `id` (UUID) is plaintext |
| G2 | Password verification without key storage | Argon2id KDF + constant-time comparison of encrypted verification header |
| G3 | Detection of offline tampering with vault data | HMAC-SHA256 digest over all user-data tables (entries, groups, settings, vault), stored with versioning |
| G4 | Subkey separation | HKDF-SHA256 derives independent enc_key and mac_key from master_key |
| G5 | Key erasure on lock/quit | Encryption key and MAC key are zeroized on lock and application exit |
| G6 | Bounded brute-force attempts | Rate limiting: 5 failed unlock attempts → 60s lockout |
| G7 | Encrypted backup portability | `.pvault` backup files use an independent export password and separate Argon2id derivation |
| G8 | Clipboard auto-clear (best-effort) | Plaintext password in clipboard is cleared after 30 seconds via a JS timer. Phase 3 will replace the JS closure approach with native pasteboard sequence detection. |

---

## 3. Explicitly Out of Scope

PwdVault is a **local-first** password manager. The following threats are
NOT defended against in the current or planned architecture:

| # | Threat | Rationale |
|---|--------|-----------|
| O1 | Malware with full control of the user's session | Once an attacker runs code as the user, they can read process memory, hook syscalls, and extract keys. This is true of all local password managers without a TPM/secure enclave. |
| O2 | Hardware-level attacks (keyloggers, DMA, cold boot) | Requires hardware defenses (TPM, secure boot) outside the scope of a user-space application. |
| O3 | Process memory dumps / debugger attachment | The enc_key and mac_key live in process memory while the vault is unlocked. A debugger or `gcore` can extract them. |
| O4 | Full-database snapshot rollback | An attacker with file-system access can restore a complete copy of `vault.db` AND the digest. Since the digest is inside the DB, a complete old copy passes integrity verification. Detecting this requires an external trust anchor (OS Keychain / DPAPI). Deferred. |
| O5 | Side-channel timing attacks on local HTTP API | The HTTP server binds to 127.0.0.1 only. We do not defend against local timing side-channels from other processes. |
| O6 | Network-level attacks on the update check | The update check is best-effort; it does not download or execute code. A MITM could suppress update notifications but cannot compromise the vault. |

---

## 4. Threat Actors

| Actor | Capability | Relevant? |
|-------|-----------|-----------|
| **Curious user** sharing the machine | Can read the vault file, tries to guess master password | ✅ G1, G2, G6 |
| **Offline attacker** with a copy of vault.db | Tries to brute-force master password; modifies/deletes/swaps records | ✅ G1, G3 |
| **Malicious browser extension** (different extension) | Tries to access the HTTP API on 127.0.0.1:17429 | ✅ Auth boundary (NM pairing) |
| **Compromised content script** in a web page | Tries to read credentials for other domains | ✅ Sender authorization (Phase 5) |
| **Resource exhaustion attacker** | Crafts a `.pvault` with extreme KDF params to OOM the app on import | ✅ KDF limits (Phase 2) |
| **Malware with user-level code execution** | Full access to process memory | ❌ O1 |

---

## 5. Attack Surfaces

### 5.1 Vault File (vault.db)

- **Confidentiality**: AES-256-GCM encryption of all entries and groups.
  The encryption key is derived via Argon2id from the master password,
  then split via HKDF into enc_key (encryption) and mac_key (integrity).
- **Integrity**: HMAC-SHA256 over all user-data tables with domain tags.
  Current digest version: 3.

**Known weakness (Phase 1 target)**: The business write and the digest
refresh are in separate redb transactions. A crash between them leaves
the digest stale, causing a spurious integrity failure on next unlock.
The digest can also be bypassed by deleting the digest row (which
triggers migration and re-baselining rather than failure).

### 5.2 Backup Files (.pvault)

- **Format**: JSON envelope containing base64-encoded salt, nonce, and
  AES-256-GCM ciphertext. Version 1.
- **KDF**: Argon2id with parameters stored in the envelope. No upper
  bounds are enforced on import (Phase 2 target).
- **No AAD**: The GCM tag authenticates only the ciphertext, not the
  envelope header. A Phase 2 improvement adds AAD over the canonical
  header.

### 5.3 Browser Extension HTTP API

- **Transport**: HTTP on 127.0.0.1:17429 (loopback only).
- **Authentication**: Bearer token obtained via pairing (6-digit code
  displayed in desktop app).
- **Known weakness (Phase 5 target)**: No caller binding — any extension
  that knows the token can access all entries. Content script URL
  requests are not validated against `sender.tab.url`.

### 5.4 Update Check

- Queries GitHub Releases API for newer versions.
- Does not download or execute code.
- **Known weakness (Phase 3 target)**: Runs regardless of the
  `check_updates` setting.

---

## 6. Database Format Evolution

### Version History

| Format version | App version | Outer storage | Inner encryption | Integrity | HKDF |
|---------------|-------------|---------------|-----------------|-----------|------|
| **pre-v1.0.5** | v1.0.0–v1.0.4 | `bincode(PasswordEntry)` plaintext | `encrypted_password` via master_key | None | No — master_key used directly |
| **v1.0.5/dv1** | dev-only (never released) | `seal_entry` (AES-GCM) | `encrypted_password` via enc_key | HMAC v1 (entries only) | Yes |
| **v1.0.5/dv2** | dev-only (never released) | `seal_entry` | `encrypted_password` via enc_key | HMAC v2 (all tables) | Yes |
| **v1.0.5/dv3** | v1.0.5 release | `seal_entry` | `encrypted_password` via enc_key | HMAC v3 (all tables + inner re-encryption) | Yes |

### Detection Logic

```
On unlock:
  1. Derive master_key from password via Argon2id
  2. Derive enc_key, mac_key via HKDF
  3. Check META table for db_digest:
     - No digest → pre-v1.0.5 → trigger migration
     - Digest version ≠ 3 → stale build → trigger migration
     - Digest version = 3 → verify_integrity
  4. Migration:
     - Decrypt inner fields with master_key, re-encrypt with enc_key
     - Re-seal outer blob via seal_entry
     - Establish fresh digest baseline (v3)
```

### Backup Format History

| Version | Structure | KDF | AAD |
|---------|-----------|-----|-----|
| **v1** (current) | JSON: `{version, created_at, salt, kdf_*, nonce, data}` | Argon2id (params in envelope) | None |

**Phase 2 target**: v2 envelope with:
- Canonical header as AAD
- KDF parameter validation
- Magic number
- Resource limits on import

### Migration Safety

When migration modifies the database format:

1. **Before Phase 1**: Migration can fail mid-way because business writes
   and digest updates are in separate transactions. A crash during
   migration could leave entries half-migrated.
2. **Phase 1 fix**: All migration steps will be in a single transaction
   with the digest update. A pre-migration backup of the original DB
   file will be created before any modification.
3. **Phase 2 fix**: Migration will be explicitly triggered by version
   detection, not by absence of a digest. An AEAD-authenticated header
   will prevent version downgrade.

---

## 7. Key Lifecycle

```
User enters master password
    │
    ▼
Argon2id(password, salt) → master_key [32 bytes]
    │
    ├── verified against encrypted_verification_header
    │
    ▼ (if valid)
HKDF-SHA256(master_key, salt) → enc_key, mac_key
    │
    ├── enc_key → KeyStore (Mutex<Option<[u8;32]>>)
    ├── mac_key → AppState.mac_key (Mutex<Option<[u8;32]>>)
    │
    ▼ (vault is now unlocked)
    │
    ├── operations use enc_key for encrypt/decrypt
    ├── mutations refresh digest using mac_key
    │
    ▼ (lock or auto-lock or quit)
    │
    enc_key.zeroize()
    mac_key.zeroize()
    last_activity = None
```

**Phase 1 target**: Wrap keys in `ZeroizeOnDrop<SecretKey>` rather than
bare `[u8; 32]` with manual zeroize calls. Move key publication to
after all verification completes.

---

## 8. Security Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-03-26 | AES-256-GCM + Argon2id chosen | Industry-standard authenticated encryption + memory-hard KDF |
| 2026-04-01 | HKDF subkey derivation added | Separates encryption and integrity keys |
| 2026-07-04 | Metadata encryption (seal_entry) | Encrypts all entry fields (title, URL, username, tags) — not just password |
| 2026-07-04 | HMAC digest over all tables | Detects tampering beyond record-level GCM tag |
| 2026-07-04 | Split get_entry_meta / get_entry_secret | Minimizes plaintext exposure — metadata fetch does not decrypt password |
| 2026-07-16 | **Release freeze** (this document) | Prevent stable release until P0 issues resolved |
