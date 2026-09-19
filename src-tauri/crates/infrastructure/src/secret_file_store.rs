//! File-backed credential store for cloud-sync secrets on platforms without
//! a Keychain (P3.2): a single 0600 JSON file, written atomically (temp file
//! then rename). Compiled on every platform so its unit tests run in CI;
//! only non-macOS builds USE it as the platform default.
//!
//! Storage model (plan C r3, pinned — exactly one legal shape):
//!
//! - The JSON file maps each account to a STORED STRING. Legacy stores hold
//!   bare base64; on Windows every value is DPAPI-protected and stored as
//!   `"dpapi1:" + base64(protected-blob)` (`:` is not in the STANDARD base64
//!   alphabet, so the prefix can never collide with a legacy value).
//! - Encoding happens ONLY on the write boundary ([`encode_stored_value`]):
//!   Windows protects every value (any write migrates the whole file to
//!   `dpapi1:`), other platforms keep the bare base64 this store has always
//!   written (on-disk bytes unchanged for existing installs).
//! - Decoding happens ONLY per entry, when a value is actually read
//!   ([`parse_stored_value`]). The map is never eagerly decoded, so one
//!   entry this platform cannot interpret (a `dpapi1:` value read on
//!   non-Windows → `SecretStoreError::Unavailable`) can never poison the
//!   whole file.
//! - The non-Windows write path operates on the RAW stored-string map and
//!   replaces only the target account, so foreign `dpapi1:` entries survive
//!   a Linux/Windows-shared profile byte-for-byte.

use std::collections::HashMap;

use crate::keychain::{SecretStore, SecretStoreError};

/// Prefix marking DPAPI-protected values (Windows write path only).
const DPAPI1_PREFIX: &str = "dpapi1:";

/// 0600 JSON file secret store (P3.2, non-macOS `platform_sync_default`).
///
/// Writes go through a temp file + rename so a crash never leaves a
/// truncated store behind, and every operation is serialized by an internal
/// mutex: `set`/`delete` span a file read and an atomic rename, and the
/// desktop IPC thread and the HTTP server thread can call concurrently —
/// without the lock, one rename would silently drop the other thread's
/// just-written update (atomic rename prevents tearing, not lost updates).
pub struct FileSecretStore {
    path: std::path::PathBuf,
    io_lock: std::sync::Mutex<()>,
}

impl FileSecretStore {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            io_lock: std::sync::Mutex::new(()),
        }
    }

    fn lock_io(&self) -> std::sync::MutexGuard<'_, ()> {
        self.io_lock
            .lock()
            .expect("sync credential file lock poisoned")
    }

    /// Read the file as the RAW stored-string map — no decoding here, so an
    /// entry this platform cannot interpret stays intact for its home
    /// platform.
    fn read_raw(&self) -> Result<HashMap<String, String>, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(e) => return Err(format!("cannot read credential file: {e}")),
        };
        serde_json::from_slice(&bytes).map_err(|e| format!("corrupt credential file: {e}"))
    }

    /// Atomically persist a raw stored-string map (values are already in
    /// their platform's stored form — encoding happened at the call site).
    fn write_raw(&self, raw: &HashMap<String, String>) -> Result<(), String> {
        let bytes = serde_json::to_vec(raw).map_err(|e| format!("serialize error: {e}"))?;

        // Atomic replace through a same-directory temp file (0600), so a
        // crash mid-write cannot truncate the previous store.
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "credential path has no parent".to_string())?;
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create credential dir: {e}"))?;
        let temp = tempfile_in(parent)?;
        std::fs::write(&temp, &bytes).map_err(|e| format!("cannot write credential file: {e}"))?;
        restrict_permissions(&temp);
        std::fs::rename(&temp, &self.path)
            .map_err(|e| format!("cannot persist credential file: {e}"))?;
        restrict_permissions(&self.path);
        Ok(())
    }
}

/// Decode ONE stored string to plaintext bytes (the per-entry lazy decode).
///
/// `dpapi1:` values only decrypt on Windows; anywhere else they yield
/// `SecretStoreError::Unavailable` with a message that names the source
/// platform (never a generic "corrupt file" error, and never internal
/// detail). A plain-base64 value that fails to decode is a genuinely
/// damaged entry and reports as corrupt — per entry only.
fn parse_stored_value(stored: &str) -> Result<Vec<u8>, SecretStoreError> {
    use base64::Engine;
    if let Some(blob) = stored.strip_prefix(DPAPI1_PREFIX) {
        #[cfg(windows)]
        {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(blob.as_bytes())
                .map_err(|_| corrupt_entry_error())?;
            return dpapi::unprotect(&bytes);
        }
        #[cfg(not(windows))]
        {
            let _ = blob;
            return Err(SecretStoreError::Unavailable(
                "this credential was encrypted by the Windows version of PwdVault \
                 and cannot be read on this platform"
                    .to_string(),
            ));
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(stored.as_bytes())
        .map_err(|_| corrupt_entry_error())
}

/// Encode plaintext bytes to their stored form (the write-boundary encode).
/// Windows DPAPI-protects every value; other platforms keep the bare base64
/// this store has always written.
fn encode_stored_value(value: &[u8]) -> Result<String, SecretStoreError> {
    #[cfg(windows)]
    {
        use base64::Engine;
        let blob = dpapi::protect(value)?;
        Ok(format!(
            "{DPAPI1_PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(blob)
        ))
    }
    #[cfg(not(windows))]
    {
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(value))
    }
}

fn corrupt_entry_error() -> SecretStoreError {
    SecretStoreError::Unavailable("corrupt credential file entry".to_string())
}

/// Create a unique temp file inside `dir` with a deterministic suffix.
fn tempfile_in(dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut name = String::from(".sync-secrets-");
    for _ in 0..12 {
        let mut byte = [0u8; 1];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut byte);
        name.push(CHARS[(byte[0] as usize) % CHARS.len()] as char);
    }
    Ok(dir.join(name))
}

fn restrict_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

// ---------------------------------------------------------------------------
// Windows DPAPI wrapper
// ---------------------------------------------------------------------------

/// Windows-only DPAPI protection for the credential file (plan C1). Every
/// value is encrypted under the logged-in user's DPAPI master key.
///
/// Protection boundary, stated honestly: this guards the FILE AT REST and
/// against reads from OTHER OS user accounts. The `pwdvault-sync` string is
/// the `szDataDescr` label DPAPI embeds in the blob — an application-domain
/// tag, NOT key material and NOT entropy (`pOptionalEntropy` is NULL), so it
/// adds nothing cryptographically. A malicious process running as the SAME
/// Windows user can decrypt these values; that threat is out of scope for a
/// user-profile file store.
#[cfg(windows)]
mod dpapi {
    use super::SecretStoreError;
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    /// `szDataDescr` label — see the module docs for why this is not entropy.
    const DATA_DESCRIPTION: PCWSTR = w!("pwdvault-sync");

    fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr().cast_mut(),
        }
    }

    /// Copy a DPAPI output buffer and release it (LocalAlloc'd by the API).
    fn take_buffer(out: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let bytes = if out.cbData == 0 || out.pbData.is_null() {
            Vec::new()
        } else {
            // SAFETY: `out` was filled by CryptProtectData/CryptUnprotectData:
            // cbData bytes of LocalAlloc'd memory, valid for reads until
            // LocalFree.
            unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec()
        };
        if !out.pbData.is_null() {
            // SAFETY: the pointer came from the DPAPI output blob and is
            // freed exactly once here.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(out.pbData.cast())));
            }
        }
        bytes
    }

    pub(super) fn protect(plain: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: `plain` is a valid borrow for the call duration; `out` is a
        // valid output blob; no prompt struct (UI_FORBIDDEN) and no entropy.
        unsafe {
            CryptProtectData(
                &blob(plain),
                DATA_DESCRIPTION,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(|_| {
            SecretStoreError::Unavailable(
                "the credential could not be encrypted for storage on this device".to_string(),
            )
        })?;
        Ok(take_buffer(&out))
    }

    pub(super) fn unprotect(protected: &[u8]) -> Result<Vec<u8>, SecretStoreError> {
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: `protected` is a valid borrow for the call duration and
        // `out` is a valid output blob. No description out-pointer, no
        // entropy, no prompt (UI_FORBIDDEN).
        unsafe {
            CryptUnprotectData(
                &blob(protected),
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(|_| {
            SecretStoreError::Unavailable(
                "stored credential cannot be decrypted on this device".to_string(),
            )
        })?;
        Ok(take_buffer(&out))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// DPAPI round trip (plan C): protect → unprotect restores the exact
        /// bytes. NOTE: CI has no Windows cargo-test job (release.yml runs
        /// tests on ubuntu only) — this test guards local Windows builds and
        /// a future CI test job, it is not currently enforced in CI.
        #[test]
        fn protect_unprotect_roundtrip() {
            let plain = b"dpapi-roundtrip-value";
            let protected = protect(plain).expect("dpapi protect");
            assert_ne!(protected, plain.to_vec(), "output must be ciphertext");
            assert_eq!(
                unprotect(&protected).expect("dpapi unprotect"),
                plain.to_vec()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// SecretStore impl
// ---------------------------------------------------------------------------

impl SecretStore for FileSecretStore {
    fn available(&self) -> bool {
        true
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), SecretStoreError> {
        let _io = self.lock_io();
        #[cfg(windows)]
        {
            // Migration write: decode every stored entry to plaintext, swap
            // in the new value, then re-protect ALL of them — any write moves
            // the whole file to dpapi1: form so no bare-base64 entry lingers
            // after an upgrade. A damaged unrelated entry fails the write
            // CLOSED (its bytes stay untouched on disk).
            let raw = self.read_raw().map_err(SecretStoreError::Unavailable)?;
            let mut plain: HashMap<String, Vec<u8>> = HashMap::with_capacity(raw.len());
            for (existing, stored) in raw.iter() {
                plain.insert(existing.clone(), parse_stored_value(stored)?);
            }
            plain.insert(account.to_string(), value.to_vec());
            let mut migrated: HashMap<String, String> = HashMap::with_capacity(plain.len());
            for (existing, plain_value) in plain.iter() {
                migrated.insert(existing.clone(), encode_stored_value(plain_value)?);
            }
            self.write_raw(&migrated)
                .map_err(SecretStoreError::Unavailable)
        }
        #[cfg(not(windows))]
        {
            // Raw pass-through: replace ONLY the target account; every other
            // entry — including "dpapi1:" values written by a Windows
            // install — is preserved byte-for-byte (no decode/re-encode of
            // the whole table).
            let mut raw = self.read_raw().map_err(SecretStoreError::Unavailable)?;
            raw.insert(account.to_string(), encode_stored_value(value)?);
            self.write_raw(&raw).map_err(SecretStoreError::Unavailable)
        }
    }

    fn get(&self, account: &str) -> Result<Vec<u8>, SecretStoreError> {
        let _io = self.lock_io();
        let raw = self.read_raw().map_err(SecretStoreError::Unavailable)?;
        let stored = raw.get(account).ok_or(SecretStoreError::NotFound)?;
        parse_stored_value(stored)
    }

    fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
        let _io = self.lock_io();
        let mut raw = self.read_raw().map_err(SecretStoreError::Unavailable)?;
        if raw.remove(account).is_none() {
            return Err(SecretStoreError::NotFound);
        }
        // Key-only removal: no entry is decoded or re-encoded, so foreign
        // dpapi1:/corrupt neighbors survive untouched (a mixed file is valid
        // — decoding is per entry). On Windows the remaining entries migrate
        // to dpapi1: on their next set().
        self.write_raw(&raw).map_err(SecretStoreError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(value: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(value)
    }

    /// The file store round-trips, upserts, isolates accounts and reports
    /// NotFound; the file on disk is JSON with 0600 permissions and accounts
    /// are namespaced (sync- prefix) by the caller.
    #[test]
    fn file_store_roundtrip_and_permissions() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sync-secrets.json");
        let store = FileSecretStore::new(path.clone());

        assert!(store.available());
        assert!(matches!(
            store.get("sync-webdav-password"),
            Err(crate::keychain::SecretStoreError::NotFound)
        ));
        assert!(matches!(
            store.delete("sync-webdav-password"),
            Err(crate::keychain::SecretStoreError::NotFound)
        ));

        store
            .set(crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT, b"dav-pass")
            .unwrap();
        store
            .set(
                crate::keychain::SYNC_BAIDU_TOKEN_ACCOUNT,
                &[0xde, 0xad, 0xbe, 0xef],
            )
            .unwrap();
        assert_eq!(
            store
                .get(crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT)
                .unwrap(),
            b"dav-pass".to_vec()
        );
        assert_eq!(
            store
                .get(crate::keychain::SYNC_BAIDU_TOKEN_ACCOUNT)
                .unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );

        // Overwrite is an upsert and leaves the other account untouched.
        store
            .set(
                crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT,
                b"new-pass".as_slice(),
            )
            .unwrap();
        assert_eq!(
            store
                .get(crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT)
                .unwrap(),
            b"new-pass".to_vec()
        );
        assert_eq!(
            store
                .get(crate::keychain::SYNC_BAIDU_TOKEN_ACCOUNT)
                .unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );

        // File is JSON, 0600 on unix, and holds string values (never raw
        // plaintext).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "credential file must be user-only");
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(json[crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT].is_string());
        assert!(
            json.get("vault-bio-wrap").is_none(),
            "bio namespace must stay disjoint"
        );

        // Delete removes only the target account.
        store
            .delete(crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT)
            .unwrap();
        assert!(matches!(
            store.get(crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT),
            Err(crate::keychain::SecretStoreError::NotFound)
        ));
        assert!(store.get(crate::keychain::SYNC_BAIDU_TOKEN_ACCOUNT).is_ok());

        // A fresh store instance reads the same persisted state.
        let reopened = FileSecretStore::new(path.clone());
        assert_eq!(
            reopened
                .get(crate::keychain::SYNC_BAIDU_TOKEN_ACCOUNT)
                .unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    /// Prefix dispatch of the per-entry decode (plan C): plain base64
    /// decodes everywhere; a `dpapi1:` value is Windows-only and fails with
    /// the explicit cross-platform Unavailable message elsewhere; broken
    /// base64 reports corrupt PER ENTRY (`:` never collides with the base64
    /// alphabet, so a dpapi1: value cannot be mistaken for a legacy one).
    #[test]
    fn parse_stored_value_prefix_dispatch() {
        assert_eq!(parse_stored_value(&b64(b"dav-pass")).unwrap(), b"dav-pass");

        let binary = [0u8, 1, 0xfe, 0xff];
        assert_eq!(parse_stored_value(&b64(&binary)).unwrap(), binary.to_vec());

        #[cfg(not(windows))]
        {
            match parse_stored_value(&format!("{DPAPI1_PREFIX}{}", b64(b"sealed-bytes"))) {
                Err(SecretStoreError::Unavailable(message)) => {
                    assert!(
                        message.contains("Windows"),
                        "message must name the source platform: {message}"
                    );
                }
                other => panic!("dpapi1: on non-Windows must be Unavailable, got {other:?}"),
            }
        }

        assert!(matches!(
            parse_stored_value("this is not base64!!"),
            Err(SecretStoreError::Unavailable(_))
        ));
        // Empty input is valid (empty) base64 — same as the pre-plan-C
        // eager decode, kept for behavior parity.
        assert_eq!(parse_stored_value("").unwrap(), Vec::<u8>::new());
    }

    /// A pre-plan-C file (bare base64 values) stays fully readable, and the
    /// raw pass-through write path preserves foreign dpapi1: entries
    /// byte-for-byte while replacing only the target account (non-Windows).
    #[cfg(not(windows))]
    #[test]
    fn legacy_file_readable_and_write_preserves_foreign_entries() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sync-secrets.json");
        let foreign_stored = format!("{DPAPI1_PREFIX}{}", b64(b"sealed-bytes"));
        let initial = format!(
            "{{\"other-dav-account\":\"{foreign_stored}\",\"sync-webdav-password\":\"{}\"}}",
            b64(b"dav-pass")
        );
        std::fs::write(&path, initial).unwrap();

        let store = FileSecretStore::new(path.clone());
        // Legacy entry reads as before the plan C change.
        assert_eq!(
            store.get("sync-webdav-password").unwrap(),
            b"dav-pass".to_vec()
        );
        // The dpapi1: neighbor is Unavailable (never a corrupt-file error for
        // the whole store) and does not block anything else.
        match store.get("other-dav-account") {
            Err(SecretStoreError::Unavailable(message)) => {
                assert!(message.contains("Windows"), "unexpected message: {message}");
            }
            other => panic!("dpapi1: entry must be Unavailable, got {other:?}"),
        }

        // Overwrite the legacy entry: only the target account changes, the
        // foreign entry keeps its exact stored bytes.
        store.set("sync-webdav-password", b"new-pass").unwrap();
        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            after["other-dav-account"].as_str().unwrap(),
            foreign_stored,
            "foreign dpapi1: entry must survive byte-for-byte"
        );
        assert_eq!(
            after["sync-webdav-password"].as_str().unwrap(),
            b64(b"new-pass"),
            "non-Windows stored form stays bare base64"
        );
        assert_eq!(store.get("sync-webdav-password").unwrap(), b"new-pass");
    }

    /// Invariant (plan C): the file never carries the plaintext secret —
    /// non-Windows stores bare base64, Windows stores dpapi1:-prefixed
    /// DPAPI blobs.
    #[test]
    fn stored_file_never_contains_plaintext_secret() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sync-secrets.json");
        let store = FileSecretStore::new(path.clone());
        store
            .set(
                crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT,
                b"plain-s3cret",
            )
            .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("plain-s3cret"),
            "file must never contain the plaintext secret"
        );
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        let stored = json[crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT]
            .as_str()
            .unwrap()
            .to_string();
        #[cfg(windows)]
        assert!(
            stored.starts_with(DPAPI1_PREFIX),
            "Windows stored form must be dpapi1:-prefixed"
        );
        #[cfg(not(windows))]
        assert_eq!(stored, b64(b"plain-s3cret"));
        // And the value still reads back.
        assert_eq!(
            store
                .get(crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT)
                .unwrap(),
            b"plain-s3cret".to_vec()
        );
    }

    /// The io_lock serializes read-modify-write cycles: many threads
    /// hammering set/get through one shared store must never lose an update
    /// (this test fails intermittently without the mutex — the rename
    /// prevents tearing, not lost updates).
    #[test]
    fn concurrent_operations_serialize_under_io_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = std::sync::Arc::new(FileSecretStore::new(dir.path().join("sync-secrets.json")));
        const THREADS: usize = 8;
        const ROUNDS: usize = 25;

        let handles: Vec<_> = (0..THREADS)
            .map(|thread| {
                let store = std::sync::Arc::clone(&store);
                std::thread::spawn(move || {
                    let account = format!("sync-thread-{thread}");
                    for round in 0..ROUNDS {
                        let value = format!("value-{thread}-{round}");
                        store.set(&account, value.as_bytes()).unwrap();
                        assert_eq!(store.get(&account).unwrap(), value.as_bytes());
                        // Interleaved reads of neighbors must always find a
                        // parseable file (never a torn/lost write).
                        let _ = store.get("sync-thread-0");
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        for thread in 0..THREADS {
            let account = format!("sync-thread-{thread}");
            assert_eq!(
                store.get(&account).unwrap(),
                format!("value-{thread}-{}", ROUNDS - 1).as_bytes(),
                "last write of every account must survive"
            );
        }
    }

    /// Windows-only DPAPI end-to-end (plan C): set → get round-trips, the
    /// migration rewrite keeps BOTH accounts readable, and the file carries
    /// the dpapi1: prefix with no plaintext. Verified by the Windows CI test
    /// job (quality-rust-windows) — first real run caught the whole-file
    /// plaintext scan false-positiveing on the account KEY name
    /// ("sync-webdav-password" contains "dav-pass"), so the secret under
    /// test must not be a substring of any key name.
    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip_migration_and_file_prefix() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sync-secrets.json");
        let store = FileSecretStore::new(path.clone());

        // '-' cannot occur in the base64 value alphabet, and this string is
        // not a substring of any account key — the leak scan below can only
        // trip on genuinely leaked ciphertext input.
        const DAV_SECRET: &[u8] = b"dav-s3cret-7Q3x";
        store
            .set(crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT, DAV_SECRET)
            .unwrap();
        store
            .set(crate::keychain::SYNC_BAIDU_TOKEN_ACCOUNT, &[0xde, 0xad])
            .unwrap();
        assert_eq!(
            store
                .get(crate::keychain::SYNC_WEBDAV_PASSWORD_ACCOUNT)
                .unwrap(),
            DAV_SECRET.to_vec()
        );
        assert_eq!(
            store
                .get(crate::keychain::SYNC_BAIDU_TOKEN_ACCOUNT)
                .unwrap(),
            vec![0xde, 0xad]
        );

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains(DPAPI1_PREFIX),
            "file must hold dpapi1: values"
        );
        assert!(
            !content.contains(std::str::from_utf8(DAV_SECRET).unwrap()),
            "no plaintext may leak to disk"
        );
    }
}
