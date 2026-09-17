//! File-backed credential store for cloud-sync secrets on platforms without
//! a Keychain (P3.2): a single 0600 JSON file holding base64 values, written
//! atomically (temp file + rename). Compiled on every platform so its unit
//! tests run in CI; only non-macOS builds USE it as the platform default.

use std::collections::HashMap;

use crate::keychain::{SecretStore, SecretStoreError};

/// 0600 JSON file secret store (P3.2, non-macOS `platform_sync_default`).
///
/// Values are base64 (STANDARD) inside a single JSON object
/// `{ "<account>": "<base64>", ... }`; writes go through a temp file + rename
/// so a crash never leaves a truncated store behind.
pub struct FileSecretStore {
    path: std::path::PathBuf,
}

impl FileSecretStore {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }

    fn read_map(&self) -> Result<HashMap<String, Vec<u8>>, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(e) => return Err(format!("cannot read credential file: {e}")),
        };
        let raw: HashMap<String, String> =
            serde_json::from_slice(&bytes).map_err(|e| format!("corrupt credential file: {e}"))?;
        let mut map = HashMap::with_capacity(raw.len());
        for (account, encoded) in raw {
            use base64::Engine;
            let value = base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| "corrupt credential file entry".to_string())?;
            map.insert(account, value);
        }
        Ok(map)
    }

    fn write_map(&self, map: &HashMap<String, Vec<u8>>) -> Result<(), String> {
        use base64::Engine;
        let raw: HashMap<&String, String> = map
            .iter()
            .map(|(account, value)| {
                (
                    account,
                    base64::engine::general_purpose::STANDARD.encode(value),
                )
            })
            .collect();
        let bytes = serde_json::to_vec(&raw).map_err(|e| format!("serialize error: {e}"))?;

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

impl SecretStore for FileSecretStore {
    fn available(&self) -> bool {
        true
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), SecretStoreError> {
        let mut map = self.read_map().map_err(SecretStoreError::Unavailable)?;
        map.insert(account.to_string(), value.to_vec());
        self.write_map(&map).map_err(SecretStoreError::Unavailable)
    }

    fn get(&self, account: &str) -> Result<Vec<u8>, SecretStoreError> {
        self.read_map()
            .map_err(SecretStoreError::Unavailable)?
            .remove(account)
            .ok_or(SecretStoreError::NotFound)
    }

    fn delete(&self, account: &str) -> Result<(), SecretStoreError> {
        let mut map = self.read_map().map_err(SecretStoreError::Unavailable)?;
        if map.remove(account).is_none() {
            return Err(SecretStoreError::NotFound);
        }
        self.write_map(&map).map_err(SecretStoreError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        // File is JSON, 0600 on unix, and holds base64 values.
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
}
