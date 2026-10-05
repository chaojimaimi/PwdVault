//! Recovery-key file export (SEC-M2, v1.1.9): with the filesystem scope
//! pulled back from the webview, the optional recovery-key file is written
//! by Rust (0600, atomic) instead of the frontend fs plugin. Key generation
//! itself is untouched — [`enable_recovery_with_file`] wraps the existing
//! security service and only adds the save-path handling.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::{AppState, VaultError};
use pwdvault_infrastructure::paths;

/// Result of `enable_recovery` over IPC: the one-time recovery key plus
/// whether the optional key file was written. The key is `Zeroizing` so the
/// in-memory copy is wiped when the response drops (SEC-L4, v1.2.0); IPC
/// serialization is transparent — the frontend sees the same JSON string.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableRecoveryResult {
    pub key: Zeroizing<String>,
    pub file_saved: bool,
}

/// Enable the recovery key and, when `save_path` is given, write the key
/// file from Rust. A failed write is an error — never a silent partial
/// success (the key is still in the response on success only).
pub fn enable_recovery_with_file(
    state: &Arc<AppState>,
    password: Zeroizing<String>,
    save_path: Option<String>,
) -> Result<EnableRecoveryResult, VaultError> {
    let key = Zeroizing::new(crate::service::security::enable_recovery(state, password)?);
    match save_path {
        None => Ok(EnableRecoveryResult {
            key,
            file_saved: false,
        }),
        Some(path) => {
            write_recovery_key_file(key.as_str(), &path)?;
            Ok(EnableRecoveryResult {
                key,
                file_saved: true,
            })
        }
    }
}

/// Write the recovery-key file after path validation (0600, atomic).
fn write_recovery_key_file(key: &str, save_path: &str) -> Result<(), VaultError> {
    let path = std::path::Path::new(save_path);
    // Second gate: the path was chosen in the frontend save dialog; it is
    // re-validated here (vault-data-dir exclusion + existing parent), and
    // the master-password parameter above remains the first gate.
    paths::validate_user_file_path(path, true)?;
    let content = recovery_key_file_content(key);
    paths::write_file_atomic_0600(path, content.as_bytes()).map_err(|error| {
        VaultError::InvalidInput {
            code: "RECOVERY_FILE_WRITE_FAILED".into(),
            // The key was already enabled by the time the write fails, but
            // this error path is the only feedback the user gets — say what
            // state the vault is in and how to obtain a key (re-enabling
            // generates a fresh one).
            message: format!(
                "the recovery key is enabled but its file could not be written ({error}); \
                 run Enable again to generate and save a new key"
            ),
        }
    })?;
    Ok(())
}

/// Verbatim Rust port of the webview's `recoveryKeyFileContent`
/// (src/components/SecuritySettingsSection.tsx:41): the exported file is
/// byte-identical regardless of which side writes it. `Generated:` uses the
/// UTC date, matching `new Date().toISOString().slice(0, 10)`.
fn recovery_key_file_content(key: &str) -> String {
    [
        "PwdVault Recovery Key",
        &format!("Generated: {}", chrono::Utc::now().format("%Y-%m-%d")),
        "",
        "Keep this file somewhere safe. It is the only way to recover your",
        "vault if you forget your master password. Anyone holding this key",
        "can unlock your vault.",
        "",
        key,
        "",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdvault_infrastructure::crypto::{self, kdf::AdaptiveParams};
    use pwdvault_infrastructure::database::{self, Settings};
    use tempfile::TempDir;

    const TEST_PASSWORD: &str = "recovery-file-test-password";

    /// Minimal unlocked modern vault — same fixture pattern as
    /// backup_tests.rs (verification + integrity header + settings).
    fn unlocked_state() -> (Arc<AppState>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(database::init_database(dir.path().join("recovery.db")).unwrap());
        let salt = [0x41; 16];
        let params = AdaptiveParams {
            m_cost: 16384,
            t_cost: 1,
            p_cost: 1,
        };
        let (master_key, _) =
            crypto::kdf::derive_key_with_params(TEST_PASSWORD, &salt, &params).unwrap();
        let verification = crypto::create_verification_header(&master_key, salt, params).unwrap();
        let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);

        database::vault_store::VaultStore::new(&db)
            .write(&mac_key, |txn| {
                database::vault_store::save_verification_data_in_txn(txn, &verification)?;
                pwdvault_infrastructure::vault_header::save_header_in_txn(
                    txn,
                    &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
                    &enc_key,
                )?;
                database::vault_store::save_settings_in_txn(txn, &Settings::default())?;
                Ok(())
            })
            .unwrap();

        let state = Arc::new(AppState::default());
        *state.database.lock().unwrap() = Some(db);
        *state.verification_data.lock().unwrap() = Some(verification);
        state.session.unlock(enc_key, mac_key);
        (state, dir)
    }

    /// Branch 1: `save_path = None` keeps the old behavior — key returned,
    /// `file_saved: false`, nothing written.
    #[test]
    fn enable_recovery_without_save_path_skips_the_file() {
        let (state, _dir) = unlocked_state();
        let result =
            enable_recovery_with_file(&state, Zeroizing::new(TEST_PASSWORD.to_string()), None)
                .unwrap();
        assert!(!result.file_saved);
        assert!(!result.key.is_empty());
        // Recovery is now enabled for the vault (wrap blob exists).
        assert!(crate::service::recovery_status(&state).unwrap());
    }

    /// Branch 2: a legal save path produces the key file with the exact
    /// template content, user-only permissions, and `file_saved: true`.
    #[test]
    fn enable_recovery_with_legal_save_path_writes_key_file() {
        let (state, out_dir) = unlocked_state();
        let target = out_dir.path().join("pwdvault-recovery-key.txt");

        let result = enable_recovery_with_file(
            &state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Some(target.to_string_lossy().into_owned()),
        )
        .unwrap();
        assert!(result.file_saved);
        assert!(!result.key.is_empty());

        let content = std::fs::read_to_string(&target).unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        assert_eq!(
            content,
            format!(
                "PwdVault Recovery Key\nGenerated: {today}\n\nKeep this file somewhere safe. \
                 It is the only way to recover your\nvault if you forget your master password. \
                 Anyone holding this key\ncan unlock your vault.\n\n{}\n",
                result.key.as_str()
            )
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "recovery key file must be user-only");
        }
    }

    /// Branch 3: an illegal save path (inside the vault data directory, or
    /// with a missing parent) is an error, and no file is written.
    #[test]
    fn enable_recovery_with_illegal_save_path_fails_cleanly() {
        let (state, _dir) = unlocked_state();

        // Inside the (real, per-platform) vault data directory. Whether that
        // directory exists on this machine decides which rule rejects —
        // PATH_FORBIDDEN when it does, PARENT_DIR_MISSING otherwise — but
        // both are InvalidInput and neither may write anything.
        let path = paths::get_db_path()
            .parent()
            .unwrap()
            .join("recovery-key-must-not-land.txt");
        let result = enable_recovery_with_file(
            &state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Some(path.to_string_lossy().into_owned()),
        );
        assert!(
            matches!(result, Err(VaultError::InvalidInput { .. })),
            "a vault-data-dir save path must be rejected"
        );
        assert!(!path.exists(), "no file may be written to the data dir");

        // Missing parent directory: deterministic PARENT_DIR_MISSING.
        let missing = std::env::temp_dir()
            .join("pwdvault-recovery-missing-dir")
            .join("key.txt");
        match enable_recovery_with_file(
            &state,
            Zeroizing::new(TEST_PASSWORD.to_string()),
            Some(missing.to_string_lossy().into_owned()),
        ) {
            Err(VaultError::InvalidInput { code, .. }) => {
                assert_eq!(code, "PARENT_DIR_MISSING");
            }
            other => panic!("expected PARENT_DIR_MISSING, got {other:?}"),
        }
    }

    /// The file template is a byte-exact port of the webview's
    /// recoveryKeyFileContent (only the date is dynamic).
    #[test]
    fn recovery_key_file_content_matches_webview_template() {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        assert_eq!(
            recovery_key_file_content("KEY-1234"),
            format!(
                "PwdVault Recovery Key\nGenerated: {today}\n\nKeep this file somewhere safe. \
                 It is the only way to recover your\nvault if you forget your master password. \
                 Anyone holding this key\ncan unlock your vault.\n\nKEY-1234\n"
            )
        );
    }
}
