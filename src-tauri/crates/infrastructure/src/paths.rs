//! Shared path utilities for PwdVault
//!
//! Provides platform-specific database path resolution used by both
//! the Tauri desktop app and the HTTP API server.

use std::path::{Path, PathBuf};

use pwdvault_domain::DomainError;

/// Get the database file path
/// Uses a consistent platform-specific app data directory
///
/// If the platform data dir cannot be resolved AND the working directory is
/// unreadable, fall back to the OS temp dir instead of panicking at startup.
pub fn get_db_path() -> PathBuf {
    let base_dir = {
        #[cfg(target_os = "macos")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join("com.pwdvault.app")
        }
        #[cfg(target_os = "windows")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join("PwdVault")
        }
        #[cfg(target_os = "linux")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join("pwdvault")
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            std::env::temp_dir()
        }
    };
    base_dir.join("vault.db")
}

/// Ensure the database directory exists, returning the db path
pub fn ensure_db_dir() -> Result<PathBuf, std::io::Error> {
    let db_path = get_db_path();
    if let Some(parent) = db_path.parent() {
        secure_dir(parent)?;
    }
    Ok(db_path)
}

/// Get the directory used for persistent log files.
pub fn log_dir() -> PathBuf {
    let base = get_db_path()
        .parent()
        .map(|p| p.join("logs"))
        .unwrap_or_else(|| match std::env::current_dir() {
            Ok(p) => p,
            Err(_) => PathBuf::from("."),
        });
    let _ = secure_dir(&base);
    base
}

/// Create or repair a directory so only the current Unix user can access it.
pub fn secure_dir(path: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Pre-create a sensitive file with restrictive permissions and repair an
/// existing file before it is opened by redb or another subsystem.
pub fn prepare_sensitive_file(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            secure_dir(parent)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
    }
    Ok(())
}

pub fn secure_file(_path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Validate a user-chosen file path before Rust reads or writes it on the
/// user's behalf (SEC-M2, v1.1.9).
///
/// Rules:
/// 1. empty paths and un-absolutizable relative paths are rejected;
/// 2. anything inside the vault data directory (resolved per platform by
///    [`get_db_path`] — the directory holding `vault.db`) is rejected, so
///    user files never land next to, or on top of, vault internals;
/// 3. write targets need an existing parent directory.
///
/// Threat model note: paths returned by the native save/open dialogs are
/// per-use user authorizations and do not need this check. The recovery-key
/// `save_path`, however, arrives from the frontend save dialog and is
/// re-validated here — together with the master-password parameter it forms
/// the second gate before anything touches disk.
pub fn validate_user_file_path(path: &Path, for_write: bool) -> Result<(), DomainError> {
    validate_user_file_path_inner(path, for_write, get_db_path().parent())
}

/// Same rules as [`validate_user_file_path`], with the vault data directory
/// injected so tests can exercise the containment branch against a tempdir
/// instead of the real per-platform data dir.
fn validate_user_file_path_inner(
    path: &Path,
    for_write: bool,
    vault_data_dir: Option<&Path>,
) -> Result<(), DomainError> {
    if path.as_os_str().is_empty() {
        return Err(DomainError::new("PATH_INVALID", "File path is empty"));
    }
    // Rule 1: relative paths are absolutized against the process working
    // directory; if that fails (missing or unreachable target), reject.
    if !path.is_absolute() {
        std::fs::canonicalize(path)
            .map_err(|_| DomainError::new("PATH_INVALID", "File path must be absolute"))?;
    }
    // Rule 3, checked before containment so the comparison below sees a
    // meaningful parent: a write target's parent must exist as a directory.
    if for_write {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| DomainError::new("PATH_INVALID", "File path has no parent directory"))?;
        if !parent.is_dir() {
            return Err(DomainError::new(
                "PARENT_DIR_MISSING",
                "The destination folder does not exist",
            ));
        }
    }
    // Rule 2: both sides are canonicalized (deepest existing ancestor for a
    // not-yet-existing save target) and the Windows verbatim prefix is
    // trimmed before the component-wise containment comparison.
    let target = canonicalize_deepest_existing(path)
        .ok_or_else(|| DomainError::new("PATH_INVALID", "File path cannot be resolved"))?;
    let target = strip_verbatim_prefix(&target);
    if let Some(data_dir) = vault_data_dir {
        if let Ok(data_dir) = std::fs::canonicalize(data_dir) {
            let data_dir = strip_verbatim_prefix(&data_dir);
            if target.starts_with(&data_dir) {
                return Err(DomainError::new(
                    "PATH_FORBIDDEN",
                    "The chosen location is reserved for PwdVault internal data",
                ));
            }
        }
    }
    Ok(())
}

/// Canonicalize the deepest existing ancestor of `path` — a save target may
/// not exist yet, but its directory (which decides containment) does.
fn canonicalize_deepest_existing(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(&current) {
            return Some(canonical);
        }
        // Step up one component; give up at the filesystem root.
        current = current.parent()?.to_path_buf();
    }
}

/// Trim the Windows verbatim (`\\?\`) prefix that `canonicalize` adds on
/// Windows so plain dialog-returned paths compare equal. Hand-written trim —
/// no new dependency.
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => path.to_path_buf(),
    }
}

/// Atomically write `bytes` to `path` with user-only permissions (SEC-M2).
/// The data lands in a same-directory temporary file created exclusively
/// (0600 on Unix; the mode flag is a no-op on Windows) and is renamed over
/// the destination, so a crash or a failed write can never leave a truncated
/// or half-written file behind. On any failure the temporary file is removed
/// before the error is returned.
pub fn write_file_atomic_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path has no parent directory",
            )
        })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let temp = unique_temp_path(parent, &file_name.to_string_lossy())?;

    let outcome = write_temp_then_rename(&temp, path, bytes);
    if outcome.is_err() {
        // Never leave a half-written temp file behind.
        let _ = std::fs::remove_file(&temp);
    }
    outcome
}

fn write_temp_then_rename(temp: &Path, target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp)?;
        file.write_all(bytes)?;
        // Defeat umask: re-assert 0600 exactly, like prepare_sensitive_file.
        std::fs::set_permissions(temp, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp)?;
        file.write_all(bytes)?;
    }
    std::fs::rename(temp, target)
}

/// Same-directory temporary file name: original name + a random suffix, so
/// concurrent writers never collide and `create_new` is always exclusive.
fn unique_temp_path(dir: &Path, original_name: &str) -> std::io::Result<PathBuf> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut suffix = String::with_capacity(12);
    let mut byte = [0u8; 1];
    for _ in 0..12 {
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut byte);
        suffix.push(CHARS[(byte[0] as usize) % CHARS.len()] as char);
    }
    let mut name = std::ffi::OsString::from(original_name);
    name.push(format!(".{suffix}.tmp"));
    Ok(dir.join(name))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn secure_dir_and_file_use_user_only_permissions() {
        let temp = tempfile::TempDir::new().unwrap();
        let dir = temp.path().join("private");
        secure_dir(&dir).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let file = dir.join("vault.db");
        prepare_sensitive_file(&file).unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(test)]
mod user_file_path_tests {
    use super::*;

    fn err_code(result: Result<(), DomainError>) -> String {
        result.expect_err("expected rejection").code
    }

    #[test]
    fn rejects_empty_path() {
        assert_eq!(
            err_code(validate_user_file_path_inner(Path::new(""), false, None)),
            "PATH_INVALID"
        );
        assert_eq!(
            err_code(validate_user_file_path_inner(Path::new(""), true, None)),
            "PATH_INVALID"
        );
    }

    /// A relative path that does not exist cannot be absolutized.
    #[test]
    fn rejects_missing_relative_path() {
        assert_eq!(
            err_code(validate_user_file_path_inner(
                Path::new("definitely-missing-file.pvault"),
                false,
                None
            )),
            "PATH_INVALID"
        );
    }

    /// Write targets need an existing parent directory; reads do not.
    #[test]
    fn write_requires_existing_parent_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("missing-dir").join("file.txt");
        assert_eq!(
            err_code(validate_user_file_path_inner(&target, true, None)),
            "PARENT_DIR_MISSING"
        );
        assert!(validate_user_file_path_inner(&target, false, None).is_ok());
    }

    #[test]
    fn accepts_legal_write_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("backup.pvault");
        assert!(validate_user_file_path_inner(&target, true, None).is_ok());
    }

    /// Anything inside the vault data directory is rejected — both an
    /// existing file (read side) and a not-yet-existing save target whose
    /// parent is the data dir (write side) — while the same shape outside
    /// stays legal.
    #[test]
    fn rejects_paths_inside_vault_data_dir() {
        let vault_dir = tempfile::TempDir::new().unwrap();

        let existing = vault_dir.path().join("sneaky.pvault");
        std::fs::write(&existing, b"x").unwrap();
        assert_eq!(
            err_code(validate_user_file_path_inner(
                &existing,
                false,
                Some(vault_dir.path())
            )),
            "PATH_FORBIDDEN"
        );

        let planned = vault_dir.path().join("sneaky-new.pvault");
        assert_eq!(
            err_code(validate_user_file_path_inner(
                &planned,
                true,
                Some(vault_dir.path())
            )),
            "PATH_FORBIDDEN"
        );

        let outside_dir = tempfile::TempDir::new().unwrap();
        let outside = outside_dir.path().join("fine.pvault");
        assert!(validate_user_file_path_inner(&outside, true, Some(vault_dir.path())).is_ok());
    }

    /// `Path::starts_with` compares components, not strings: a sibling
    /// directory whose name merely shares a string prefix must pass.
    #[test]
    fn containment_is_component_wise_not_string_prefix() {
        let vault_dir = tempfile::TempDir::new().unwrap();
        let sibling = vault_dir.path().with_file_name(format!(
            "{}-sibling",
            vault_dir.path().file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&sibling).unwrap();
        let target = sibling.join("fine.pvault");
        assert!(validate_user_file_path_inner(&target, true, Some(vault_dir.path())).is_ok());
    }

    #[test]
    fn atomic_write_roundtrip_and_overwrite() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("out.pvault");

        write_file_atomic_0600(&target, b"first").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        #[cfg(unix)]
        assert_eq!(mode_of(&target), 0o600);

        // Overwrite replaces the content and re-asserts 0600.
        write_file_atomic_0600(&target, b"second-content").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second-content");
        #[cfg(unix)]
        assert_eq!(mode_of(&target), 0o600);

        // Exactly one file left: no temporary file may survive.
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1, "no temporary file may survive");
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A failing write (read-only directory) must leave neither the target
    /// nor any temporary file behind. (Vacuously skipped under root, which
    /// ignores the read-only directory bit.)
    #[cfg(unix)]
    #[test]
    fn failed_write_leaves_no_half_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("out.pvault");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = write_file_atomic_0600(&target, b"nope");
        // Restore before TempDir cleanup.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        if result.is_ok() {
            // Privileges ignore the read-only bit (e.g. root): the failure
            // branch cannot be exercised in this environment.
            return;
        }
        assert!(!target.exists());
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 0, "no temporary file may be left behind");
    }
}
