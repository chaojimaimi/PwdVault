//! Shared path utilities for PwdVault
//!
//! Provides platform-specific database path resolution used by both
//! the Tauri desktop app and the HTTP API server.

use std::path::{Path, PathBuf};

/// Get the database file path
/// Uses a consistent platform-specific app data directory
pub fn get_db_path() -> PathBuf {
    let base_dir = {
        #[cfg(target_os = "macos")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join("com.pwdvault.app")
        }
        #[cfg(target_os = "windows")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join("PwdVault")
        }
        #[cfg(target_os = "linux")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join("pwdvault")
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            std::env::current_dir().unwrap()
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
