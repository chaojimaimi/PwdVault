//! Shared path utilities for PwdVault
//!
//! Provides platform-specific database path resolution used by both
//! the Tauri desktop app and the HTTP API server.

use std::path::PathBuf;

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
        std::fs::create_dir_all(parent)?;
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
    let _ = std::fs::create_dir_all(&base);
    base
}
