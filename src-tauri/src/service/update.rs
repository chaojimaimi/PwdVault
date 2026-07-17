//! Update check (§5.6.2).
//!
//! Runs the GitHub releases HTTP GET on a blocking worker so the Tauri IPC
//! thread stays responsive during the 5s timeout. The worker polls the
//! `update_check_cancel` flag on `AppState` so lock/quit can abort promptly
//! instead of blocking for the full timeout.

use std::time::Duration;

use crate::{AppState, UpdateInfo, VaultError};

const UPDATE_URL: &str = "https://api.github.com/repos/chaojimaimi/PwdVault/releases/latest";
const TIMEOUT: Duration = Duration::from_secs(5);

/// Fetch the latest release from GitHub and compare versions.
///
/// The caller is expected to run this on a `spawn_blocking` worker. Returns
/// `Ok(UpdateInfo)` with `has_update=false` if the check is cancelled before
/// completion (so the frontend treats cancellation as "no update right now").
pub fn check_for_updates(state: &std::sync::Arc<AppState>) -> Result<UpdateInfo, VaultError> {
    // Reset the cancellation flag from any prior run.
    state
        .update_check_cancel
        .store(false, std::sync::atomic::Ordering::SeqCst);

    let current = env!("CARGO_PKG_VERSION");

    let config = ureq::config::Config::builder()
        .timeout_global(Some(TIMEOUT))
        .build();
    let agent: ureq::Agent = config.into();

    let mut response = agent
        .get(UPDATE_URL)
        .header("User-Agent", "PwdVault-Update-Checker")
        .call()
        .map_err(|_| VaultError::InternalError("Update check failed".to_string()))?;

    // Abort early if lock/quit cancelled us while the request was in flight.
    if is_cancelled(state) {
        return Ok(no_update(current));
    }

    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|_| VaultError::InternalError("Failed to read response".to_string()))?;

    if is_cancelled(state) {
        return Ok(no_update(current));
    }

    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|_| VaultError::InternalError("Invalid response".to_string()))?;

    let tag_name = json["tag_name"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches('v');

    let current_ver = semver::Version::parse(current)
        .map_err(|e| VaultError::InternalError(format!("Invalid current version: {}", e)))?;
    let latest_ver = semver::Version::parse(tag_name)
        .map_err(|e| VaultError::InternalError(format!("Invalid remote version: {}", e)))?;

    Ok(UpdateInfo {
        has_update: latest_ver > current_ver,
        latest_version: tag_name.to_string(),
        release_notes: json["body"].as_str().unwrap_or("").to_string(),
        download_url: json["html_url"].as_str().unwrap_or("").to_string(),
    })
}

/// Mark the in-flight update check (if any) as cancelled.
pub fn cancel_update_check(state: &std::sync::Arc<AppState>) {
    state
        .update_check_cancel
        .store(true, std::sync::atomic::Ordering::SeqCst);
}

fn is_cancelled(state: &std::sync::Arc<AppState>) -> bool {
    state
        .update_check_cancel
        .load(std::sync::atomic::Ordering::SeqCst)
}

fn no_update(current: &str) -> UpdateInfo {
    UpdateInfo {
        has_update: false,
        latest_version: current.to_string(),
        release_notes: String::new(),
        download_url: String::new(),
    }
}
