//! Update check (§5.6.2).
//!
//! Runs the GitHub releases HTTP GET on a blocking worker so the Tauri IPC
//! thread stays responsive during the 5s timeout. The worker polls the
//! `update_check_cancel` flag on `AppState` so lock/quit can abort promptly
//! instead of blocking for the full timeout.

use std::time::Duration;

use crate::{AppState, UpdateInfo, VaultError};

const UPDATE_URL: &str = "https://api.github.com/repos/chaojimaimi/PwdVault/releases?per_page=5";
const TIMEOUT: Duration = Duration::from_secs(5);

/// Response body cap for the update check (D5). The releases payload is a few
/// KiB; refusing to buffer unbounded attacker- or proxy-supplied bytes keeps
/// the update check from allocating arbitrary memory.
const MAX_UPDATE_BODY_SIZE: u64 = 1024 * 1024;

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

    // Cap the response body: an oversized payload fails the read and the
    // update check degrades to a silent no-op, which is acceptable here.
    // (ureq 3's Body has no io::Read impl; `with_config().limit()` is the
    // API-sanctioned way to bound the read.)
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_UPDATE_BODY_SIZE)
        .read_to_string()
        .map_err(|_| VaultError::InternalError("Failed to read response".to_string()))?;

    if is_cancelled(state) {
        return Ok(no_update(current));
    }

    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|_| VaultError::InternalError("Invalid response".to_string()))?;

    let latest = pick_latest_release(&json)
        .ok_or_else(|| VaultError::InternalError("No parseable release found".to_string()))?;

    let current_ver = semver::Version::parse(current)
        .map_err(|e| VaultError::InternalError(format!("Invalid current version: {}", e)))?;

    Ok(UpdateInfo {
        has_update: latest.version > current_ver,
        latest_version: latest.version.to_string(),
        release_notes: latest.notes,
        download_url: latest.url,
    })
}

/// Pick the highest-semver release from the releases list payload.
///
/// Uses the LIST endpoint instead of `releases/latest`: CI publishes every
/// build as a prerelease while unsigned (the §5.6.6 #8 policy), and the
/// latest-release endpoint hides prereleases — it would forever point at an
/// old full release. Parsing the list and taking the max semver tag works
/// regardless of the prerelease flag.
fn pick_latest_release(json: &serde_json::Value) -> Option<LatestRelease> {
    let mut best: Option<(semver::Version, LatestRelease)> = None;
    for entry in json.as_array()? {
        let tag = entry["tag_name"].as_str()?.trim_start_matches('v');
        let Ok(version) = semver::Version::parse(tag) else {
            continue; // skip non-semver tags instead of failing the check
        };
        let candidate = LatestRelease {
            version: version.clone(),
            notes: entry["body"].as_str().unwrap_or("").to_string(),
            url: entry["html_url"].as_str().unwrap_or("").to_string(),
        };
        best = match &best {
            Some((best_version, _)) if *best_version >= version => best,
            _ => Some((version, candidate)),
        };
    }
    best.map(|(_, release)| release)
}

struct LatestRelease {
    version: semver::Version,
    notes: String,
    url: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The releases LIST endpoint answers with an array; the checker must
    /// take the highest semver tag regardless of order, skip non-semver
    /// entries, and compare against the running version.
    #[test]
    fn pick_latest_takes_max_semver_and_skips_unparsable() {
        let json: serde_json::Value = serde_json::from_str(
            r#"[
            {"tag_name": "v1.0.2", "body": "old full release", "html_url": "u1"},
            {"tag_name": "not-a-version", "body": "", "html_url": "u2"},
            {"tag_name": "v1.1.6", "body": "prerelease notes", "html_url": "u3"},
            {"tag_name": "v1.1.5", "body": "", "html_url": "u4"}
        ]"#,
        )
        .unwrap();
        let latest = pick_latest_release(&json).unwrap();
        assert_eq!(latest.version, semver::Version::new(1, 1, 6));
        assert_eq!(latest.notes, "prerelease notes");
        assert_eq!(latest.url, "u3");
    }

    #[test]
    fn pick_latest_returns_none_on_garbage() {
        assert!(pick_latest_release(&serde_json::json!([])).is_none());
        assert!(pick_latest_release(&serde_json::json!({"tag_name": "v1.0.0"})).is_none());
        let all_garbage: serde_json::Value =
            serde_json::from_str(r#"[{"tag_name": "nope"}]"#).unwrap();
        assert!(pick_latest_release(&all_garbage).is_none());
    }

    /// Pin the comparison semantics the checker depends on: semver compares
    /// patch/minor numerically (a plain string sort would put "1.1.6" above
    /// "1.1.10" — the classic bug this must never regress into).
    #[test]
    fn version_comparison_is_numeric_not_lexicographic() {
        let current = semver::Version::parse("1.1.6").unwrap();
        let newer_patch = semver::Version::parse("1.1.10").unwrap();
        let newer_minor = semver::Version::parse("1.2.0").unwrap();
        assert!(newer_patch > current, "1.1.10 > 1.1.6 numerically");
        assert!(newer_minor > current);
    }
}
