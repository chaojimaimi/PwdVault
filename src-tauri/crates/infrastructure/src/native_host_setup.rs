//! Native Messaging host registration
//!
//! Writes the browser Native Messaging manifest so Chrome/Firefox know how to
//! launch the bundled `pwdvault-native` host binary. Runs idempotently on every
//! app startup so the manifest's `path` field stays correct after upgrades
//! (the bundle's absolute path changes when the app is reinstalled).

use std::fs;
use std::io;
use std::path::Path;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::PathBuf;

/// The native messaging host name browsers use in `connectNative`.
pub const HOST_NAME: &str = "com.pwdvault.app";
/// Stable ID derived from the public key embedded in the Chrome manifest.
pub const CHROME_EXTENSION_ID: &str = "kekeibdcccjakipnmdpbafhaeknioaem";
pub const FIREFOX_EXTENSION_ID: &str = "pwdvault@pwdvault.app";

/// Register the native messaging host for Chrome and Firefox.
///
/// `host_binary_path` is the absolute path to the bundled `pwdvault-native`
/// binary inside the app bundle's resources directory.
/// `extension_ids` maps each browser to its extension ID (the 32-char string
/// shown in chrome://extensions). In development the IDs are unstable, so a
/// separate registration script is provided for manual re-registration.
///
/// This is safe to call on every startup: each target is overwritten with the
/// current path, so reinstalls that move the bundle are handled automatically.
pub fn register(host_binary_path: &Path, extension_ids: &ExtensionIds) {
    // Best-effort: registration failures are logged but never fatal. The app
    // must still start even if a browser isn't installed or the user lacks
    // write permission to the NM directory.
    for browser in [Browser::Chrome, Browser::Firefox] {
        if let Err(e) = register_browser(browser, host_binary_path, extension_ids) {
            tracing::error!(
                "native_host_setup: failed to register {} for {:?}: {}",
                HOST_NAME,
                browser,
                e
            );
        }
    }
}

/// Extension IDs for each browser. In development these are the 32-char IDs
/// shown in chrome://extensions / about:addons. After store publication the
/// IDs become stable.
#[derive(Debug, Clone)]
pub struct ExtensionIds {
    /// The stable packaged ID plus any valid legacy/development IDs retained
    /// during migration so an extension update does not break connectivity.
    pub chrome: Vec<String>,
    pub firefox: String,
}

impl Default for ExtensionIds {
    fn default() -> Self {
        Self {
            chrome: vec![CHROME_EXTENSION_ID.to_string()],
            firefox: FIREFOX_EXTENSION_ID.to_string(),
        }
    }
}

pub fn is_valid_chrome_extension_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| matches!(byte, b'a'..=b'p'))
}

#[derive(Debug, Clone, Copy)]
enum Browser {
    Chrome,
    Firefox,
}

/// Build the manifest JSON for a given browser.
fn build_manifest(host_binary_path: &Path, browser: Browser, ids: &ExtensionIds) -> String {
    let mut manifest = serde_json::json!({
        "name": HOST_NAME,
        "description": "PwdVault native messaging host",
        "path": host_binary_path.to_string_lossy(),
        "type": "stdio",
    });
    match browser {
        Browser::Chrome => {
            manifest["allowed_origins"] = serde_json::json!(ids
                .chrome
                .iter()
                .filter(|id| is_valid_chrome_extension_id(id))
                .map(|id| format!("chrome-extension://{id}/"))
                .collect::<Vec<_>>());
        }
        Browser::Firefox => {
            manifest["allowed_extensions"] = serde_json::json!([ids.firefox]);
        }
    }
    serde_json::to_string_pretty(&manifest).expect("native host manifest serializable") + "\n"
}

/// Chrome and Firefox registry entries must point to different files on
/// Windows. Otherwise registering the second browser overwrites the first
/// browser's allowlist while leaving both registry keys apparently valid.
#[cfg(any(target_os = "windows", test))]
fn windows_manifest_filename(browser: Browser) -> String {
    let suffix = match browser {
        Browser::Chrome => "chrome",
        Browser::Firefox => "firefox",
    };
    format!("{}.{}.json", HOST_NAME, suffix)
}

fn register_browser(
    browser: Browser,
    host_binary_path: &Path,
    ids: &ExtensionIds,
) -> io::Result<()> {
    let manifest = build_manifest(host_binary_path, browser, ids);

    #[cfg(target_os = "macos")]
    {
        let dir = nm_dir_macos(browser)?;
        crate::paths::secure_dir(&dir)?;
        let manifest_path = dir.join(format!("{}.json", HOST_NAME));
        crate::paths::prepare_sensitive_file(&manifest_path)?;
        fs::write(&manifest_path, &manifest)?;
    }

    #[cfg(target_os = "linux")]
    {
        let dir = nm_dir_linux(browser)?;
        crate::paths::secure_dir(&dir)?;
        let manifest_path = dir.join(format!("{}.json", HOST_NAME));
        crate::paths::prepare_sensitive_file(&manifest_path)?;
        fs::write(&manifest_path, &manifest)?;
    }

    #[cfg(target_os = "windows")]
    {
        register_windows(browser, &manifest)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Platform-specific Native Messaging directory resolution
// ---------------------------------------------------------------------------

/// Resolve the Native Messaging hosts directory on macOS.
#[cfg(target_os = "macos")]
fn nm_dir_macos(browser: Browser) -> io::Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home dir"))?;
    let app_support = home.join("Library/Application Support");

    let dir = match browser {
        Browser::Chrome => app_support.join("Google/Chrome/NativeMessagingHosts"),
        Browser::Firefox => app_support.join("Mozilla/NativeMessagingHosts"),
    };
    Ok(dir)
}

/// Resolve the Native Messaging hosts directory on Linux.
#[cfg(target_os = "linux")]
fn nm_dir_linux(browser: Browser) -> io::Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home dir"))?;

    let dir = match browser {
        Browser::Chrome => home.join(".config/google-chrome/NativeMessagingHosts"),
        // Also cover Chromium as a fallback by writing to the google-chrome dir;
        // Firefox uses a separate location.
        Browser::Firefox => home.join(".mozilla/native-messaging-hosts"),
    };
    Ok(dir)
}

/// On Windows the manifest path is registered in the registry rather than a
/// fixed directory. We write the manifest JSON into the app's data directory
/// and point the registry value at it.
#[cfg(target_os = "windows")]
fn register_windows(browser: Browser, manifest: &str) -> io::Result<()> {
    // Store the manifest file under the app data directory.
    let base = dirs::data_local_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "local app data dir"))?
        .join("PwdVault");
    crate::paths::secure_dir(&base)?;
    let manifest_path = base.join(windows_manifest_filename(browser));
    crate::paths::prepare_sensitive_file(&manifest_path)?;
    fs::write(&manifest_path, manifest)?;

    let path_str = manifest_path.to_string_lossy().to_string();

    write_windows_registry_views(browser, HOST_NAME, &path_str)
}

/// Write the Native Messaging registration into both Windows registry views.
///
/// Chrome queries the 32-bit view first and the 64-bit view second. Updating
/// only the process-default view can therefore leave an older 32-bit entry in
/// front of the freshly installed 64-bit entry. That stale entry may launch an
/// obsolete or missing Host even after the desktop application is reinstalled.
#[cfg(target_os = "windows")]
fn write_windows_registry_views(
    browser: Browser,
    host_name: &str,
    manifest_path: &str,
) -> io::Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let subkey = match browser {
        Browser::Chrome => r"Software\Google\Chrome\NativeMessagingHosts",
        Browser::Firefox => r"Software\Mozilla\NativeMessagingHosts",
    };
    let key_path = format!("{}\\{}", subkey, host_name);

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for view in [KEY_WOW64_32KEY, KEY_WOW64_64KEY] {
        let (key, _) = hkcu.create_subkey_with_flags(&key_path, KEY_ALL_ACCESS | view)?;
        key.set_value("", &manifest_path)?;
    }

    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn register_browser(_browser: Browser, _host_binary_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native messaging registration not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ids() -> ExtensionIds {
        ExtensionIds {
            chrome: vec!["abcdefghijklmnopabcdefghijklmnop".to_string()],
            firefox: "zyxwvutsrqponmlkjihgfedcba".to_string(),
        }
    }

    #[test]
    fn manifest_contains_required_fields() {
        let path = Path::new("/tmp/pwdvault-native");
        let manifest = build_manifest(path, Browser::Chrome, &test_ids());

        assert!(manifest.contains("\"name\": \"com.pwdvault.app\""));
        assert!(manifest.contains("\"type\": \"stdio\""));
        assert!(manifest.contains("\"path\": \"/tmp/pwdvault-native\""));
        assert!(manifest.contains("\"allowed_origins\""));
        assert!(!manifest.contains("\"allowed_extensions\""));
    }

    #[test]
    fn manifest_escapes_backslashes_for_windows() {
        let path = Path::new(r"C:\Program Files\PwdVault\pwdvault-native.exe");
        let manifest = build_manifest(path, Browser::Chrome, &test_ids());

        // Backslashes must be escaped in JSON string values.
        assert!(manifest.contains(r"C:\\Program Files\\PwdVault\\pwdvault-native.exe"));
    }

    #[test]
    fn manifest_has_chrome_origin_for_chrome() {
        let path = Path::new("/tmp/pwdvault-native");
        let manifest = build_manifest(path, Browser::Chrome, &test_ids());
        assert!(manifest.contains("chrome-extension://abcdefghijklmnopabcdefghijklmnop/"));
        assert!(!manifest.contains("moz-extension://"));
    }

    #[test]
    fn default_manifest_uses_stable_chrome_extension_id() {
        let manifest = build_manifest(
            Path::new("/tmp/pwdvault-native"),
            Browser::Chrome,
            &ExtensionIds::default(),
        );
        assert!(manifest.contains(&format!("chrome-extension://{CHROME_EXTENSION_ID}/")));
    }

    #[test]
    fn manifest_keeps_stable_and_valid_legacy_chrome_ids() {
        let ids = ExtensionIds {
            chrome: vec![
                CHROME_EXTENSION_ID.to_string(),
                "abcdefghijklmnopabcdefghijklmnop".to_string(),
                "invalid".to_string(),
            ],
            firefox: FIREFOX_EXTENSION_ID.to_string(),
        };
        let manifest = build_manifest(Path::new("/tmp/pwdvault-native"), Browser::Chrome, &ids);
        assert!(manifest.contains(&format!("chrome-extension://{CHROME_EXTENSION_ID}/")));
        assert!(manifest.contains("chrome-extension://abcdefghijklmnopabcdefghijklmnop/"));
        assert!(!manifest.contains("chrome-extension://invalid/"));
    }

    #[test]
    fn manifest_has_firefox_extension_id_for_firefox() {
        let path = Path::new("/tmp/pwdvault-native");
        let manifest = build_manifest(path, Browser::Firefox, &test_ids());
        assert!(manifest.contains("\"allowed_extensions\""));
        assert!(manifest.contains("zyxwvutsrqponmlkjihgfedcba"));
        assert!(!manifest.contains("\"allowed_origins\""));
        assert!(!manifest.contains("moz-extension://"));
    }

    #[test]
    fn windows_browser_manifests_use_distinct_filenames() {
        let chrome = windows_manifest_filename(Browser::Chrome);
        let firefox = windows_manifest_filename(Browser::Firefox);

        assert_eq!(chrome, "com.pwdvault.app.chrome.json");
        assert_eq!(firefox, "com.pwdvault.app.firefox.json");
        assert_ne!(chrome, firefox);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_registration_writes_both_registry_views() {
        use winreg::enums::*;
        use winreg::RegKey;

        let host_name = format!("com.pwdvault.test.{}", std::process::id());
        let manifest_path = r"C:\Temp\pwdvault-native-test.json";
        let parent = r"Software\Google\Chrome\NativeMessagingHosts";
        let key_path = format!("{}\\{}", parent, host_name);
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        write_windows_registry_views(Browser::Chrome, &host_name, manifest_path)
            .expect("write both registry views");

        for view in [KEY_WOW64_32KEY, KEY_WOW64_64KEY] {
            let key = hkcu
                .open_subkey_with_flags(&key_path, KEY_READ | view)
                .unwrap_or_else(|error| {
                    panic!("registration exists in {view:?} registry view: {error}")
                });
            let actual: String = key.get_value("").expect("default manifest path value");
            assert_eq!(actual, manifest_path);
        }

        // Some supported Windows versions share/reflect this HKCU subtree
        // between registry views. Read both views before cleanup, then accept
        // NotFound while deleting the second alias of the same underlying key.
        for view in [KEY_WOW64_32KEY, KEY_WOW64_64KEY] {
            match hkcu.delete_subkey_with_flags(&key_path, view) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove test registration from {view:?}: {error}"),
            }
        }
    }
}
