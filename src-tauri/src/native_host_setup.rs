//! Native Messaging host registration
//!
//! Writes the browser Native Messaging manifest so Chrome/Firefox know how to
//! launch the bundled `pwdvault-native` host binary. Runs idempotently on every
//! app startup so the manifest's `path` field stays correct after upgrades
//! (the bundle's absolute path changes when the app is reinstalled).

use std::path::{Path, PathBuf};
use std::fs;
use std::io;

/// The native messaging host name browsers use in `connectNative`.
pub const HOST_NAME: &str = "com.pwdvault.app";

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
            eprintln!(
                "native_host_setup: failed to register {} for {:?}: {}",
                HOST_NAME, browser, e
            );
        }
    }
}

/// Extension IDs for each browser. In development these are the 32-char IDs
/// shown in chrome://extensions / about:addons. After store publication the
/// IDs become stable.
#[derive(Debug, Clone)]
pub struct ExtensionIds {
    pub chrome: String,
    pub firefox: String,
}

impl Default for ExtensionIds {
    fn default() -> Self {
        // Placeholders — real IDs must be supplied. The auto-registration in
        // lib.rs uses these only when the bundled config file is absent.
        ExtensionIds {
            chrome: String::new(),
            firefox: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Browser {
    Chrome,
    Firefox,
}

/// Build the manifest JSON for a given browser.
fn build_manifest(host_binary_path: &Path, browser: Browser, ids: &ExtensionIds) -> String {
    let path_str = host_binary_path.to_string_lossy().replace('\\', "\\\\");

    let origin = match browser {
        Browser::Chrome => format!("chrome-extension://{}/", ids.chrome),
        Browser::Firefox => format!("moz-extension://{}/", ids.firefox),
    };

    format!(
        r#"{{
  "name": "{name}",
  "description": "PwdVault native messaging host",
  "path": "{path}",
  "type": "stdio",
  "allowed_origins": ["{origin}"]
}}
"#,
        name = HOST_NAME,
        path = path_str,
        origin = origin,
    )
}

fn register_browser(browser: Browser, host_binary_path: &Path, ids: &ExtensionIds) -> io::Result<()> {
    let manifest = build_manifest(host_binary_path, browser, ids);

    #[cfg(target_os = "macos")]
    {
        let dir = nm_dir_macos(browser)?;
        fs::create_dir_all(&dir)?;
        let manifest_path = dir.join(format!("{}.json", HOST_NAME));
        fs::write(&manifest_path, &manifest)?;
    }

    #[cfg(target_os = "linux")]
    {
        let dir = nm_dir_linux(browser)?;
        fs::create_dir_all(&dir)?;
        let manifest_path = dir.join(format!("{}.json", HOST_NAME));
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
    let home = dirs::home_dir().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home dir"))?;
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
    let home = dirs::home_dir().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home dir"))?;

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
    use winreg::enums::*;
    use winreg::RegKey;

    // Store the manifest file under the app data directory.
    let base = dirs::data_local_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "local app data dir"))?
        .join("PwdVault");
    fs::create_dir_all(&base)?;
    let manifest_path = base.join(format!("{}.json", HOST_NAME));
    fs::write(&manifest_path, manifest)?;

    let path_str = manifest_path.to_string_lossy().to_string();

    let subkey = match browser {
        Browser::Chrome => r"Software\Google\Chrome\NativeMessagingHosts",
        Browser::Firefox => r"Software\Mozilla\NativeMessagingHosts",
    };

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey(&format!("{}\\{}", subkey, HOST_NAME))?;
    key.set_value("", &path_str)?;

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
            chrome: "abcdefghijklmnopabcdefghijklmnop".to_string(),
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
    fn manifest_has_firefox_origin_for_firefox() {
        let path = Path::new("/tmp/pwdvault-native");
        let manifest = build_manifest(path, Browser::Firefox, &test_ids());
        assert!(manifest.contains("moz-extension://zyxwvutsrqponmlkjihgfedcba/"));
        assert!(!manifest.contains("chrome-extension://"));
    }
}
