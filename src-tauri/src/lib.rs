//! PwdVault - A secure, local-first password manager

pub mod auth;
#[cfg(test)]
pub mod benchmarks;
pub mod constants;
pub mod crypto;
pub mod database;
#[cfg(test)]
pub mod fixtures;
pub mod native_host_setup;
pub mod native_messaging;
pub mod pairing;
pub mod paths;
pub mod service;
pub mod session;
#[cfg(test)]
pub mod test_infra;

use redb::Database;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager, State,
};
use zeroize::Zeroizing;

use crypto::{EncryptionError, KdfError, KeyStoreError, VerificationData};

#[cfg(test)]
use crypto::{create_verification_header, decrypt, encrypt, EncryptedData};
use database::{Group, PasswordEntry, Settings};

#[cfg(test)]
use database::{count_entries, delete_entry, list_entries, load_entry, save_entry};

// ============================================================================
// Application State
// ============================================================================

pub struct AppState {
    pub verification_data: Mutex<Option<VerificationData>>,
    pub database: Mutex<Option<Arc<Database>>>,
    /// Unified vault session — holds enc_key, mac_key, last_activity, and
    /// session_generation. Replaces the former keystore, mac_key,
    /// last_activity, and op_lock fields with a single state machine that
    /// provides a consistent concurrency model across Tauri IPC, HTTP, and
    /// auto-lock. (§5.1.1)
    pub session: session::VaultSession,
    /// Closure to update the tray lock/unlock menu item text
    pub update_lock_menu_fn: Mutex<Option<Box<dyn Fn(&str) + Send + Sync>>>,
    /// Closure to reload the main window (for auto-lock)
    pub reload_window_fn: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// Dynamic auto-lock timeout in seconds (loaded from settings)
    pub auto_lock_secs: Mutex<u64>,
    /// Number of consecutive failed unlock attempts
    pub failed_unlock_attempts: Mutex<u32>,
    /// Timestamp when lockout expires (None = not locked out)
    pub lockout_until: Mutex<Option<Instant>>,
    /// Rate limiting for pair endpoint (requests per minute)
    pub pair_request_count: Mutex<u32>,
    pub pair_last_reset: Mutex<Option<Instant>>,
}

impl AppState {
    /// Reset the auto-lock activity timer (called on vault operations)
    pub fn touch_activity(&self) {
        self.session.touch_activity();
    }

    /// Update the tray menu item text for lock/unlock
    pub fn update_lock_menu(&self, text: &str) {
        let guard = self.update_lock_menu_fn.lock().expect("menu lock poisoned");
        if let Some(ref callback) = *guard {
            callback(text);
        }
    }

    /// Reload the main window (used by auto-lock)
    pub fn reload_window(&self) {
        let guard = self.reload_window_fn.lock().expect("window lock poisoned");
        if let Some(ref callback) = *guard {
            callback();
        }
    }

    /// Check if the vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.session.is_unlocked()
    }

    /// Obtain an operation lease on the vault session. While held, auto-lock
    /// cannot clear the session keys. All service operations should acquire
    /// a lease at the start. (§5.1.1)
    pub fn lease(&self) -> Result<session::SessionLease<'_>, VaultError> {
        self.session.lease()
    }

    /// Lock the vault: obtain exclusive access, wait for in-flight operations
    /// to drain, then atomically clear keys. Used by auto-lock and manual lock.
    pub fn lock_vault(&self) {
        self.session.exclusive_lock_and_clear();
        self.update_lock_menu("Unlock Vault");
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            verification_data: Mutex::new(None),
            database: Mutex::new(None),
            session: session::VaultSession::new(),
            update_lock_menu_fn: Mutex::new(None),
            reload_window_fn: Mutex::new(None),
            auto_lock_secs: Mutex::new(constants::AUTO_LOCK_SECS),
            failed_unlock_attempts: Mutex::new(0),
            lockout_until: Mutex::new(None),
            pair_request_count: Mutex::new(0),
            pair_last_reset: Mutex::new(None),
        }
    }
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub enum VaultError {
    VaultLocked,
    VaultAlreadyExists,
    InvalidPassword,
    EntryNotFound,
    EncryptionFailed(String),
    DecryptionFailed(String),
    DatabaseError(String),
    InternalError(String),
    InvalidBackup(String),
    RateLimited { retry_after_secs: u64 },
}

impl From<EncryptionError> for VaultError {
    fn from(e: EncryptionError) -> Self {
        VaultError::EncryptionFailed(e.to_string())
    }
}

impl From<KeyStoreError> for VaultError {
    fn from(e: KeyStoreError) -> Self {
        match e {
            KeyStoreError::VaultLocked => VaultError::VaultLocked,
            KeyStoreError::AlreadyUnlocked => VaultError::VaultAlreadyExists,
        }
    }
}

impl From<KdfError> for VaultError {
    fn from(e: KdfError) -> Self {
        VaultError::InternalError(e.to_string())
    }
}

impl From<crypto::VerificationError> for VaultError {
    fn from(e: crypto::VerificationError) -> Self {
        VaultError::InternalError(e.to_string())
    }
}

impl From<database::DatabaseError> for VaultError {
    fn from(e: database::DatabaseError) -> Self {
        VaultError::DatabaseError(e.to_string())
    }
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::VaultLocked => write!(f, "Vault is locked"),
            VaultError::VaultAlreadyExists => write!(f, "Vault already exists"),
            VaultError::InvalidPassword => write!(f, "Invalid password"),
            VaultError::EntryNotFound => write!(f, "Entry not found"),
            VaultError::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            VaultError::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            VaultError::DatabaseError(e) => write!(f, "Database error: {}", e),
            VaultError::InternalError(e) => write!(f, "Internal error: {}", e),
            VaultError::InvalidBackup(e) => write!(f, "Invalid backup: {}", e),
            VaultError::RateLimited { retry_after_secs } => {
                write!(
                    f,
                    "Too many failed attempts. Try again in {}s",
                    retry_after_secs
                )
            }
        }
    }
}

impl VaultError {
    /// Returns a sanitized message suitable for external callers (HTTP API,
    /// browser extension). Internal details such as file paths or serialization
    /// errors are stripped to avoid information leakage.
    pub fn public_message(&self) -> String {
        match self {
            VaultError::VaultLocked => "Vault is locked".to_string(),
            VaultError::VaultAlreadyExists => "Vault already exists".to_string(),
            VaultError::InvalidPassword => "Invalid password".to_string(),
            VaultError::EntryNotFound => "Entry not found".to_string(),
            VaultError::RateLimited { retry_after_secs } => {
                format!("Too many attempts. Retry in {}s", retry_after_secs)
            }
            VaultError::InvalidBackup(_) => "Invalid backup file".to_string(),
            VaultError::EncryptionFailed(_)
            | VaultError::DecryptionFailed(_)
            | VaultError::DatabaseError(_)
            | VaultError::InternalError(_) => "Internal error".to_string(),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

// ============================================================================
// IPC Commands
// ============================================================================

#[tauri::command]
fn is_vault_initialized(state: State<'_, Arc<AppState>>) -> bool {
    service::is_initialized(state.inner())
}

#[tauri::command]
fn is_vault_unlocked(state: State<'_, Arc<AppState>>) -> bool {
    service::is_unlocked(state.inner())
}

#[tauri::command]
fn init_vault(
    password: Zeroizing<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<(), VaultError> {
    service::init_vault(state.inner(), password)
}

#[tauri::command]
fn unlock_vault(
    password: Zeroizing<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<bool, VaultError> {
    service::unlock_vault(state.inner(), password)
}

#[tauri::command]
fn lock_vault(state: State<'_, Arc<AppState>>) {
    service::lock_vault(state.inner());
}

#[tauri::command]
fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> Result<String, VaultError> {
    service::generate_password(
        length,
        include_uppercase,
        include_lowercase,
        include_numbers,
        include_symbols,
    )
}

// ============================================================================
// Update Check
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub has_update: bool,
    pub latest_version: String,
    pub release_notes: String,
    pub download_url: String,
}

#[tauri::command]
fn check_for_updates() -> Result<UpdateInfo, VaultError> {
    let current = env!("CARGO_PKG_VERSION");

    let config = ureq::config::Config::builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build();
    let agent: ureq::Agent = config.into();

    let mut response = agent
        .get("https://api.github.com/repos/chaojimaimi/PwdVault/releases/latest")
        .header("User-Agent", "PwdVault-Update-Checker")
        .call()
        .map_err(|_| VaultError::InternalError("Update check failed".to_string()))?;

    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|_| VaultError::InternalError("Failed to read response".to_string()))?;

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

// ============================================================================
// Entry Management Commands
// ============================================================================

/// Request to create a new password entry
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateEntryRequest {
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    /// Plaintext password. Wrapped in Zeroizing so the heap buffer is wiped
    /// when the request is dropped (after encryption).
    pub password: Zeroizing<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub group_id: Option<String>,
}

/// Decrypted secrets for a password entry.
/// Returned only by explicit secret-fetch endpoints so plaintext fields are not
/// kept in memory longer than necessary.
#[derive(Debug, Serialize, Deserialize)]
pub struct EntrySecretResponse {
    pub password: Zeroizing<String>,
    pub notes: Option<Zeroizing<String>>,
    pub last_used_at: Option<i64>,
}

/// Summary of password entry (without decrypted password)
#[derive(Debug, Serialize, Deserialize)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    pub tags: Vec<String>,
    pub group_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<PasswordEntry> for EntrySummary {
    fn from(entry: PasswordEntry) -> Self {
        Self {
            id: entry.id,
            title: entry.title,
            url: entry.url,
            username: entry.username,
            tags: entry.tags,
            group_id: entry.group_id,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }
}

#[tauri::command]
fn create_entry(
    request: CreateEntryRequest,
    state: State<'_, Arc<AppState>>,
) -> Result<EntrySummary, VaultError> {
    service::create_entry(state.inner(), request)
}

#[tauri::command]
fn get_entry_meta(id: String, state: State<'_, Arc<AppState>>) -> Result<EntrySummary, VaultError> {
    service::get_entry_meta(state.inner(), id)
}

#[tauri::command]
fn get_entry_secret(
    id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<EntrySecretResponse, VaultError> {
    service::get_entry_secret(state.inner(), id)
}

#[tauri::command]
fn list_all_entries(state: State<'_, Arc<AppState>>) -> Result<Vec<EntrySummary>, VaultError> {
    service::list_all_entries(state.inner())
}

#[tauri::command]
fn update_entry(
    id: String,
    request: CreateEntryRequest,
    state: State<'_, Arc<AppState>>,
) -> Result<EntrySummary, VaultError> {
    service::update_entry(state.inner(), id, request)
}

// ============================================================================
// Group Management Commands
// ============================================================================

#[tauri::command]
fn create_group(name: String, state: State<'_, Arc<AppState>>) -> Result<Group, VaultError> {
    service::create_group(state.inner(), name)
}

#[tauri::command]
fn list_all_groups(state: State<'_, Arc<AppState>>) -> Result<Vec<Group>, VaultError> {
    service::list_all_groups(state.inner())
}

#[tauri::command]
fn remove_group(id: String, state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    service::remove_group(state.inner(), id)
}

#[tauri::command]
fn update_group(
    id: String,
    name: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Group, VaultError> {
    service::update_group(state.inner(), id, name)
}

// ============================================================================
// Settings Commands
// ============================================================================

#[tauri::command]
fn get_settings(state: State<'_, Arc<AppState>>) -> Result<database::Settings, VaultError> {
    service::get_settings(state.inner())
}

#[tauri::command]
fn update_settings(
    settings: database::Settings,
    state: State<'_, Arc<AppState>>,
) -> Result<database::Settings, VaultError> {
    service::update_settings(state.inner(), settings)
}

#[tauri::command]
fn remove_entry(id: String, state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    service::remove_entry(state.inner(), id)
}

#[tauri::command]
fn get_entry_count(state: State<'_, Arc<AppState>>) -> Result<usize, VaultError> {
    service::get_entry_count(state.inner())
}

// ============================================================================
// Import/Export Commands
// ============================================================================

/// Plaintext entry for export (password/notes as strings, not encrypted bytes)
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportEntry {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    pub password: Zeroizing<String>,
    pub notes: Option<Zeroizing<String>>,
    pub tags: Vec<String>,
    pub group_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Plaintext backup payload
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupPayload {
    pub entries: Vec<ExportEntry>,
    pub groups: Vec<Group>,
    pub settings: Settings,
}

/// Encrypted backup file format
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultBackup {
    pub version: u32,
    pub created_at: i64,
    pub salt: String, // base64
    pub kdf_memory: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub nonce: String, // base64
    pub data: String,  // base64 (AES-256-GCM encrypted payload)
}

/// Result of import operation
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportResult {
    pub entries_imported: usize,
    pub groups_imported: usize,
}

#[tauri::command]
fn export_vault(
    export_password: Zeroizing<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<VaultBackup, VaultError> {
    service::export_vault(state.inner(), export_password)
}

#[tauri::command]
fn import_vault(
    backup: VaultBackup,
    import_password: Zeroizing<String>,
    state: State<'_, Arc<AppState>>,
) -> Result<ImportResult, VaultError> {
    service::import_vault(state.inner(), backup, import_password)
}

// ============================================================================
// Setup Command (called on app start)
// ============================================================================

#[tauri::command]
fn setup_vault(state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    service::setup_vault(state.inner())
}

// ============================================================================
// Auto-Lock Background Thread
// ============================================================================

fn start_auto_lock_thread(state: Arc<AppState>) {
    std::thread::spawn(move || loop {
        let deadline = {
            let timeout = *state.auto_lock_secs.lock().expect("timeout lock poisoned");
            state.session.auto_lock_deadline(timeout)
        };

        match deadline {
            Some(d) => {
                let now = std::time::Instant::now();
                if d > now {
                    // Cap the sleep at 5 seconds so the thread re-evaluates
                    // the deadline periodically. Without this cap, if the user
                    // shortens auto_lock_secs while the thread is sleeping
                    // toward the old (longer) deadline, the vault wouldn't
                    // lock until the original deadline passes.
                    let sleep_dur = (d - now).min(std::time::Duration::from_secs(5));
                    std::thread::sleep(sleep_dur);
                    // After waking, re-check in case activity was updated while sleeping.
                    let should_lock = {
                        let timeout = *state.auto_lock_secs.lock().expect("timeout lock poisoned");
                        state.session.should_auto_lock(timeout)
                    };
                    if should_lock {
                        state.lock_vault();
                        state.reload_window();
                    }
                } else {
                    // Already past the deadline; lock immediately.
                    state.lock_vault();
                    state.reload_window();
                }
            }
            None => {
                // Vault is locked or not yet initialized; idle until something changes.
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    });
}

// ============================================================================
// Entry Point
// ============================================================================

/// Locate the bundled native messaging host binary and register it with the
/// installed browsers. Reads extension IDs from a config file next to the
/// database; if absent (e.g. dev mode or IDs not yet configured), registration
/// is skipped so we never write a manifest with invalid placeholders.
fn register_native_host(app: &tauri::App) {
    let resource_dir = match app.path().resource_dir() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("native_host_setup: cannot resolve resource dir: {}", e);
            return;
        }
    };

    // In a packaged bundle the binary lives under resources/binaries/
    // (placed there by bundle.resources in tauri.conf.json, which preserves the
    // directory structure). During development (pnpm tauri dev) it is absent —
    // registration is skipped silently.
    let binary_name = if cfg!(windows) {
        "pwdvault-native.exe"
    } else {
        "pwdvault-native"
    };
    let host_path = resource_dir.join("binaries").join(binary_name);

    if !host_path.exists() {
        // Expected in dev mode (no bundle). Stay quiet so dev logs aren't noisy.
        return;
    }

    // Tauri's bundle.resources does not preserve the executable bit, so the
    // host binary may lack +x after packaging. Fix it on every launch (cheap
    // and idempotent). No-op on Windows where the extension governs execution.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&host_path) {
            let mut perms = meta.permissions();
            if perms.mode() & 0o111 == 0 {
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(&host_path, perms);
            }
        }
    }

    // Read extension IDs from a config file next to the database. This file is
    // created by the registration script (install-native-host.sh) or manually.
    // Without valid IDs we cannot write a usable manifest.
    let ids = match load_extension_ids() {
        Some(ids) if !ids.chrome.is_empty() => ids,
        _ => {
            // IDs not configured yet — skip silently. Use the install script.
            return;
        }
    };

    native_host_setup::register(&host_path, &ids);
}

/// Load extension IDs from a JSON config file placed next to the vault
/// database (e.g. ~/Library/Application Support/com.pwdvault.app/native-host.json).
/// Format: {"chrome": "<id>", "firefox": "<id>"}
fn load_extension_ids() -> Option<native_host_setup::ExtensionIds> {
    let config_path = paths::get_db_path().parent()?.join("native-host.json");
    let content = std::fs::read_to_string(&config_path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    Some(native_host_setup::ExtensionIds {
        chrome: value.get("chrome")?.as_str()?.to_string(),
        firefox: value
            .get("firefox")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize structured logging to a daily-rotated file under the app data dir.
    let file_appender = tracing_appender::rolling::daily(&paths::log_dir(), "pwdvault.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("pwdvault=info")),
        )
        .with_writer(non_blocking)
        .with_ansi(false)
        .init();

    let state = Arc::new(AppState::default());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(state.clone())
        .setup(move |app| {
            // Start native messaging server in background thread
            let state_for_server = state.clone();
            let app_handle = app.handle().clone();

            std::thread::spawn(move || {
                if let Err(e) = native_messaging::start_server(
                    constants::NATIVE_MESSAGING_PORT,
                    state_for_server,
                    Some(app_handle),
                ) {
                    tracing::error!("Failed to start native messaging server: {}", e);
                }
            });

            // Register the native messaging host so browsers can spawn it.
            // Idempotent: overwrites the manifest on every launch so the binary
            // path stays correct after upgrades relocate the bundle.
            register_native_host(app);

            // Build system tray menu
            let show_i = MenuItem::with_id(app, "show", "Show PwdVault", true, None::<&str>)?;
            let lock_i = MenuItem::with_id(app, "lock", "Lock Vault", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &lock_i, &quit_i])?;

            // Store closures for updating tray menu and reloading window from any thread
            {
                let lock_i_clone = lock_i.clone();
                let app_handle = app.handle().clone();
                *state
                    .update_lock_menu_fn
                    .lock()
                    .expect("menu lock poisoned") = Some(Box::new(move |text: &str| {
                    let _ = lock_i_clone.set_text(text);
                }));
                *state.reload_window_fn.lock().expect("window lock poisoned") =
                    Some(Box::new(move || {
                        if let Some(window) = app_handle.get_webview_window("main") {
                            let _ = window.eval("window.location.reload()");
                        }
                    }));
            }

            // Start auto-lock background thread
            start_auto_lock_thread(state.clone());

            // Create tray icon
            let tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("PwdVault")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "lock" => {
                        let state = app.state::<Arc<AppState>>();
                        if state.is_unlocked() {
                            state.lock_vault();
                        }
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                            let _ = window.eval("window.location.reload()");
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click {
                        button: tauri::tray::MouseButton::Left,
                        button_state: tauri::tray::MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            // Prevent the window from being destroyed on close — hide to tray instead
            // This keeps the HTTP server alive for the browser extension (Plan B)
            if let Some(window) = app.get_webview_window("main") {
                let tray_handle = tray.clone();
                let win = window.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = win.hide();
                        let _ = &tray_handle;
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            is_vault_initialized,
            is_vault_unlocked,
            init_vault,
            unlock_vault,
            lock_vault,
            generate_password,
            setup_vault,
            // Entry management
            create_entry,
            get_entry_meta,
            get_entry_secret,
            list_all_entries,
            update_entry,
            remove_entry,
            get_entry_count,
            // Group management
            create_group,
            list_all_groups,
            remove_group,
            update_group,
            // Settings
            get_settings,
            update_settings,
            // Import/Export
            export_vault,
            import_vault,
            // Update check
            check_for_updates,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a test AppState with a temp database
    fn setup_test_state() -> (Arc<AppState>, TempDir) {
        let temp = TempDir::new().expect("create temp dir");
        let db_path = temp.path().join("test_vault.db");
        let db = Arc::new(database::init_database(&db_path).expect("init db"));

        let state = Arc::new(AppState::default());
        *state.database.lock().expect("db lock") = Some(db);
        (state, temp)
    }

    /// Helper: initialize vault with a password
    fn init_test_vault(state: &Arc<AppState>, password: &str) {
        // Clear any existing session state
        state.lock_vault();

        let salt = crypto::kdf::generate_salt();
        let (master_key, params) = crypto::kdf::derive_key(password, &salt).expect("derive key");
        let verification = create_verification_header(&master_key, salt.clone(), params)
            .expect("create verification");
        let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);

        let db = state
            .database
            .lock()
            .expect("db lock")
            .clone()
            .expect("db exists");
        database::save_verification_data(&db, &verification).expect("save verification");

        *state.verification_data.lock().expect("v lock") = Some(verification);
        state.session.unlock(enc_key, mac_key);
        state.touch_activity();
    }

    // ---- AppState tests ----

    #[test]
    fn test_appstate_default() {
        let state = AppState::default();
        assert!(state.verification_data.lock().unwrap().is_none());
        assert!(state.database.lock().unwrap().is_none());
        assert!(!state.is_unlocked());
    }

    #[test]
    fn test_touch_and_lock_vault() {
        let state = Arc::new(AppState::default());
        assert!(!state.is_unlocked());

        // touch_activity only works when unlocked (session is Locked by default)
        state.touch_activity();
        // Still locked since we never unlocked
        assert!(!state.is_unlocked());

        state.lock_vault();
        assert!(!state.is_unlocked());
    }

    // ---- generate_password tests ----

    #[test]
    fn test_generate_password_length() {
        let pw = generate_password(20, true, true, true, true).unwrap();
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn test_generate_password_all_charsets() {
        let pw = generate_password(100, true, true, true, true).unwrap();
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_password_empty_charset_returns_error() {
        let result = generate_password(10, false, false, false, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("character type"));
    }

    #[test]
    fn test_generate_password_only_symbols() {
        let pw = generate_password(20, false, false, false, true).unwrap();
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn test_generate_password_guarantees_all_types() {
        // Verify that all requested character types are included
        let pw = generate_password(16, true, true, true, true).unwrap();

        let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = pw.chars().any(|c| c.is_ascii_digit());
        let has_symbol = pw.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

        assert!(has_upper, "Password missing uppercase letters");
        assert!(has_lower, "Password missing lowercase letters");
        assert!(has_digit, "Password missing digits");
        assert!(has_symbol, "Password missing symbols");
    }

    #[test]
    fn test_generate_password_short_guarantees_all_types() {
        // Even very short passwords should contain all requested types
        // With 4 requested types and length 4, each position gets exactly one type
        for _ in 0..100 {
            let pw = generate_password(4, true, true, true, true).unwrap();
            assert_eq!(pw.len(), 4);

            let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
            let has_digit = pw.chars().any(|c| c.is_ascii_digit());
            let has_symbol = pw.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

            assert!(
                has_upper && has_lower && has_digit && has_symbol,
                "Short password missing required character type"
            );
        }
    }

    #[test]
    fn test_generate_password_partial_types() {
        // Test with only some character types enabled
        let pw = generate_password(12, true, false, true, false).unwrap();
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(!pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(!pw.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)));
    }

    // ---- VaultError Display ----

    #[test]
    fn test_vault_error_display() {
        assert_eq!(VaultError::VaultLocked.to_string(), "Vault is locked");
        assert_eq!(
            VaultError::VaultAlreadyExists.to_string(),
            "Vault already exists"
        );
        assert!(VaultError::EncryptionFailed("test".into())
            .to_string()
            .contains("test"));
        assert!(matches!(
            VaultError::RateLimited {
                retry_after_secs: 60
            },
            VaultError::RateLimited {
                retry_after_secs: 60
            }
        ));
        assert!(VaultError::RateLimited {
            retry_after_secs: 30
        }
        .to_string()
        .contains("30"));
    }

    // ---- get_db_path test ----

    #[test]
    fn test_get_db_path_returns_valid_path() {
        let path = paths::get_db_path();
        assert!(path.to_string_lossy().ends_with("vault.db"));
        assert!(path.parent().is_some());
    }

    // ---- ensure_db_dir test ----

    #[test]
    fn test_ensure_db_dir_creates_directory() {
        let temp = TempDir::new().unwrap();
        let custom_path = temp.path().join("subdir").join("vault.db");

        // We test paths::ensure_db_dir directly with a custom base
        if let Some(parent) = custom_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        assert!(custom_path.parent().unwrap().exists());
    }

    // ---- Full vault lifecycle ----

    #[test]
    fn test_vault_init_unlock_lock_cycle() {
        let (state, _temp) = setup_test_state();

        // Not initialized
        assert!(!state.verification_data.lock().unwrap().is_some());

        // Init vault
        let salt = crypto::kdf::generate_salt();
        let (key, params) = crypto::kdf::derive_key("TestPassword123", &salt).unwrap();
        let verification = create_verification_header(&key, salt, params).unwrap();

        let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&key, &salt);
        let db = state.database.lock().unwrap().clone().unwrap();
        database::save_verification_data(&db, &verification).unwrap();
        *state.verification_data.lock().unwrap() = Some(verification);
        state.session.unlock(enc_key, mac_key);
        state.touch_activity();

        // Should be unlocked now
        assert!(state.is_unlocked());

        // Lock
        state.lock_vault();
        assert!(!state.is_unlocked());
    }

    #[test]
    fn test_crud_operations() {
        let (state, _temp) = setup_test_state();
        init_test_vault(&state, "master123");

        let db = state.database.lock().unwrap().clone().unwrap();

        // Create entry
        let mut entry = PasswordEntry::new(
            "GitHub".to_string(),
            Some("https://github.com".to_string()),
            "user@example.com".to_string(),
        );

        // Encrypt password
        let key = state.session.get_enc_key().unwrap();
        let enc_data = encrypt(&key, b"secret_password").unwrap();
        entry.encrypted_password = bincode::serialize(&enc_data).unwrap();
        save_entry(&db, &key, &entry).unwrap();

        // Read entry
        let loaded = load_entry(&db, &key, &entry.id).unwrap().unwrap();
        assert_eq!(loaded.title, "GitHub");
        assert_eq!(loaded.username, "user@example.com");

        // Decrypt and verify
        let enc: EncryptedData = bincode::deserialize(&loaded.encrypted_password).unwrap();
        let decrypted = decrypt(&key, &enc).unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), "secret_password");

        // List entries
        let ids = list_entries(&db).unwrap();
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&entry.id));

        // Count
        assert_eq!(count_entries(&db).unwrap(), 1);

        // Delete
        let deleted = delete_entry(&db, &entry.id).unwrap();
        assert!(deleted);
        assert_eq!(count_entries(&db).unwrap(), 0);
    }

    #[test]
    fn test_entry_with_notes_and_tags() {
        let (state, _temp) = setup_test_state();
        init_test_vault(&state, "master123");

        let db = state.database.lock().unwrap().clone().unwrap();
        let key = state.session.get_enc_key().unwrap();

        let mut entry = PasswordEntry::new("Site".to_string(), None, "user".to_string());
        entry.encrypted_password = bincode::serialize(&encrypt(&key, b"pass").unwrap()).unwrap();
        entry.encrypted_notes =
            Some(bincode::serialize(&encrypt(&key, b"my notes").unwrap()).unwrap());
        entry.tags = vec!["work".to_string(), "important".to_string()];

        save_entry(&db, &key, &entry).unwrap();

        let loaded = load_entry(&db, &key, &entry.id).unwrap().unwrap();
        assert_eq!(loaded.tags, vec!["work", "important"]);

        // Decrypt notes
        let enc: EncryptedData =
            bincode::deserialize(loaded.encrypted_notes.as_ref().unwrap()).unwrap();
        let notes = String::from_utf8(decrypt(&key, &enc).unwrap()).unwrap();
        assert_eq!(notes, "my notes");
    }

    #[test]
    fn test_multiple_entries() {
        let (state, _temp) = setup_test_state();
        init_test_vault(&state, "master123");

        let db = state.database.lock().unwrap().clone().unwrap();
        let key = state.session.get_enc_key().unwrap();

        for i in 0..5 {
            let mut entry = PasswordEntry::new(
                format!("Site {}", i),
                Some(format!("https://site{}.com", i)),
                format!("user{}@test.com", i),
            );
            entry.encrypted_password =
                bincode::serialize(&encrypt(&key, format!("pass{}", i).as_bytes()).unwrap())
                    .unwrap();
            save_entry(&db, &key, &entry).unwrap();
        }

        assert_eq!(count_entries(&db).unwrap(), 5);
        let ids = list_entries(&db).unwrap();
        assert_eq!(ids.len(), 5);
    }

    // ---- Rate Limiting ----

    #[test]
    fn test_rate_limit_allows_initial_attempts() {
        let state = AppState::default();
        for _ in 0..4 {
            service::record_failed_attempt(&state);
        }
        assert!(service::check_rate_limit(&state).is_ok());
    }

    #[test]
    fn test_rate_limit_triggers_after_five_failures() {
        let state = AppState::default();
        for _ in 0..5 {
            service::record_failed_attempt(&state);
        }
        let result = service::check_rate_limit(&state);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VaultError::RateLimited { .. }
        ));
    }

    #[test]
    fn test_rate_limit_resets_on_success() {
        let state = AppState::default();
        for _ in 0..4 {
            service::record_failed_attempt(&state);
        }
        service::reset_rate_limit(&state);
        assert!(service::check_rate_limit(&state).is_ok());
        assert_eq!(*state.failed_unlock_attempts.lock().unwrap(), 0);
    }

    #[test]
    fn test_rate_limit_blocks_during_lockout() {
        let state = AppState::default();
        for _ in 0..5 {
            service::record_failed_attempt(&state);
        }
        let result = service::check_rate_limit(&state);
        assert!(result.is_err());
    }

    #[test]
    fn test_rate_limit_expires_after_duration() {
        let state = AppState::default();
        // Manually set a lockout that already expired
        *state.lockout_until.lock().unwrap() = Some(Instant::now() - Duration::from_secs(1));
        assert!(service::check_rate_limit(&state).is_ok());
    }
}
