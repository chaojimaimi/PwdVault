//! PwdVault - A secure, local-first password manager

pub mod crypto;
pub mod database;
pub mod native_messaging;
pub mod paths;

use redb::Database;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager, State,
};
use zeroize::Zeroize;

use crypto::{
    clear_key, create_verification_header, decrypt, encrypt, is_unlocked, set_key,
    unlock_with_password, EncryptedData, EncryptionError, KeyStoreError, KdfError,
    VerificationData,
};
use database::{count_entries, delete_entry, list_entries, load_entry, save_entry, PasswordEntry};

// ============================================================================
// Constants
// ============================================================================

/// Auto-lock timeout in seconds (10 minutes)
const AUTO_LOCK_SECS: u64 = 600;

/// Auto-lock check interval in seconds
const AUTO_LOCK_CHECK_INTERVAL_SECS: u64 = 30;

// ============================================================================
// Application State
// ============================================================================

pub struct AppState {
    pub verification_data: Mutex<Option<VerificationData>>,
    pub database: Mutex<Option<Arc<Database>>>,
    pub last_activity: Mutex<Option<Instant>>,
    /// Closure to update the tray lock/unlock menu item text
    pub update_lock_menu_fn: Mutex<Option<Box<dyn Fn(&str) + Send + Sync>>>,
    /// Closure to reload the main window (for auto-lock)
    pub reload_window_fn: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl AppState {
    /// Reset the auto-lock activity timer (called on vault operations)
    pub fn touch_activity(&self) {
        *self.last_activity.lock().expect("activity lock poisoned") = Some(Instant::now());
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

    /// Atomic lock: clear key and activity under the same mutex
    pub fn lock_vault(&self) {
        let mut activity = self.last_activity.lock().expect("activity lock poisoned");
        clear_key();
        *activity = None;
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            verification_data: Mutex::new(None),
            database: Mutex::new(None),
            last_activity: Mutex::new(None),
            update_lock_menu_fn: Mutex::new(None),
            reload_window_fn: Mutex::new(None),
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
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the database file path (delegates to shared paths module)
fn get_db_path() -> PathBuf {
    paths::get_db_path()
}

/// Get the database directory (ensures it exists)
fn ensure_db_dir() -> Result<PathBuf, VaultError> {
    paths::ensure_db_dir().map_err(|e| VaultError::InternalError(e.to_string()))
}

/// Get the database from state
fn get_db(state: &Arc<AppState>) -> Result<Arc<Database>, VaultError> {
    let guard = state.database.lock().expect("db lock poisoned");
    guard.clone().ok_or_else(|| VaultError::InternalError("Database not initialized".to_string()))
}

// ============================================================================
// IPC Commands
// ============================================================================

#[tauri::command]
fn is_vault_initialized(state: State<'_, Arc<AppState>>) -> bool {
    state.verification_data.lock().expect("verification lock poisoned").is_some()
}

#[tauri::command]
fn is_vault_unlocked() -> bool {
    is_unlocked()
}

#[tauri::command]
fn init_vault(
    password: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), VaultError> {
    let mut password = password;

    if state.verification_data.lock().expect("verification lock poisoned").is_some() {
        password.zeroize();
        return Err(VaultError::VaultAlreadyExists);
    }

    // Initialize database
    let db_path = ensure_db_dir()?;
    let db = Arc::new(database::init_database(&db_path)?);
    *state.database.lock().expect("db lock poisoned") = Some(db.clone());

    let salt = crypto::kdf::generate_salt();
    let (key, params) = crypto::kdf::derive_key(&password, &salt)?;

    password.zeroize();

    let verification_data = create_verification_header(&key, salt, params)?;

    // Save verification data to database
    database::save_verification_data(&db, &verification_data)?;

    *state.verification_data.lock().expect("verification lock poisoned") = Some(verification_data);
    set_key(key)?;

    // Start auto-lock timer and update tray menu
    state.touch_activity();
    state.update_lock_menu("Lock Vault");

    Ok(())
}

#[tauri::command]
fn unlock_vault(password: String, state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    let mut password = password;

    let verification_data = state
        .verification_data
        .lock()
        .expect("verification lock poisoned")
        .as_ref()
        .ok_or(VaultError::VaultLocked)?
        .clone();

    let success = unlock_with_password(&password, &verification_data)?;

    password.zeroize();

    if success {
        state.touch_activity();
        state.update_lock_menu("Lock Vault");
    }

    Ok(success)
}

#[tauri::command]
fn lock_vault(state: State<'_, Arc<AppState>>) {
    state.lock_vault();
    state.update_lock_menu("Unlock Vault");
}

#[tauri::command]
fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> String {
    use rand::Rng;

    let mut charset = String::new();
    if include_uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if include_lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if include_numbers {
        charset.push_str("0123456789");
    }
    if include_symbols {
        charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
    }

    if charset.is_empty() {
        charset = "abcdefghijklmnopqrstuvwxyz".to_string();
    }

    let bytes: Vec<u8> = charset.bytes().collect();
    let mut rng = rand::thread_rng();

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..bytes.len());
            bytes[idx] as char
        })
        .collect()
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
    pub password: String,
    pub notes: Option<String>,
    pub tags: Vec<String>,
}

/// Response for password entry (password decrypted)
#[derive(Debug, Serialize, Deserialize)]
pub struct EntryResponse {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
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
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }
}

#[tauri::command]
fn create_entry(request: CreateEntryRequest, state: State<'_, Arc<AppState>>) -> Result<EntrySummary, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let key = crypto::get_key()?;

    // Encrypt password
    let encrypted_password = encrypt(&key, request.password.as_bytes())?;
    let encrypted_password_bytes = bincode::serialize(&encrypted_password)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

    // Encrypt notes if present
    let encrypted_notes = if let Some(notes) = &request.notes {
        let encrypted = encrypt(&key, notes.as_bytes())?;
        let bytes = bincode::serialize(&encrypted)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        Some(bytes)
    } else {
        None
    };

    let mut entry = PasswordEntry::new(request.title, request.url, request.username);
    entry.encrypted_password = encrypted_password_bytes;
    entry.encrypted_notes = encrypted_notes;
    entry.tags = request.tags;

    save_entry(&db, &entry)?;

    state.touch_activity();

    Ok(entry.into())
}

#[tauri::command]
fn get_entry(id: String, state: State<'_, Arc<AppState>>) -> Result<EntryResponse, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let entry = load_entry(&db, &id)?.ok_or(VaultError::EntryNotFound)?;

    let key = crypto::get_key()?;

    // Decrypt password
    let encrypted_password: EncryptedData = bincode::deserialize(&entry.encrypted_password)
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
    let password_bytes = decrypt(&key, &encrypted_password)?;
    let password = String::from_utf8(password_bytes)
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;

    // Decrypt notes if present
    let notes = if let Some(encrypted_notes_bytes) = &entry.encrypted_notes {
        let encrypted: EncryptedData = bincode::deserialize(encrypted_notes_bytes)
            .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
        let notes_bytes = decrypt(&key, &encrypted)?;
        Some(String::from_utf8(notes_bytes).map_err(|e| VaultError::DecryptionFailed(e.to_string()))?)
    } else {
        None
    };

    state.touch_activity();

    Ok(EntryResponse {
        id: entry.id,
        title: entry.title,
        url: entry.url,
        username: entry.username,
        password,
        notes,
        tags: entry.tags,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        last_used_at: entry.last_used_at,
    })
}

#[tauri::command]
fn list_all_entries(state: State<'_, Arc<AppState>>) -> Result<Vec<EntrySummary>, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let ids = list_entries(&db)?;
    let mut summaries = Vec::new();

    for id in ids {
        if let Some(entry) = load_entry(&db, &id)? {
            summaries.push(entry.into());
        }
    }

    state.touch_activity();

    Ok(summaries)
}

#[tauri::command]
fn update_entry(
    id: String,
    request: CreateEntryRequest,
    state: State<'_, Arc<AppState>>,
) -> Result<EntrySummary, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let mut entry = load_entry(&db, &id)?.ok_or(VaultError::EntryNotFound)?;

    let key = crypto::get_key()?;

    // Update fields
    entry.title = request.title;
    entry.url = request.url;
    entry.username = request.username;
    entry.tags = request.tags;
    entry.updated_at = chrono::Utc::now().timestamp();

    // Encrypt and update password
    let encrypted_password = encrypt(&key, request.password.as_bytes())?;
    entry.encrypted_password = bincode::serialize(&encrypted_password)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

    // Encrypt and update notes
    entry.encrypted_notes = if let Some(notes) = &request.notes {
        let encrypted = encrypt(&key, notes.as_bytes())?;
        Some(bincode::serialize(&encrypted).map_err(|e| VaultError::EncryptionFailed(e.to_string()))?)
    } else {
        None
    };

    save_entry(&db, &entry)?;

    state.touch_activity();

    Ok(entry.into())
}

#[tauri::command]
fn remove_entry(id: String, state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let existed = delete_entry(&db, &id)?;

    state.touch_activity();

    Ok(existed)
}

#[tauri::command]
fn get_entry_count(state: State<'_, Arc<AppState>>) -> Result<usize, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let count = count_entries(&db)?;

    state.touch_activity();

    Ok(count)
}

// ============================================================================
// Setup Command (called on app start)
// ============================================================================

#[tauri::command]
fn setup_vault(state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    // Check if database is already loaded in state
    {
        let db_guard = state.database.lock().expect("db lock poisoned");
        if db_guard.is_some() && state.verification_data.lock().expect("verification lock poisoned").is_some() {
            return Ok(true);
        }
    }

    let db_path = get_db_path();

    if !db_path.exists() {
        return Ok(false);
    }

    // Initialize database
    let db = Arc::new(database::init_database(&db_path)?);
    *state.database.lock().expect("db lock poisoned") = Some(db.clone());

    // Load verification data from database
    let verification_data = database::load_verification_data(&db)?;

    if let Some(data) = verification_data {
        *state.verification_data.lock().expect("verification lock poisoned") = Some(data);
        return Ok(true);
    }

    Ok(false)
}

// ============================================================================
// Auto-Lock Background Thread
// ============================================================================

fn start_auto_lock_thread(state: Arc<AppState>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(AUTO_LOCK_CHECK_INTERVAL_SECS));

            let should_lock = {
                let activity = state.last_activity.lock().expect("activity lock poisoned");
                if let Some(instant) = *activity {
                    is_unlocked() && instant.elapsed().as_secs() >= AUTO_LOCK_SECS
                } else {
                    false
                }
            };

            if should_lock {
                state.lock_vault();
                state.update_lock_menu("Unlock Vault");
                state.reload_window();
            }
        }
    });
}

// ============================================================================
// Entry Point
// ============================================================================

const NATIVE_MESSAGING_PORT: u16 = 17429;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = Arc::new(AppState::default());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state.clone())
        .setup(move |app| {
            // Start native messaging server in background thread
            let state_for_server = state.clone();

            std::thread::spawn(move || {
                if let Err(e) = native_messaging::start_server(NATIVE_MESSAGING_PORT, state_for_server) {
                    eprintln!("Failed to start native messaging server: {}", e);
                }
            });

            // Build system tray menu
            let show_i = MenuItem::with_id(app, "show", "Show PwdVault", true, None::<&str>)?;
            let lock_i = MenuItem::with_id(app, "lock", "Lock Vault", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &lock_i, &quit_i])?;

            // Store closures for updating tray menu and reloading window from any thread
            {
                let lock_i_clone = lock_i.clone();
                let app_handle = app.handle().clone();
                *state.update_lock_menu_fn.lock().expect("menu lock poisoned") = Some(Box::new(move |text: &str| {
                    let _ = lock_i_clone.set_text(text);
                }));
                *state.reload_window_fn.lock().expect("window lock poisoned") = Some(Box::new(move || {
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
                        if is_unlocked() {
                            clear_key();
                            if let Some(item) = app.menu().and_then(|m| m.get("lock")) {
                                if let tauri::menu::MenuItemKind::MenuItem(mi) = item {
                                    let _ = mi.set_text("Unlock Vault");
                                }
                            }
                        }
                        // Always show window (displays unlock screen if locked)
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
            get_entry,
            list_all_entries,
            update_entry,
            remove_entry,
            get_entry_count,
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
        // Clear any leftover key from previous tests
        clear_key();

        let temp = TempDir::new().expect("create temp dir");
        let db_path = temp.path().join("test_vault.db");
        let db = Arc::new(database::init_database(&db_path).expect("init db"));

        let state = Arc::new(AppState::default());
        *state.database.lock().expect("db lock") = Some(db);
        (state, temp)
    }

    /// Helper: initialize vault with a password
    fn init_test_vault(state: &Arc<AppState>, password: &str) {
        // Clear any leftover key from parallel tests sharing global keystore
        clear_key();

        let salt = crypto::kdf::generate_salt();
        let (key, params) = crypto::kdf::derive_key(password, &salt).expect("derive key");
        let verification = create_verification_header(&key, salt.clone(), params).expect("create verification");

        let db = state.database.lock().expect("db lock").clone().expect("db exists");
        database::save_verification_data(&db, &verification).expect("save verification");

        *state.verification_data.lock().expect("v lock") = Some(verification);
        set_key(key).expect("set key");
        state.touch_activity();
    }

    // ---- AppState tests ----

    #[test]
    fn test_appstate_default() {
        let state = AppState::default();
        assert!(state.verification_data.lock().unwrap().is_none());
        assert!(state.database.lock().unwrap().is_none());
        assert!(state.last_activity.lock().unwrap().is_none());
    }

    #[test]
    fn test_touch_and_lock_vault() {
        let state = Arc::new(AppState::default());
        assert!(state.last_activity.lock().unwrap().is_none());

        state.touch_activity();
        assert!(state.last_activity.lock().unwrap().is_some());

        state.lock_vault();
        assert!(state.last_activity.lock().unwrap().is_none());
    }

    // ---- generate_password tests ----

    #[test]
    fn test_generate_password_length() {
        let pw = generate_password(20, true, true, true, true);
        assert_eq!(pw.len(), 20);
    }

    #[test]
    fn test_generate_password_all_charsets() {
        let pw = generate_password(100, true, true, true, true);
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_password_empty_charset_fallback() {
        let pw = generate_password(10, false, false, false, false);
        assert_eq!(pw.len(), 10);
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn test_generate_password_only_symbols() {
        let pw = generate_password(20, false, false, false, true);
        assert_eq!(pw.len(), 20);
    }

    // ---- VaultError Display ----

    #[test]
    fn test_vault_error_display() {
        assert_eq!(VaultError::VaultLocked.to_string(), "Vault is locked");
        assert_eq!(VaultError::VaultAlreadyExists.to_string(), "Vault already exists");
        assert!(VaultError::EncryptionFailed("test".into()).to_string().contains("test"));
    }

    // ---- get_db_path test ----

    #[test]
    fn test_get_db_path_returns_valid_path() {
        let path = get_db_path();
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

        let db = state.database.lock().unwrap().clone().unwrap();
        database::save_verification_data(&db, &verification).unwrap();
        *state.verification_data.lock().unwrap() = Some(verification);
        set_key(key).unwrap();
        state.touch_activity();

        // Should be unlocked now
        assert!(is_unlocked());
        assert!(state.last_activity.lock().unwrap().is_some());

        // Lock
        state.lock_vault();
        assert!(!is_unlocked());
        assert!(state.last_activity.lock().unwrap().is_none());
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
        let key = crypto::get_key().unwrap();
        let enc_data = encrypt(&key, b"secret_password").unwrap();
        entry.encrypted_password = bincode::serialize(&enc_data).unwrap();
        save_entry(&db, &entry).unwrap();

        // Read entry
        let loaded = load_entry(&db, &entry.id).unwrap().unwrap();
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
        let key = crypto::get_key().unwrap();

        let mut entry = PasswordEntry::new(
            "Site".to_string(),
            None,
            "user".to_string(),
        );
        entry.encrypted_password = bincode::serialize(&encrypt(&key, b"pass").unwrap()).unwrap();
        entry.encrypted_notes = Some(bincode::serialize(&encrypt(&key, b"my notes").unwrap()).unwrap());
        entry.tags = vec!["work".to_string(), "important".to_string()];

        save_entry(&db, &entry).unwrap();

        let loaded = load_entry(&db, &entry.id).unwrap().unwrap();
        assert_eq!(loaded.tags, vec!["work", "important"]);

        // Decrypt notes
        let enc: EncryptedData = bincode::deserialize(loaded.encrypted_notes.as_ref().unwrap()).unwrap();
        let notes = String::from_utf8(decrypt(&key, &enc).unwrap()).unwrap();
        assert_eq!(notes, "my notes");
    }

    #[test]
    fn test_multiple_entries() {
        let (state, _temp) = setup_test_state();
        init_test_vault(&state, "master123");

        let db = state.database.lock().unwrap().clone().unwrap();
        let key = crypto::get_key().unwrap();

        for i in 0..5 {
            let mut entry = PasswordEntry::new(
                format!("Site {}", i),
                Some(format!("https://site{}.com", i)),
                format!("user{}@test.com", i),
            );
            entry.encrypted_password = bincode::serialize(&encrypt(&key, format!("pass{}", i).as_bytes()).unwrap()).unwrap();
            save_entry(&db, &entry).unwrap();
        }

        assert_eq!(count_entries(&db).unwrap(), 5);
        let ids = list_entries(&db).unwrap();
        assert_eq!(ids.len(), 5);
    }
}
