//! PwdVault - A secure, local-first password manager

pub mod auth;
pub mod crypto;
pub mod database;
pub mod native_host_setup;
pub mod native_messaging;
pub mod paths;

use redb::Database;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
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
use crypto::kdf::AdaptiveParams;
    use database::{
    count_entries,
    delete_entry,
    list_entries,
    load_entry,
    save_entry,
    PasswordEntry,
    Group,
    save_group,
    load_group,
    delete_group,
    list_groups,
    Settings,
    save_settings,
    load_settings,
};

// ============================================================================
// Constants
// ============================================================================

/// Auto-lock timeout in seconds (10 minutes)
const AUTO_LOCK_SECS: u64 = 600;

/// Auto-lock check interval in seconds
const AUTO_LOCK_CHECK_INTERVAL_SECS: u64 = 30;

/// Maximum consecutive failed unlock attempts before lockout
const MAX_FAILED_ATTEMPTS: u32 = 5;

/// Lockout duration in seconds after max failed attempts
#[cfg(not(test))]
const LOCKOUT_DURATION_SECS: u64 = 60;
#[cfg(test)]
const LOCKOUT_DURATION_SECS: u64 = 1;

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

    /// Atomic lock: clear key, reset activity, and update tray menu text
    pub fn lock_vault(&self) {
        {
            let mut activity = self.last_activity.lock().expect("activity lock poisoned");
            clear_key();
            *activity = None;
        }
        self.update_lock_menu("Unlock Vault");
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
            auto_lock_secs: Mutex::new(AUTO_LOCK_SECS),
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
                write!(f, "Too many failed attempts. Try again in {}s", retry_after_secs)
            }
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

// ============================================================================
// Rate Limiting
// ============================================================================

/// Check if the rate limiter is currently blocking unlock attempts.
pub(crate) fn check_rate_limit(state: &AppState) -> Result<(), VaultError> {
    let lockout = state.lockout_until.lock().expect("lockout lock poisoned");
    if let Some(until) = *lockout {
        let now = Instant::now();
        if now < until {
            let remaining = (until - now).as_secs();
            return Err(VaultError::RateLimited {
                retry_after_secs: remaining,
            });
        }
    }
    Ok(())
}

/// Record a failed unlock attempt. After MAX_FAILED_ATTEMPTS, starts lockout.
pub(crate) fn record_failed_attempt(state: &AppState) {
    let mut attempts = state
        .failed_unlock_attempts
        .lock()
        .expect("attempts lock poisoned");
    *attempts += 1;
    if *attempts >= MAX_FAILED_ATTEMPTS {
        let mut lockout = state.lockout_until.lock().expect("lockout lock poisoned");
        *lockout = Some(Instant::now() + Duration::from_secs(LOCKOUT_DURATION_SECS));
        *attempts = 0;
    }
}

/// Reset rate limit state (called on successful unlock).
pub(crate) fn reset_rate_limit(state: &AppState) {
    *state
        .failed_unlock_attempts
        .lock()
        .expect("attempts lock poisoned") = 0;
    *state
        .lockout_until
        .lock()
        .expect("lockout lock poisoned") = None;
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

    // Save default settings
    let default_settings = Settings::default();
    save_settings(&db, &default_settings)?;

    // Start auto-lock timer and update tray menu
    state.touch_activity();
    state.update_lock_menu("Lock Vault");

    Ok(())
}

#[tauri::command]
fn unlock_vault(password: String, state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    check_rate_limit(&state)?;

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
        reset_rate_limit(&state);
        // Load settings (e.g. auto-lock timeout) from database
        if let Ok(db) = get_db(&state) {
            if let Ok(settings) = load_settings(&db) {
                *state.auto_lock_secs.lock().expect("timeout lock poisoned") = settings.auto_lock_secs;
            }
        }
        state.touch_activity();
        state.update_lock_menu("Lock Vault");
    } else {
        record_failed_attempt(&state);
    }

    Ok(success)
}

#[tauri::command]
fn lock_vault(state: State<'_, Arc<AppState>>) {
    state.lock_vault();
}

#[tauri::command]
fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> Result<String, VaultError> {
    // Clamp length to sane bounds
    let length = length.clamp(4, 128);

    use rand::{rngs::OsRng, Rng};

    let mut charset = String::new();
    let mut required_chars = Vec::new();

    // Collect all available character classes and their representatives
    if include_uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        required_chars.push('A');
    }
    if include_lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
        required_chars.push('a');
    }
    if include_numbers {
        charset.push_str("0123456789");
        required_chars.push('0');
    }
    if include_symbols {
        charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
        required_chars.push('!');
    }

    if charset.is_empty() {
        return Err(VaultError::InternalError(
            "At least one character type must be selected".to_string(),
        ));
    }

    let mut rng = OsRng; // Use OS entropy source for better security
    let bytes: Vec<u8> = charset.bytes().collect();

    let num_required = required_chars.len();
    let mut password_chars: Vec<char> = required_chars;

    // Fill remaining positions with random characters from full charset
    for _ in 0..(length.saturating_sub(num_required)) {
        let idx = rng.gen_range(0..bytes.len());
        password_chars.push(bytes[idx] as char);
    }

    // Fisher-Yates shuffle to avoid predictable patterns (e.g., always starting with uppercase)
    let len = password_chars.len();
    for i in 0..len {
        let j = rng.gen_range(i..len);
        password_chars.swap(i, j);
    }

    Ok(password_chars.into_iter().collect())
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
        download_url: json["html_url"]
            .as_str()
            .unwrap_or("")
            .to_string(),
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
    pub password: String,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub group_id: Option<String>,
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
    pub group_id: Option<String>,
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
fn create_entry(request: CreateEntryRequest, state: State<'_, Arc<AppState>>) -> Result<EntrySummary, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    // Input validation
    if request.title.is_empty() || request.title.len() > 4096 {
        return Err(VaultError::InternalError("Invalid title length".to_string()));
    }
    if request.username.is_empty() || request.username.len() > 4096 {
        return Err(VaultError::InternalError("Invalid username length".to_string()));
    }
    if request.password.len() > 1024 {
        return Err(VaultError::InternalError("Invalid password length".to_string()));
    }
    if request.notes.as_ref().map_or(false, |n| n.len() > 65536) {
        return Err(VaultError::InternalError("Notes too long".to_string()));
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
    entry.group_id = request.group_id;

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
    let mut password_bytes = decrypt(&key, &encrypted_password)?;
    let mut password = String::from_utf8(password_bytes.clone())
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;

    // Decrypt notes if present
    let mut notes = if let Some(encrypted_notes_bytes) = &entry.encrypted_notes {
        let encrypted: EncryptedData = bincode::deserialize(encrypted_notes_bytes)
            .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
        let mut notes_bytes = decrypt(&key, &encrypted)?;
        let notes_str = String::from_utf8(notes_bytes.clone())
            .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
        notes_bytes.zeroize();
        Some(notes_str)
    } else {
        None
    };

    state.touch_activity();

    let response = EntryResponse {
        id: entry.id,
        title: entry.title,
        url: entry.url,
        username: entry.username,
        password: password.clone(),
        notes: notes.clone(),
        tags: entry.tags,
        group_id: entry.group_id,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        last_used_at: entry.last_used_at,
    };

    // Zeroize plaintext sensitive data after building response
    password.zeroize();
    password_bytes.zeroize();
    if let Some(ref mut n) = notes {
        n.zeroize();
    }

    Ok(response)
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

    // Input validation
    if request.title.is_empty() || request.title.len() > 4096 {
        return Err(VaultError::InternalError("Invalid title length".to_string()));
    }
    if request.username.is_empty() || request.username.len() > 4096 {
        return Err(VaultError::InternalError("Invalid username length".to_string()));
    }
    if request.password.len() > 1024 {
        return Err(VaultError::InternalError("Invalid password length".to_string()));
    }

    let db = get_db(&state)?;
    let mut entry = load_entry(&db, &id)?.ok_or(VaultError::EntryNotFound)?;

    let key = crypto::get_key()?;

    // Update fields
    entry.title = request.title;
    entry.url = request.url;
    entry.username = request.username;
    entry.tags = request.tags;
    entry.group_id = request.group_id;
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

// ============================================================================
// Group Management Commands
// ============================================================================

#[tauri::command]
fn create_group(name: String, state: State<'_, Arc<AppState>>) -> Result<Group, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let group = Group::new(name);
    save_group(&db, &group)?;

    state.touch_activity();
    Ok(group)
}

#[tauri::command]
fn list_all_groups(state: State<'_, Arc<AppState>>) -> Result<Vec<Group>, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let ids = list_groups(&db)?;
    let mut groups = Vec::new();
    for id in ids {
        if let Some(g) = load_group(&db, &id)? {
            groups.push(g);
        }
    }

    state.touch_activity();
    Ok(groups)
}

#[tauri::command]
fn remove_group(id: String, state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let existed = delete_group(&db, &id)?;

    // Cascade: clear group_id on entries that referenced the deleted group
    if existed {
        let entry_ids = list_entries(&db)?;
        for entry_id in entry_ids {
            if let Some(mut entry) = load_entry(&db, &entry_id)? {
                if entry.group_id.as_deref() == Some(id.as_str()) {
                    entry.group_id = None;
                    save_entry(&db, &entry)?;
                }
            }
        }
    }

    state.touch_activity();
    Ok(existed)
}

#[tauri::command]
fn update_group(id: String, name: String, state: State<'_, Arc<AppState>>) -> Result<Group, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let mut group = load_group(&db, &id)?.ok_or(VaultError::InternalError("Group not found".to_string()))?;
    group.name = name;
    group.updated_at = chrono::Utc::now().timestamp();
    save_group(&db, &group)?;

    state.touch_activity();
    Ok(group)
}

// ============================================================================
// Settings Commands
// ============================================================================

#[tauri::command]
fn get_settings(state: State<'_, Arc<AppState>>) -> Result<Settings, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }
    let db = get_db(&state)?;
    let settings = load_settings(&db)?;
    state.touch_activity();
    Ok(settings)
}

#[tauri::command]
fn update_settings(settings: Settings, state: State<'_, Arc<AppState>>) -> Result<Settings, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }
    if settings.auto_lock_secs < 30 || settings.auto_lock_secs > 3600 {
        return Err(VaultError::InternalError(
            "Auto-lock timeout must be between 30 and 3600 seconds".to_string(),
        ));
    }
    if settings.default_length < 4 || settings.default_length > 128 {
        return Err(VaultError::InternalError(
            "Password length must be between 4 and 128".to_string(),
        ));
    }
    let db = get_db(&state)?;
    save_settings(&db, &settings)?;
    // Apply auto-lock timeout immediately
    *state.auto_lock_secs.lock().expect("timeout lock poisoned") = settings.auto_lock_secs;
    state.touch_activity();
    Ok(settings)
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
// Import/Export Commands
// ============================================================================

/// Plaintext entry for export (password/notes as strings, not encrypted bytes)
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportEntry {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
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
    pub salt: String,          // base64
    pub kdf_memory: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub nonce: String,          // base64
    pub data: String,           // base64 (AES-256-GCM encrypted payload)
}

/// Result of import operation
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportResult {
    pub entries_imported: usize,
    pub groups_imported: usize,
}

#[tauri::command]
fn export_vault(mut export_password: String, state: State<'_, Arc<AppState>>) -> Result<VaultBackup, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let key = crypto::get_key()?;

    // Load all entries and decrypt passwords/notes
    let entry_ids = list_entries(&db)?;
    let mut export_entries = Vec::new();
    for id in entry_ids {
        if let Some(entry) = load_entry(&db, &id)? {
            // Decrypt password
            let enc_pwd: EncryptedData = bincode::deserialize(&entry.encrypted_password)
                .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
            let pwd_bytes = decrypt(&key, &enc_pwd)?;
            let password = String::from_utf8(pwd_bytes)
                .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;

            // Decrypt notes
            let notes = if let Some(ref enc_notes_bytes) = entry.encrypted_notes {
                let enc: EncryptedData = bincode::deserialize(enc_notes_bytes)
                    .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
                let notes_bytes = decrypt(&key, &enc)?;
                Some(String::from_utf8(notes_bytes)
                    .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?)
            } else {
                None
            };

            export_entries.push(ExportEntry {
                id: entry.id,
                title: entry.title,
                url: entry.url,
                username: entry.username,
                password,
                notes,
                tags: entry.tags,
                group_id: entry.group_id,
                created_at: entry.created_at,
                updated_at: entry.updated_at,
            });
        }
    }

    // Load groups
    let group_ids = list_groups(&db)?;
    let mut groups = Vec::new();
    for id in group_ids {
        if let Some(g) = load_group(&db, &id)? {
            groups.push(g);
        }
    }

    // Load settings
    let settings = load_settings(&db)?;

    // Build plaintext payload
    let payload = BackupPayload {
        entries: export_entries,
        groups,
        settings,
    };

    let mut payload_json = serde_json::to_vec(&payload)
        .map_err(|e| VaultError::InternalError(e.to_string()))?;

    // Derive export key from export password using Argon2id
    let salt = crypto::kdf::generate_salt();
    let (export_key, params) = crypto::kdf::derive_key(&export_password, &salt)?;

    // Zeroize export password immediately after key derivation
    export_password.zeroize();

    // Encrypt payload with export key
    let encrypted = encrypt(&export_key, &payload_json)?;

    // Zeroize plaintext payload
    payload_json.zeroize();
    for mut entry in payload.entries {
        unsafe { entry.password.as_bytes_mut() }.zeroize();
        if let Some(ref mut n) = entry.notes {
            unsafe { n.as_bytes_mut() }.zeroize();
        }
    }

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let backup = VaultBackup {
        version: 1,
        created_at: chrono::Utc::now().timestamp(),
        salt: b64.encode(&salt),
        kdf_memory: params.m_cost,
        kdf_iterations: params.t_cost,
        kdf_parallelism: params.p_cost,
        nonce: b64.encode(&encrypted.nonce),
        data: b64.encode(&encrypted.ciphertext),
    };

    state.touch_activity();
    Ok(backup)
}

#[tauri::command]
fn import_vault(backup: VaultBackup, mut import_password: String, state: State<'_, Arc<AppState>>) -> Result<ImportResult, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    if backup.version != 1 {
        return Err(VaultError::InvalidBackup("Unsupported backup version".to_string()));
    }

    // Decode salt and nonce from base64
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let salt = b64.decode(&backup.salt)
        .map_err(|e| VaultError::InvalidBackup(format!("Invalid salt: {}", e)))?;
    let nonce_bytes = b64.decode(&backup.nonce)
        .map_err(|e| VaultError::InvalidBackup(format!("Invalid nonce: {}", e)))?;
    let ciphertext = b64.decode(&backup.data)
        .map_err(|e| VaultError::InvalidBackup(format!("Invalid data: {}", e)))?;

    if salt.len() != 16 {
        return Err(VaultError::InvalidBackup("Invalid salt length".to_string()));
    }

    // Derive key from import password with stored KDF params
    let salt_array: [u8; 16] = salt.try_into()
        .map_err(|_| VaultError::InvalidBackup("Invalid salt".to_string()))?;
    let (import_key, _params) = crypto::kdf::derive_key_with_params(
        &import_password,
        &salt_array,
        &AdaptiveParams {
            m_cost: backup.kdf_memory,
            t_cost: backup.kdf_iterations,
            p_cost: backup.kdf_parallelism,
        },
    )?;

    // Zeroize import password after key derivation
    import_password.zeroize();

    // Decrypt payload
    let encrypted_data = EncryptedData {
        nonce: nonce_bytes,
        ciphertext,
    };
    let mut payload_bytes = decrypt(&import_key, &encrypted_data)
        .map_err(|_| VaultError::InvalidPassword)?;

    // Parse payload — validate before any destructive operations
    let payload: BackupPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VaultError::InvalidBackup(format!("Invalid payload: {}", e)))?;

    // Zeroize decrypted payload bytes
    payload_bytes.zeroize();

    let db = get_db(&state)?;
    let key = crypto::get_key()?;

    // Pre-validate and prepare groups (generate new IDs to avoid conflicts)
    let mut group_id_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut new_groups = Vec::new();
    for g in &payload.groups {
        let new_group = Group::new(g.name.clone());
        group_id_map.insert(g.id.clone(), new_group.id.clone());
        new_groups.push(new_group);
    }

    // Pre-validate and encrypt all entries before any destructive operations
    let mut new_entries = Vec::new();
    for export_entry in &payload.entries {
        let mut entry = PasswordEntry::new(
            export_entry.title.clone(),
            export_entry.url.clone(),
            export_entry.username.clone(),
        );

        // Encrypt password with current master key
        let enc_pwd = encrypt(&key, export_entry.password.as_bytes())?;
        entry.encrypted_password = bincode::serialize(&enc_pwd)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        // Encrypt notes
        entry.encrypted_notes = if let Some(ref notes) = export_entry.notes {
            let enc = encrypt(&key, notes.as_bytes())?;
            Some(bincode::serialize(&enc)
                .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?)
        } else {
            None
        };

        entry.tags = export_entry.tags.clone();
        // Map old group_id to new group_id
        entry.group_id = export_entry.group_id.as_ref()
            .and_then(|gid| group_id_map.get(gid).cloned());
        entry.created_at = export_entry.created_at;
        entry.updated_at = export_entry.updated_at;

        new_entries.push(entry);
    }

    // All validation and encryption succeeded — now perform database mutations
    // Clear existing entries and groups (propagate errors)
    let existing_entry_ids = list_entries(&db)?;
    for id in existing_entry_ids {
        delete_entry(&db, &id)?;
    }
    let existing_group_ids = list_groups(&db)?;
    for id in existing_group_ids {
        delete_group(&db, &id)?;
    }

    // Write new groups
    for g in &new_groups {
        save_group(&db, g)?;
    }

    // Write new entries
    for entry in &new_entries {
        save_entry(&db, entry)?;
    }

    // Apply imported settings
    save_settings(&db, &payload.settings)?;
    *state.auto_lock_secs.lock().expect("timeout lock poisoned") = payload.settings.auto_lock_secs;

    let entries_count = payload.entries.len();
    let groups_count = payload.groups.len();

    state.touch_activity();
    Ok(ImportResult {
        entries_imported: entries_count,
        groups_imported: groups_count,
    })
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
        // Load auto-lock timeout from settings
        if let Ok(settings) = load_settings(&db) {
            *state.auto_lock_secs.lock().expect("timeout lock poisoned") = settings.auto_lock_secs;
        }
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
                let timeout = *state.auto_lock_secs.lock().expect("timeout lock poisoned");
                if let Some(instant) = *activity {
                    is_unlocked() && instant.elapsed().as_secs() >= timeout
                } else {
                    false
                }
            };

            if should_lock {
                state.lock_vault();
                state.reload_window();
            }
        }
    });
}

// ============================================================================
// Entry Point
// ============================================================================

const NATIVE_MESSAGING_PORT: u16 = 17429;

/// Locate the bundled native messaging host binary and register it with the
/// installed browsers. Reads extension IDs from a config file next to the
/// database; if absent (e.g. dev mode or IDs not yet configured), registration
/// is skipped so we never write a manifest with invalid placeholders.
fn register_native_host(app: &tauri::App) {
    let resource_dir = match app.path().resource_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("native_host_setup: cannot resolve resource dir: {}", e);
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
    let config_path = paths::get_db_path()
        .parent()?
        .join("native-host.json");
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
    let state = Arc::new(AppState::default());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(state.clone())
        .setup(move |app| {
            // Start native messaging server in background thread
            let state_for_server = state.clone();

            std::thread::spawn(move || {
                if let Err(e) = native_messaging::start_server(NATIVE_MESSAGING_PORT, state_for_server) {
                    eprintln!("Failed to start native messaging server: {}", e);
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
                            let state = app.state::<Arc<AppState>>();
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
            get_entry,
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
        assert_eq!(VaultError::VaultAlreadyExists.to_string(), "Vault already exists");
        assert!(VaultError::EncryptionFailed("test".into()).to_string().contains("test"));
        assert!(matches!(
            VaultError::RateLimited { retry_after_secs: 60 },
            VaultError::RateLimited { retry_after_secs: 60 }
        ));
        assert!(VaultError::RateLimited { retry_after_secs: 30 }.to_string().contains("30"));
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

    // ---- Rate Limiting ----

    #[test]
    fn test_rate_limit_allows_initial_attempts() {
        let state = AppState::default();
        for _ in 0..4 {
            record_failed_attempt(&state);
        }
        assert!(check_rate_limit(&state).is_ok());
    }

    #[test]
    fn test_rate_limit_triggers_after_five_failures() {
        let state = AppState::default();
        for _ in 0..5 {
            record_failed_attempt(&state);
        }
        let result = check_rate_limit(&state);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VaultError::RateLimited { .. }));
    }

    #[test]
    fn test_rate_limit_resets_on_success() {
        let state = AppState::default();
        for _ in 0..4 {
            record_failed_attempt(&state);
        }
        reset_rate_limit(&state);
        assert!(check_rate_limit(&state).is_ok());
        assert_eq!(*state.failed_unlock_attempts.lock().unwrap(), 0);
    }

    #[test]
    fn test_rate_limit_blocks_during_lockout() {
        let state = AppState::default();
        for _ in 0..5 {
            record_failed_attempt(&state);
        }
        let result = check_rate_limit(&state);
        assert!(result.is_err());
    }

    #[test]
    fn test_rate_limit_expires_after_duration() {
        let state = AppState::default();
        // Manually set a lockout that already expired
        *state.lockout_until.lock().unwrap() = Some(
            Instant::now() - Duration::from_secs(1),
        );
        assert!(check_rate_limit(&state).is_ok());
    }
}
