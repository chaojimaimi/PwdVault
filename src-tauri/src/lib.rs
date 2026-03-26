//! PwdVault - A secure, local-first password manager

pub mod crypto;
pub mod database;
pub mod native_messaging;

use redb::Database;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use tauri::State;
use zeroize::Zeroize;

use crypto::{
    clear_key, create_verification_header, decrypt, encrypt, is_unlocked, set_key,
    unlock_with_password, EncryptedData, EncryptionError, KeyStoreError, KdfError,
    VerificationData,
};
use database::{count_entries, delete_entry, list_entries, load_entry, save_entry, PasswordEntry};

// ============================================================================
// Application State
// ============================================================================

pub struct AppState {
    pub verification_data: Mutex<Option<VerificationData>>,
    pub database: Mutex<Option<Arc<Database>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            verification_data: Mutex::new(None),
            database: Mutex::new(None),
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

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the database file path
/// Uses a consistent platform-specific app data directory
fn get_db_path() -> PathBuf {
    // Use platform-specific app data directory
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

/// Get the database directory (ensures it exists)
fn ensure_db_dir() -> Result<PathBuf, VaultError> {
    let db_path = get_db_path();
    eprintln!("[DEBUG] Database path: {:?}", db_path);
    if let Some(parent) = db_path.parent() {
        eprintln!("[DEBUG] Parent directory: {:?}", parent);
        std::fs::create_dir_all(parent)
            .map_err(|e| VaultError::InternalError(e.to_string()))?;
    }
    Ok(db_path)
}

/// Get the database from state
fn get_db(state: &Arc<AppState>) -> Result<Arc<Database>, VaultError> {
    let guard = state.database.lock().unwrap();
    guard.clone().ok_or_else(|| VaultError::InternalError("Database not initialized".to_string()))
}

// ============================================================================
// IPC Commands
// ============================================================================

#[tauri::command]
fn is_vault_initialized(state: State<'_, Arc<AppState>>) -> bool {
    state.verification_data.lock().unwrap().is_some()
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

    if state.verification_data.lock().unwrap().is_some() {
        password.zeroize();
        return Err(VaultError::VaultAlreadyExists);
    }

    // Initialize database
    let db_path = ensure_db_dir()?;
    let db = Arc::new(database::init_database(&db_path)?);
    *state.database.lock().unwrap() = Some(db.clone());

    let salt = crypto::kdf::generate_salt();
    let (key, params) = crypto::kdf::derive_key(&password, &salt)?;

    password.zeroize();

    let verification_data = create_verification_header(&key, salt, params)?;

    // Save verification data to database
    database::save_verification_data(&db, &verification_data)?;

    *state.verification_data.lock().unwrap() = Some(verification_data);
    set_key(key)?;

    Ok(())
}

#[tauri::command]
fn unlock_vault(password: String, state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    let mut password = password;

    let verification_data = state
        .verification_data
        .lock()
        .unwrap()
        .as_ref()
        .ok_or(VaultError::VaultLocked)?
        .clone();

    let success = unlock_with_password(&password, &verification_data)?;

    password.zeroize();

    Ok(success)
}

#[tauri::command]
fn lock_vault() {
    clear_key();
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

    Ok(entry.into())
}

#[tauri::command]
fn remove_entry(id: String, state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    let existed = delete_entry(&db, &id)?;
    Ok(existed)
}

#[tauri::command]
fn get_entry_count(state: State<'_, Arc<AppState>>) -> Result<usize, VaultError> {
    if !is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(&state)?;
    Ok(count_entries(&db)?)
}

// ============================================================================
// Setup Command (called on app start)
// ============================================================================

#[tauri::command]
fn setup_vault(state: State<'_, Arc<AppState>>) -> Result<bool, VaultError> {
    // Check if database is already loaded in state
    {
        let db_guard = state.database.lock().unwrap();
        if db_guard.is_some() && state.verification_data.lock().unwrap().is_some() {
            return Ok(true);
        }
    }

    let db_path = get_db_path();

    if !db_path.exists() {
        return Ok(false);
    }

    // Initialize database
    let db = Arc::new(database::init_database(&db_path)?);
    *state.database.lock().unwrap() = Some(db.clone());

    // Load verification data from database
    let verification_data = database::load_verification_data(&db)?;

    if let Some(data) = verification_data {
        *state.verification_data.lock().unwrap() = Some(data);
        return Ok(true);
    }

    Ok(false)
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
        .setup(move |_app| {
            // Start native messaging server in background thread
            let state_for_server = state.clone();

            std::thread::spawn(move || {
                if let Err(e) = native_messaging::start_server(NATIVE_MESSAGING_PORT, state_for_server) {
                    eprintln!("Failed to start native messaging server: {}", e);
                }
            });

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