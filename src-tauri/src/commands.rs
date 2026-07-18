//! Tauri IPC command wrappers (§5.6.3 adapter layer).
//!
//! Each command is a thin wrapper that delegates to the application service
//! layer. CPU-intensive operations (KDF, import/export, update check) run on
//! `tauri::async_runtime::spawn_blocking` so the IPC thread and the window/
//! tray stay responsive (§5.6.2).

use std::sync::Arc;

use tauri::State;
use zeroize::Zeroizing;

use pwdvault_application::{self as app, AppState, VaultError};
use pwdvault_domain::{CreateEntryRequest, UpdateEntryRequest};

pub type AppHandle = Arc<AppState>;

// ---------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn is_vault_initialized(state: State<'_, AppHandle>) -> bool {
    app::is_initialized(state.inner())
}

#[tauri::command]
pub fn is_vault_unlocked(state: State<'_, AppHandle>) -> bool {
    app::is_unlocked(state.inner())
}

#[tauri::command]
pub async fn init_vault(
    password: Zeroizing<String>,
    state: State<'_, AppHandle>,
) -> Result<(), VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app::init_vault(&state, password))
        .await
        .map_err(|e| VaultError::InternalError(format!("init task join error: {}", e)))?
}

#[tauri::command]
pub async fn unlock_vault(
    password: Zeroizing<String>,
    state: State<'_, AppHandle>,
) -> Result<bool, VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app::unlock_vault(&state, password))
        .await
        .map_err(|e| VaultError::InternalError(format!("unlock task join error: {}", e)))?
}

#[tauri::command]
pub fn lock_vault(state: State<'_, AppHandle>) {
    app::lock_vault(state.inner());
}

#[tauri::command]
pub fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> Result<String, VaultError> {
    app::generate_password(
        length,
        include_uppercase,
        include_lowercase,
        include_numbers,
        include_symbols,
    )
}

#[tauri::command]
pub fn setup_vault(state: State<'_, AppHandle>) -> Result<bool, VaultError> {
    app::setup_vault(state.inner())
}

// ---------------------------------------------------------------------------
// Entry management
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn create_entry(
    request: CreateEntryRequest,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::EntrySummary, VaultError> {
    app::create_entry(state.inner(), request)
}

#[tauri::command]
pub fn get_entry_meta(
    id: String,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::EntrySummary, VaultError> {
    app::get_entry_meta(state.inner(), id)
}

#[tauri::command]
pub fn get_entry_secret(
    id: String,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::EntrySecretResponse, VaultError> {
    app::get_entry_secret(state.inner(), id)
}

#[tauri::command]
pub fn list_all_entries(
    state: State<'_, AppHandle>,
) -> Result<Vec<pwdvault_domain::EntrySummary>, VaultError> {
    app::list_all_entries(state.inner())
}

#[tauri::command]
pub fn update_entry(
    id: String,
    request: UpdateEntryRequest,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::EntrySummary, VaultError> {
    app::update_entry(state.inner(), id, request)
}

#[tauri::command]
pub fn remove_entry(id: String, state: State<'_, AppHandle>) -> Result<bool, VaultError> {
    app::remove_entry(state.inner(), id)
}

#[tauri::command]
pub fn get_entry_count(state: State<'_, AppHandle>) -> Result<usize, VaultError> {
    app::get_entry_count(state.inner())
}

// ---------------------------------------------------------------------------
// Group management
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn create_group(
    name: String,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::Group, VaultError> {
    app::create_group(state.inner(), name)
}

#[tauri::command]
pub fn list_all_groups(
    state: State<'_, AppHandle>,
) -> Result<Vec<pwdvault_domain::Group>, VaultError> {
    app::list_all_groups(state.inner())
}

#[tauri::command]
pub fn remove_group(id: String, state: State<'_, AppHandle>) -> Result<bool, VaultError> {
    app::remove_group(state.inner(), id)
}

#[tauri::command]
pub fn update_group(
    id: String,
    name: String,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::Group, VaultError> {
    app::update_group(state.inner(), id, name)
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_settings(state: State<'_, AppHandle>) -> Result<pwdvault_domain::Settings, VaultError> {
    app::get_settings(state.inner())
}

#[tauri::command]
pub fn update_settings(
    settings: pwdvault_domain::Settings,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::Settings, VaultError> {
    app::update_settings(state.inner(), settings)
}

#[tauri::command]
pub fn revoke_extension_access() -> bool {
    pwdvault_infrastructure::auth::revoke_extension_access();
    pwdvault_infrastructure::pairing::cancel_all_sessions();
    true
}

// ---------------------------------------------------------------------------
// Import / Export
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn export_vault(
    export_password: Zeroizing<String>,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::VaultBackup, VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app::export_vault(&state, export_password))
        .await
        .map_err(|e| VaultError::InternalError(format!("export task join error: {}", e)))?
}

#[tauri::command]
pub async fn import_vault(
    backup: pwdvault_domain::VaultBackup,
    import_password: Zeroizing<String>,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::ImportResult, VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app::import_vault(&state, backup, import_password))
        .await
        .map_err(|e| VaultError::InternalError(format!("import task join error: {}", e)))?
}

// ---------------------------------------------------------------------------
// Update check
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn check_for_updates(
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::UpdateInfo, VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app::check_for_updates(&state))
        .await
        .map_err(|e| VaultError::InternalError(format!("update check join error: {}", e)))?
}
