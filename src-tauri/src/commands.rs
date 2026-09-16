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

/// A1: reset the auto-lock activity timer. Called by the frontend on local
/// user input (pointer/keyboard) so that reading an entry without any vault
/// operation does not let the session time out under the user's hands.
#[tauri::command]
pub fn touch_activity(state: State<'_, AppHandle>) {
    state.inner().touch_activity();
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

/// P2.4 (D6): Tauri-only — generate the current TOTP code for an entry. The
/// browser-extension bridge does not expose TOTP codes (touch_activity
/// precedent for desktop-only commands).
#[tauri::command]
pub fn totp_code(
    id: String,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::TotpCodeResponse, VaultError> {
    app::totp_code(state.inner(), id)
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
    let result =
        tauri::async_runtime::spawn_blocking(move || app::export_vault(&state, export_password))
            .await
            .map_err(|e| VaultError::InternalError(format!("export task join error: {}", e)))?;
    match &result {
        Ok(_) => tracing::info!("vault backup generation completed"),
        Err(error) => tracing::error!(error = ?error, "vault backup generation failed"),
    }
    result
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

// ---------------------------------------------------------------------------
// Security operations (Phase 1) — Tauri-IPC only (D6, touch_activity precedent)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn change_password(
    current_password: Zeroizing<String>,
    new_password: Zeroizing<String>,
    recovery_key: Option<String>,
    state: State<'_, AppHandle>,
) -> Result<(), VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        app::change_password(&state, current_password, new_password, recovery_key)
    })
    .await
    .map_err(|e| VaultError::InternalError(format!("change password task join error: {}", e)))?
}

#[tauri::command]
pub fn biometric_status(
    state: State<'_, AppHandle>,
) -> Result<pwdvault_domain::BiometricStatus, VaultError> {
    app::biometric_status(state.inner(), state.inner().secret_store.as_ref())
}

#[tauri::command]
pub async fn enable_biometric(
    password: Zeroizing<String>,
    state: State<'_, AppHandle>,
) -> Result<(), VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        app::enable_biometric(&state, password, state.secret_store.as_ref())
    })
    .await
    .map_err(|e| VaultError::InternalError(format!("enable biometric task join error: {}", e)))?
}

#[tauri::command]
pub fn disable_biometric(state: State<'_, AppHandle>) -> Result<(), VaultError> {
    app::disable_biometric(state.inner(), state.inner().secret_store.as_ref())
}

#[tauri::command]
pub async fn unlock_biometric(state: State<'_, AppHandle>) -> Result<(), VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        app::unlock_biometric(&state, state.secret_store.as_ref())
    })
    .await
    .map_err(|e| VaultError::InternalError(format!("biometric unlock task join error: {}", e)))?
}

#[tauri::command]
pub fn recovery_status(state: State<'_, AppHandle>) -> Result<bool, VaultError> {
    app::recovery_status(state.inner())
}

#[tauri::command]
pub async fn enable_recovery(
    password: Zeroizing<String>,
    state: State<'_, AppHandle>,
) -> Result<String, VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        app::enable_recovery(&state, password)
    })
    .await
    .map_err(|e| VaultError::InternalError(format!("enable recovery task join error: {}", e)))?
}

#[tauri::command]
pub async fn disable_recovery(
    current_password: Zeroizing<String>,
    state: State<'_, AppHandle>,
) -> Result<(), VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app::disable_recovery(&state, current_password))
        .await
        .map_err(|e| VaultError::InternalError(format!("disable recovery task join error: {}", e)))?
}

#[tauri::command]
pub async fn recover_vault(
    recovery_key: String,
    new_password: Zeroizing<String>,
    state: State<'_, AppHandle>,
) -> Result<(), VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        app::recover_vault(&state, &recovery_key, new_password)
    })
    .await
    .map_err(|e| VaultError::InternalError(format!("recover vault task join error: {}", e)))?
}

// ---------------------------------------------------------------------------
// Cloud sync (Phase 3) — Tauri-only (D6, touch_activity precedent). The
// browser-extension bridge never sees sync operations. sync_connect /
// sync_now perform network I/O and KDF work: spawn_blocking keeps the IPC
// thread responsive (§5.6.2).
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn sync_status(
    state: State<'_, AppHandle>,
) -> Result<pwdvault_application::SyncStatusResponse, VaultError> {
    app::sync_status(state.inner())
}

#[tauri::command]
pub async fn sync_connect(
    config: pwdvault_application::SyncConfig,
    container_password: Zeroizing<String>,
    webdav_password: Option<Zeroizing<String>>,
    state: State<'_, AppHandle>,
) -> Result<pwdvault_application::SyncStatusResponse, VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        app::sync_connect(&state, config, container_password, webdav_password)
    })
    .await
    .map_err(|e| VaultError::InternalError(format!("sync connect task join error: {}", e)))?
}

#[tauri::command]
pub async fn sync_now(
    state: State<'_, AppHandle>,
) -> Result<pwdvault_application::SyncStatusResponse, VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app::sync_now(&state))
        .await
        .map_err(|e| VaultError::InternalError(format!("sync now task join error: {}", e)))?
}

#[tauri::command]
pub fn sync_disconnect(state: State<'_, AppHandle>) -> Result<(), VaultError> {
    app::sync_disconnect(state.inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdvault_infrastructure::crypto;
    use tauri::Manager;

    /// A1: the `touch_activity` command must delegate to
    /// `AppState::touch_activity` so pure-local user input advances the
    /// auto-lock deadline exactly like vault operations do.
    #[test]
    fn touch_activity_command_advances_auto_lock_deadline() {
        let app = tauri::test::mock_app();
        let state = Arc::new(AppState::default());
        app.manage(state.clone());

        // Locked session: no deadline exists and touching stays a no-op.
        assert!(state.session.auto_lock_deadline(600).is_none());

        // Unlock the session (same helper pattern as the native messaging tests).
        let salt = crypto::kdf::generate_salt();
        let (master_key, _params) =
            crypto::kdf::derive_key("correct horse battery staple", &salt)
                .expect("derive master key");
        let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);
        state.session.unlock(enc_key, mac_key);

        let before = state
            .session
            .auto_lock_deadline(600)
            .expect("unlocked deadline before touch");
        std::thread::sleep(std::time::Duration::from_millis(10));

        let ipc_state: State<'_, AppHandle> = app.state();
        touch_activity(ipc_state);

        let after = state
            .session
            .auto_lock_deadline(600)
            .expect("deadline after touch");
        assert!(
            after > before,
            "touch_activity must advance the auto-lock deadline"
        );
    }
}
