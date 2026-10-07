//! Tauri IPC command wrappers (§5.6.3 adapter layer).
//!
//! Each command is a thin wrapper that delegates to the application service
//! layer. CPU-intensive operations (KDF, import/export) run on
//! `tauri::async_runtime::spawn_blocking` so the IPC thread and the window/
//! tray stay responsive (§5.6.2).

use std::sync::Arc;

use tauri::State;
use zeroize::Zeroizing;

use pwdvault_application::{self as app, AppState, EnableRecoveryResult, VaultError};
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

/// CQ-P3a: delegate to the shared application service so the desktop IPC
/// path and the extension HTTP dispatcher run the identical revocation
/// sequence (and any failure surfaces as a VaultError instead of being
/// invisible behind an unconditional `true`).
#[tauri::command]
pub fn revoke_extension_access(state: State<'_, AppHandle>) -> Result<bool, VaultError> {
    app::revoke_extension_access(state.inner())?;
    Ok(true)
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
// Backup file IO (SEC-M2, v1.1.9) — native save/open dialogs and filesystem
// access move into Rust so the webview needs no fs capability. The plugin's
// blocking dialog variants must never run on the main thread, so every
// dialog call happens inside spawn_blocking (§5.6.2).
// ---------------------------------------------------------------------------

/// SEC-M2: export the unlocked vault through a native save dialog and write
/// the .pvault container from Rust (pretty JSON, atomic 0600 write). A
/// cancelled dialog is `Ok(None)` — the frontend treats that as "no file
/// chosen", not as an error.
#[tauri::command]
pub async fn export_vault_file(
    app: tauri::AppHandle,
    export_password: Zeroizing<String>,
    state: State<'_, AppHandle>,
) -> Result<Option<String>, VaultError> {
    let state = state.inner().clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        export_vault_file_blocking(&app, export_password, &state)
    })
    .await
    .map_err(|e| VaultError::InternalError(format!("export file task join error: {}", e)))?;
    match &result {
        Ok(Some(_)) => tracing::info!("vault backup export written to file"),
        Ok(None) => tracing::info!("vault backup export cancelled by user"),
        Err(error) => tracing::error!(error = ?error, "vault backup file export failed"),
    }
    result
}

/// Blocking half of `export_vault_file` (runs on the spawn_blocking pool).
fn export_vault_file_blocking(
    app: &tauri::AppHandle,
    export_password: Zeroizing<String>,
    state: &AppHandle,
) -> Result<Option<String>, VaultError> {
    use tauri_plugin_dialog::DialogExt;

    let Some(file_path) = app
        .dialog()
        .file()
        .add_filter("PwdVault Backup", &["pvault"])
        .set_file_name(backup_default_file_name())
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let path = file_path
        .into_path()
        .map_err(|error| VaultError::InvalidInput {
            code: "PATH_INVALID".into(),
            message: format!("the selected file path is not usable: {error}"),
        })?;

    let backup = app::export_vault(state, export_password)?;
    let json = serde_json::to_string_pretty(&backup)
        .map_err(|e| VaultError::InternalError(e.to_string()))?;
    pwdvault_infrastructure::paths::write_file_atomic_0600(&path, json.as_bytes()).map_err(
        |error| VaultError::InvalidInput {
            code: "BACKUP_WRITE_FAILED".into(),
            message: format!("cannot write the backup file: {error}"),
        },
    )?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

/// SEC-M2: pick a .pvault backup with the native open dialog and read +
/// pre-validate it in Rust (14 MiB cap, JSON shape, envelope version/magic —
/// the full cryptographic validation still happens in `import_vault`).
/// Cancelled dialog is `Ok(None)`.
#[tauri::command]
pub async fn read_backup_file(
    app: tauri::AppHandle,
    // Frozen contract keeps the state parameter; the parse itself is
    // stateless (all vault-dependent validation runs in import_vault).
    _state: State<'_, AppHandle>,
) -> Result<Option<pwdvault_domain::VaultBackup>, VaultError> {
    let result = tauri::async_runtime::spawn_blocking(move || read_backup_file_blocking(&app))
        .await
        .map_err(|e| VaultError::InternalError(format!("read backup task join error: {}", e)))?;
    match &result {
        Ok(Some(_)) => tracing::info!("backup file selected and pre-validated"),
        Ok(None) => tracing::info!("backup file selection cancelled by user"),
        Err(error) => tracing::error!(error = ?error, "backup file read failed"),
    }
    result
}

/// Blocking half of `read_backup_file` (runs on the spawn_blocking pool).
fn read_backup_file_blocking(
    app: &tauri::AppHandle,
) -> Result<Option<pwdvault_domain::VaultBackup>, VaultError> {
    use tauri_plugin_dialog::DialogExt;

    let Some(file_path) = app
        .dialog()
        .file()
        .add_filter("PwdVault Backup", &["pvault"])
        .blocking_pick_file()
    else {
        return Ok(None);
    };
    let path = file_path
        .into_path()
        .map_err(|error| VaultError::InvalidInput {
            code: "PATH_INVALID".into(),
            message: format!("the selected file path is not usable: {error}"),
        })?;
    let bytes = std::fs::read(&path).map_err(|error| VaultError::InvalidInput {
        code: "BACKUP_READ_FAILED".into(),
        message: format!("cannot read the backup file: {error}"),
    })?;
    app::parse_backup_file_bytes(&bytes).map(Some)
}

/// Default export file name, mirroring the webview's
/// `pwdvault-backup-${new Date().toISOString().slice(0, 10)}.pvault`.
fn backup_default_file_name() -> String {
    format!("pwdvault-backup-{}.pvault", utc_today_string())
}

/// UTC date as YYYY-MM-DD — the std-only equivalent of the webview's
/// `new Date().toISOString().slice(0, 10)` (this crate has no chrono
/// dependency; the algorithm below is Howard Hinnant's civil_from_days).
fn utc_today_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Days since 1970-01-01 → (year, month, day) in the proleptic Gregorian
/// calendar (Howard Hinnant's civil_from_days, public domain).
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if month <= 2 { y + 1 } else { y }, month, day)
}

// ---------------------------------------------------------------------------
// Security operations (Phase 1) — Tauri-IPC only (D6, touch_activity precedent)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn change_password(
    current_password: Zeroizing<String>,
    new_password: Zeroizing<String>,
    // Zeroized on drop like the other password args (same-file precedent at
    // current_password/new_password): the one-time recovery key must not
    // linger in heap memory after the change completes.
    recovery_key: Option<Zeroizing<String>>,
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

/// SEC-M2: generate the recovery key; with `save_path` (frontend save
/// dialog) the key file is validated and written by Rust (0600, atomic). A
/// failed write is an error — never a silent partial success. IPC-only
/// change (no HTTP dispatcher route), signature frozen in fix plan §3.1.
#[tauri::command]
pub async fn enable_recovery(
    password: Zeroizing<String>,
    save_path: Option<String>,
    state: State<'_, AppHandle>,
) -> Result<EnableRecoveryResult, VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        app::enable_recovery_with_file(&state, password, save_path)
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
        .map_err(|e| {
            VaultError::InternalError(format!("disable recovery task join error: {}", e))
        })?
}

#[tauri::command]
pub async fn recover_vault(
    recovery_key: Zeroizing<String>,
    new_password: Zeroizing<String>,
    state: State<'_, AppHandle>,
) -> Result<(), VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        app::recover_vault(&state, recovery_key.as_str(), new_password)
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

/// P3.4 (D6): Tauri-only — start the Baidu Netdisk OAuth pairing: returns
/// the authorize URL and parks a listener on the fixed loopback callback
/// port. spawn_blocking: binding the port can block (§5.6.2).
#[tauri::command]
pub async fn baidu_start_auth(
    state: State<'_, AppHandle>,
) -> Result<pwdvault_application::BaiduAuthStart, VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app::baidu_start_auth(&state))
        .await
        .map_err(|e| {
            VaultError::InternalError(format!("baidu auth start task join error: {}", e))
        })?
}

/// P3.4 (D6): Tauri-only — exchange the authorization code (explicit, or
/// the one captured from the pending `baidu_start_auth` callback when
/// `None`/empty) for tokens stored in the non-interactive credential store.
#[tauri::command]
pub async fn baidu_complete_auth(
    code: Option<String>,
    state: State<'_, AppHandle>,
) -> Result<(), VaultError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app::baidu_complete_auth(&state, code))
        .await
        .map_err(|e| {
            VaultError::InternalError(format!("baidu auth complete task join error: {}", e))
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdvault_infrastructure::crypto;
    use tauri::Manager;

    /// The std-only civil_from_days used for the default export file name
    /// must agree with known UTC dates.
    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(19_358), (2023, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }

    /// utc_today_string renders the same shape as the webview's
    /// `new Date().toISOString().slice(0, 10)`.
    #[test]
    fn utc_today_string_is_iso_date_shape() {
        let today = utc_today_string();
        assert_eq!(today.len(), 10, "YYYY-MM-DD: {today}");
        assert_eq!(&today[4..5], "-");
        assert_eq!(&today[7..8], "-");
        assert!(today[..4].chars().all(|c| c.is_ascii_digit()));
        assert!(today[5..7].chars().all(|c| c.is_ascii_digit()));
        assert!(today[8..10].chars().all(|c| c.is_ascii_digit()));
    }

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
        let (master_key, _params) = crypto::kdf::derive_key("correct horse battery staple", &salt)
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
