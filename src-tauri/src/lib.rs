//! PwdVault — Tauri desktop application entry point (§5.6.3 adapter layer).
//!
//! This crate is the outermost adapter: it wires the Tauri runtime (window,
//! tray, IPC commands, plugins) to the application layer and hosts the Native
//! Messaging HTTP server. All business logic lives in `pwdvault_application`;
//! crypto, database, and filesystem implementations live in
//! `pwdvault_infrastructure`; entities, DTOs, and validation live in
//! `pwdvault_domain`.

mod commands;
pub mod native_messaging;
pub mod shortcuts;
// WP3 (v1.5.0): post-unlock trash auto-purge, shared by the IPC unlock
// commands and the NM dispatcher unlock arm (the emit-capable adapters).
mod unlock_effects;

// Re-export the application layer so external callers (tests, benches) can
// still write `pwdvault_lib::AppState`, `pwdvault_lib::VaultError`, etc.
pub use pwdvault_application::service;
pub use pwdvault_application::{AppState, VaultError};
pub use pwdvault_application::{
    BackupPayload, CreateEntryRequest, EntrySecretResponse, EntrySummary, ExportEntry,
    ImportResult, SyncBackendKind, SyncConfig, SyncState, SyncStatusResponse, UpdateEntryRequest,
    VaultBackup,
};
pub use pwdvault_domain::{Group, PasswordEntry, Settings};

use std::sync::Arc;

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Emitter, Manager,
};

use pwdvault_domain::constants;
use pwdvault_infrastructure::{database, native_host_setup, paths};

// ---------------------------------------------------------------------------
// Auto-Lock background thread
// ---------------------------------------------------------------------------

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
                    // Cap the sleep at 5 seconds so the thread re-evaluates the
                    // deadline periodically. Without this cap, shortening
                    // auto_lock_secs while sleeping toward the old deadline would
                    // delay the lock until the original deadline passes.
                    let sleep_dur = (d - now).min(std::time::Duration::from_secs(5));
                    std::thread::sleep(sleep_dur);
                    let should_lock = {
                        let timeout = *state.auto_lock_secs.lock().expect("timeout lock poisoned");
                        state.session.should_auto_lock(timeout)
                    };
                    if should_lock {
                        state.lock_vault();
                        state.reload_window();
                    }
                } else {
                    state.lock_vault();
                    state.reload_window();
                }
            }
            None => {
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Auto-Sync background thread (v1.6.0 WP3 / D6)
// ---------------------------------------------------------------------------

/// Timed auto-sync scheduler. Wakes at most every 30 seconds and hands the
/// decision to the application layer's `run_sync_cycle_if_due` (unlock /
/// interval / last-finished gating, plus the busy try_lock skip — a tick
/// never queues behind a running manual cycle). The thread IS the background
/// context: the cycle runs blocking right here (D6) — no extra
/// spawn_blocking indirection.
///
/// SILENT BY DESIGN: successes and failures alike are recorded in
/// `SyncState` (visible on the settings status line) but NEVER emitted as
/// events or toasts — transient network jitter from a background timer must
/// not interrupt the user (the deliberate opposite of the SF-P* position on
/// user-initiated actions).
fn start_auto_sync_thread(state: Arc<AppState>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        pwdvault_application::service::run_sync_cycle_if_due(&state);
    });
}

// ---------------------------------------------------------------------------
// Native host registration
// ---------------------------------------------------------------------------

fn register_native_host(app: &tauri::App) {
    let resource_dir = match app.path().resource_dir() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("native_host_setup: cannot resolve resource dir: {}", e);
            return;
        }
    };

    let binary_name = if cfg!(windows) {
        "pwdvault-native.exe"
    } else {
        "pwdvault-native"
    };
    let host_path = resource_dir.join("binaries").join(binary_name);

    if !host_path.exists() {
        // Expected in dev mode (no bundle). Stay quiet.
        return;
    }

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

    let ids = load_extension_ids();
    native_host_setup::register(&host_path, &ids);
}

fn load_extension_ids() -> native_host_setup::ExtensionIds {
    let mut ids = native_host_setup::ExtensionIds::default();
    let Some(parent) = paths::get_db_path().parent().map(|path| path.to_path_buf()) else {
        return ids;
    };
    let config_path = parent.join("native-host.json");
    // SF-P2d: best effort, but never silent — the native-host.json config
    // file must not stay readable by other accounts.
    if let Err(error) = paths::secure_file(&config_path) {
        tracing::warn!(
            "could not tighten permissions on the native-host.json config file: {}",
            error
        );
    }
    let Some(value) = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
    else {
        return ids;
    };

    if let Some(chrome) = value.get("chrome").and_then(|value| value.as_str()) {
        if native_host_setup::is_valid_chrome_extension_id(chrome)
            && !ids.chrome.iter().any(|existing| existing == chrome)
        {
            ids.chrome.push(chrome.to_string());
        }
    }
    if let Some(firefox) = value.get("firefox").and_then(|value| value.as_str()) {
        if !firefox.is_empty() && !firefox.contains(['\r', '\n']) {
            if firefox != native_host_setup::FIREFOX_EXTENSION_ID {
                // Advisory only — the manifest keeps whatever ID is configured
                // here, but the host's allowed_origins hard-check rejects
                // browsers whose ID does not match, so warn loudly.
                tracing::warn!(
                    "native-host.json firefox id does not match the host's expected id \
                     ({}): the host will refuse connection attempts from that browser",
                    native_host_setup::FIREFOX_EXTENSION_ID
                );
            }
            ids.firefox = firefox.to_string();
        }
    }
    ids
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Read the persisted global-shortcut config at boot (best-effort). Only
/// touches an EXISTING database file — creating one here would race the
/// first-run setup flow.
fn boot_shortcut_config() -> (bool, String) {
    let db_path = paths::get_db_path();
    if !db_path.exists() {
        return (true, shortcuts::DEFAULT_GLOBAL_SHORTCUT.to_string());
    }
    match database::init_database(&db_path) {
        Ok(db) => {
            match database::load_settings(&db) {
                Ok(settings) => (settings.global_shortcut_enabled, settings.global_shortcut),
                Err(error) => {
                    tracing::warn!("could not load settings for the global shortcut, keeping the default: {error}");
                    (true, shortcuts::DEFAULT_GLOBAL_SHORTCUT.to_string())
                }
            }
        }
        Err(error) => {
            tracing::warn!("could not open the vault for the global shortcut config, keeping the default: {error}");
            (true, shortcuts::DEFAULT_GLOBAL_SHORTCUT.to_string())
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let file_appender = tracing_appender::rolling::daily(paths::log_dir(), "pwdvault.log");
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
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        // M11: clipboard write/read for the auto-clear mechanism; the
        // capabilities file grants only allow-write-text + allow-read-text.
        .plugin(tauri_plugin_clipboard_manager::init())
        // In-app auto-update: signed feed check + download/install (updater)
        // and relaunch-after-install (process). The frontend drives them via
        // the @tauri-apps/plugin-updater / plugin-process JS bindings; the
        // capabilities file grants `updater:default` + `process:allow-restart`.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        // WP5 (v1.4.0): global show-vault shortcut. Registration is driven
        // from Rust (shortcuts.rs); the capability file grants the plugin's
        // register/unregister/is-registered permissions only.
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .manage(state.clone())
        .setup(move |app| {
            // Start native messaging server in background thread.
            let state_for_server = state.clone();
            let app_handle = app.handle().clone();
            std::thread::spawn(move || {
                if let Err(e) = native_messaging::start_server(
                    constants::NATIVE_MESSAGING_PORT,
                    state_for_server,
                    Some(app_handle.clone()),
                ) {
                    tracing::error!("Failed to start native messaging server: {}", e);
                    // B3: a bind failure must not stay silent. If another
                    // process squats the port, it can intercept extension
                    // traffic — surface the failure in the UI so the user can
                    // free the port and restart. The error string contains no
                    // sensitive details (bind errors only name the OS cause).
                    let _ = app_handle.emit(
                        "native-server-error",
                        format!("Browser extension server failed to start: {e}"),
                    );
                }
            });

            register_native_host(app);

            // System tray menu.
            let show_i = MenuItem::with_id(app, "show", "Show PwdVault", true, None::<&str>)?;
            let lock_i = MenuItem::with_id(app, "lock", "Lock Vault", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &lock_i, &quit_i])?;

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

            // WP5 (v1.4.0): the application layer asks us to (re)register the
            // shortcut whenever persisted settings say so (boot settings load
            // in setup_vault, settings saves).
            {
                let app_handle = app.handle().clone();
                *state
                    .apply_global_shortcut_fn
                    .lock()
                    .expect("shortcut lock poisoned") =
                    Some(Box::new(move |enabled, accelerator| {
                        shortcuts::apply_global_shortcut(&app_handle, enabled, accelerator)
                    }));
            }
            // Boot registration. Prefer the persisted config: the settings
            // row is read through a short-lived database handle (dropped
            // before setup_vault re-opens the file) so a disabled/customized
            // shortcut never fires, not even between boot and unlock. Any
            // read problem falls back to the default binding — setup_vault
            // re-applies the real settings when the frontend boots.
            let (boot_enabled, boot_accelerator) = boot_shortcut_config();
            if let Err(error) =
                shortcuts::apply_global_shortcut(app.handle(), boot_enabled, &boot_accelerator)
            {
                tracing::warn!("global shortcut could not be registered: {error}");
            }

            start_auto_lock_thread(state.clone());
            // v1.6.0 (D6): timed auto-sync — disabled unless the user opts in
            // via Settings.auto_sync_interval_min.
            start_auto_sync_thread(state.clone());

            let tray = TrayIconBuilder::new()
                // TrayIconBuilder::icon takes a non-optional Image; the icon
                // is compiled into the binary, so a missing embedded icon is
                // a build defect and must fail loudly instead of panicking on
                // a bare unwrap (D3).
                .icon(
                    app.default_window_icon()
                        .expect("embedded window icon missing")
                        .clone(),
                )
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

            // Close-to-tray: keep the HTTP server alive for the extension.
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
            commands::is_vault_initialized,
            commands::is_vault_unlocked,
            commands::init_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::touch_activity,
            commands::generate_password,
            commands::setup_vault,
            commands::create_entry,
            commands::get_entry_meta,
            commands::get_entry_secret,
            // v1.6.0 (D7): boolean-only password check for the extension's
            // save/update prompt (also routed via the NM bridge).
            commands::verify_entry_password,
            commands::list_all_entries,
            commands::update_entry,
            commands::remove_entry,
            commands::get_entry_count,
            // v1.4.0 trash — Tauri IPC only (D6): the extension bridge never
            // sees soft-deleted entries or physical deletes.
            commands::list_deleted_entries,
            commands::restore_entry,
            commands::purge_entry,
            commands::empty_trash,
            // P2.4 (D6): Tauri-only TOTP code generation.
            commands::totp_code,
            commands::create_group,
            commands::list_all_groups,
            commands::remove_group,
            commands::update_group,
            commands::get_settings,
            commands::update_settings,
            // WP5 (v1.4.0): settings-page-driven global shortcut registration.
            commands::register_global_shortcut,
            commands::revoke_extension_access,
            commands::export_vault,
            commands::import_vault,
            // SEC-M2 (v1.1.9): native save/open dialogs + backup file IO in
            // Rust — the webview needs no fs capability for backup flows.
            commands::export_vault_file,
            commands::read_backup_file,
            // Phase 1 security operations — Tauri IPC only (D6).
            commands::change_password,
            commands::biometric_status,
            commands::enable_biometric,
            commands::disable_biometric,
            commands::unlock_biometric,
            commands::recovery_status,
            commands::enable_recovery,
            commands::disable_recovery,
            commands::recover_vault,
            // Phase 3 cloud sync — Tauri IPC only (D6).
            commands::sync_status,
            commands::sync_connect,
            commands::sync_disconnect,
            commands::sync_now,
            // P3.4 (D6): Baidu Netdisk OAuth pairing — the extension never
            // handles cloud credentials.
            commands::baidu_start_auth,
            commands::baidu_complete_auth,
            // v1.5.0 — Tauri IPC only (D6): the security dashboard report
            // carries ids/scores only, and the CSV importer stages plaintext
            // rows in AppState; neither is ever reachable via the extension
            // bridge.
            commands::security_report,
            commands::import_csv_open,
            commands::import_csv_commit,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
