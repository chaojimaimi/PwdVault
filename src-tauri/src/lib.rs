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

// Re-export the application layer so external callers (tests, benches) can
// still write `pwdvault_lib::AppState`, `pwdvault_lib::VaultError`, etc.
pub use pwdvault_application::{
    AppState, VaultError,
};
pub use pwdvault_application::{
    CreateEntryRequest, UpdateEntryRequest, EntrySummary, EntrySecretResponse,
    ExportEntry, BackupPayload, VaultBackup, ImportResult, UpdateInfo,
};
pub use pwdvault_domain::{Group, PasswordEntry, Settings};
pub use pwdvault_application::service;

use std::sync::Arc;

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

use pwdvault_domain::constants;
use pwdvault_infrastructure::{native_host_setup, paths};

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

    let binary_name = if cfg!(windows) { "pwdvault-native.exe" } else { "pwdvault-native" };
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
    let _ = paths::secure_file(&config_path);
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
            ids.firefox = firefox.to_string();
        }
    }
    ids
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

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
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(state.clone())
        .setup(move |app| {
            // Start native messaging server in background thread.
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

            register_native_host(app);

            // System tray menu.
            let show_i = MenuItem::with_id(app, "show", "Show PwdVault", true, None::<&str>)?;
            let lock_i = MenuItem::with_id(app, "lock", "Lock Vault", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &lock_i, &quit_i])?;

            {
                let lock_i_clone = lock_i.clone();
                let app_handle = app.handle().clone();
                *state.update_lock_menu_fn.lock().expect("menu lock poisoned") =
                    Some(Box::new(move |text: &str| {
                        let _ = lock_i_clone.set_text(text);
                    }));
                *state.reload_window_fn.lock().expect("window lock poisoned") =
                    Some(Box::new(move || {
                        if let Some(window) = app_handle.get_webview_window("main") {
                            let _ = window.eval("window.location.reload()");
                        }
                    }));
            }

            start_auto_lock_thread(state.clone());

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
            commands::generate_password,
            commands::setup_vault,
            commands::create_entry,
            commands::get_entry_meta,
            commands::get_entry_secret,
            commands::list_all_entries,
            commands::update_entry,
            commands::remove_entry,
            commands::get_entry_count,
            commands::create_group,
            commands::list_all_groups,
            commands::remove_group,
            commands::update_group,
            commands::get_settings,
            commands::update_settings,
            commands::revoke_extension_access,
            commands::export_vault,
            commands::import_vault,
            commands::check_for_updates,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
