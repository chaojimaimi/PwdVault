//! Post-unlock side effects shared by both adapters (WP3, v1.5.0).
//!
//! The Tauri IPC unlock commands and the Native Messaging dispatcher unlock
//! arm both call [`sweep_trash_and_emit`] right after the application layer
//! published the session keys. The sweep itself lives in the application
//! layer (`service::run_trash_auto_purge`, pure function — it cannot emit);
//! only the adapter owns the `tauri::AppHandle` needed to surface the result.

use std::sync::Arc;

use tauri::Emitter;

use pwdvault_application::AppState;

/// Run ONE bounded trash auto-purge batch after a successful unlock and emit
/// `trash-auto-purged(count)` so the webview can toast the outcome. A zero
/// count (feature off or nothing expired) is NOT emitted.
///
/// Timing contract: this runs AFTER `complete_unlock` published the keys —
/// outside any D8 exclusive window — so the unlock path is only ever delayed
/// by the ≤500-row batch cap (`MAX_TRASH_SWEEP_BATCH`). Failures are logged
/// and swallowed: the unlock itself already succeeded, and a failed sweep
/// must never surface as a failed unlock (the next unlock retries).
pub(crate) fn sweep_trash_and_emit(app: &tauri::AppHandle, state: &Arc<AppState>) {
    // The tauri-app crate has no chrono dependency (commands.rs civil_from_days
    // precedent); unix seconds from the clock are all the sweep needs.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    match pwdvault_application::service::run_trash_auto_purge(state, now) {
        Ok(0) => {}
        Ok(count) => {
            tracing::info!("trash auto-purge removed {count} expired item(s) after unlock");
            if let Err(error) = app.emit("trash-auto-purged", count) {
                tracing::error!("could not surface the trash auto-purge result: {error}");
            }
        }
        Err(error) => {
            tracing::warn!(
                "trash auto-purge after unlock failed: {}",
                error.public_message()
            );
        }
    }
}
