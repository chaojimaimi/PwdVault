//! Application state container (§5.6.3).
//!
//! `AppState` holds the shared mutable state accessed by every use case and
//! adapter: the redb handle, vault session (keys + activity), verification
//! data, rate-limit counters, and UI callbacks. UI callbacks (tray menu text,
//! window reload) are injected by the tauri-app adapter; the application layer
//! only calls them through the stored closures.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use redb::Database;

use pwdvault_domain::constants::AUTO_LOCK_SECS;
use pwdvault_infrastructure::crypto::VerificationData;

use crate::error::VaultError;
use crate::session::{SessionLease, VaultSession};

pub type UpdateLockMenuFn = Box<dyn Fn(&str) + Send + Sync>;
pub type ReloadWindowFn = Box<dyn Fn() + Send + Sync>;

/// Shared application state. Wrapped in `Arc<AppState>` and shared across
/// Tauri IPC commands, the Native Messaging HTTP server, and the auto-lock
/// background thread.
pub struct AppState {
    pub verification_data: Mutex<Option<VerificationData>>,
    pub database: Mutex<Option<Arc<Database>>>,
    /// Unified vault session — holds enc_key, mac_key, last_activity, and
    /// session_generation (§5.1.1).
    pub session: VaultSession,
    /// Closure to update the tray lock/unlock menu item text.
    pub update_lock_menu_fn: Mutex<Option<UpdateLockMenuFn>>,
    /// Closure to reload the main window (for auto-lock).
    pub reload_window_fn: Mutex<Option<ReloadWindowFn>>,
    /// Dynamic auto-lock timeout in seconds (loaded from settings).
    pub auto_lock_secs: Mutex<u64>,
    /// Number of consecutive failed unlock attempts.
    pub failed_unlock_attempts: Mutex<u32>,
    /// Timestamp when lockout expires (None = not locked out).
    pub lockout_until: Mutex<Option<Instant>>,
    /// Rate limiting for pair endpoint (requests per minute).
    pub pair_request_count: Mutex<u32>,
    pub pair_last_reset: Mutex<Option<Instant>>,
    /// Cancellation flag for the in-flight update check (§5.6.2).
    pub update_check_cancel: AtomicBool,
}

impl AppState {
    /// Reset the auto-lock activity timer (called on vault operations).
    pub fn touch_activity(&self) {
        self.session.touch_activity();
    }

    /// Update the tray menu item text for lock/unlock.
    pub fn update_lock_menu(&self, text: &str) {
        let guard = self.update_lock_menu_fn.lock().expect("menu lock poisoned");
        if let Some(ref callback) = *guard {
            callback(text);
        }
    }

    /// Reload the main window (used by auto-lock).
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
    pub fn lease(&self) -> Result<SessionLease<'_>, VaultError> {
        self.session.lease()
    }

    /// Lock the vault: obtain exclusive access, wait for in-flight operations
    /// to drain, then atomically clear keys. Used by auto-lock and manual lock.
    pub fn lock_vault(&self) {
        // §5.6.2: cancel any in-flight update check so its blocking worker
        // returns promptly instead of holding a thread for the full timeout.
        self.update_check_cancel
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.session.exclusive_lock_and_clear();
        self.update_lock_menu("Unlock Vault");
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            verification_data: Mutex::new(None),
            database: Mutex::new(None),
            session: VaultSession::new(),
            update_lock_menu_fn: Mutex::new(None),
            reload_window_fn: Mutex::new(None),
            auto_lock_secs: Mutex::new(AUTO_LOCK_SECS),
            failed_unlock_attempts: Mutex::new(0),
            lockout_until: Mutex::new(None),
            pair_request_count: Mutex::new(0),
            pair_last_reset: Mutex::new(None),
            update_check_cancel: AtomicBool::new(false),
        }
    }
}
