//! Application state container (§5.6.3).
//!
//! `AppState` holds the shared mutable state accessed by every use case and
//! adapter: the redb handle, vault session (keys + activity), verification
//! data, rate-limit counters, and UI callbacks. UI callbacks (tray menu text,
//! window reload) are injected by the tauri-app adapter; the application layer
//! only calls them through the stored closures.

use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::Condvar;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use redb::Database;

use pwdvault_domain::constants::AUTO_LOCK_SECS;
use pwdvault_infrastructure::crypto::VerificationData;
use pwdvault_infrastructure::keychain::{platform_default, platform_sync_default, SecretStore};

use crate::error::VaultError;
use crate::session::{SessionLease, VaultSession};

pub type UpdateLockMenuFn = Box<dyn Fn(&str) + Send + Sync>;
pub type ReloadWindowFn = Box<dyn Fn() + Send + Sync>;

/// One-shot parking gate for the D8-window regression tests (test-only).
///
/// A window function calls [`WindowGate::wait_if_armed`] right after its
/// exclusive drain; when a test armed the gate, that window parks there —
/// a deterministic interleave point — until the test calls
/// [`WindowGate::open`]. The gate is INSTANCE-scoped (a field on
/// [`AppState`]) and one-shot (it disarms on the first hit), so parallel
/// tests never interfere (review P3-2: this crate's suite runs in
/// parallel; a resident static gate would leak between tests).
#[cfg(test)]
#[derive(Default)]
pub struct WindowGate {
    armed: Mutex<bool>,
    arrived: Mutex<bool>,
    arrived_signal: Condvar,
    opened: Mutex<bool>,
    open_signal: Condvar,
}

#[cfg(test)]
impl WindowGate {
    /// Arm the gate: the next window reaching it parks until [`open`](Self::open).
    pub fn arm(&self) {
        *self.armed.lock().expect("gate lock poisoned") = true;
    }

    /// Park if armed (one-shot: disarms on the hit) and signal arrival.
    pub fn wait_if_armed(&self) {
        let was_armed = {
            let mut armed = self.armed.lock().expect("gate lock poisoned");
            let was_armed = *armed;
            *armed = false;
            was_armed
        };
        if !was_armed {
            return;
        }
        {
            let mut arrived = self.arrived.lock().expect("gate lock poisoned");
            *arrived = true;
            self.arrived_signal.notify_all();
        }
        let mut opened = self.opened.lock().expect("gate lock poisoned");
        while !*opened {
            opened = self.open_signal.wait(opened).expect("gate lock poisoned");
        }
    }

    /// Block until the gated window has parked.
    pub fn wait_until_arrived(&self) {
        let mut arrived = self.arrived.lock().expect("gate lock poisoned");
        while !*arrived {
            arrived = self
                .arrived_signal
                .wait(arrived)
                .expect("gate lock poisoned");
        }
    }

    /// Release the parked window.
    pub fn open(&self) {
        let mut opened = self.opened.lock().expect("gate lock poisoned");
        *opened = true;
        self.open_signal.notify_all();
    }
}

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
    /// Phase 1: platform credential store for the biometric wrap key
    /// (macOS Keychain; `UnavailableSecretStore` stub elsewhere). Tests
    /// replace this field with a `MemorySecretStore` — commands need no
    /// platform special-casing.
    pub secret_store: Arc<dyn SecretStore>,
    /// Phase 3 (P3.2): NON-INTERACTIVE credential store for cloud-sync
    /// credentials (WebDAV password, Baidu token). Deliberately a separate
    /// instance from [`AppState::secret_store`]: the bio store's items sit
    /// behind a Touch ID access control, and a background sync must never
    /// pop a fingerprint prompt.
    pub sync_secret_store: Arc<dyn SecretStore>,
    /// Fix plan A (P0): serializes all D8 exclusive windows (sync merge,
    /// password change, recovery re-seal). Held by a window function from
    /// before its `exclusive_lock_and_clear()` drain to after its final
    /// republish (success AND error paths), so two windows can never
    /// interleave. Lock order: `exclusive_window` -> session internals ->
    /// menu/verification mutexes. Window functions never enter holding a
    /// lease, and `lock_vault` never takes this guard — no deadlock.
    pub exclusive_window: Mutex<()>,
    /// Fix plan A §2.3: bumped on EVERY `lock_vault` before the drain. A D8
    /// window captures the value before opening and republishes its keys
    /// only if the epoch still matches — a manual/auto lock during the
    /// window is never silently revoked by the window's republish.
    pub lock_epoch: AtomicU64,
    /// Test seams (cfg(test)): one-shot parks placed right after each D8
    /// window's drain. See [`WindowGate`].
    #[cfg(test)]
    pub merge_window_gate: WindowGate,
    #[cfg(test)]
    pub reseal_window_gate: WindowGate,
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

    /// Lock the vault: bump the lock epoch (invalidating any in-flight D8
    /// window's republish), obtain exclusive access, wait for in-flight
    /// operations to drain, then atomically clear keys. Used by auto-lock
    /// and manual lock.
    pub fn lock_vault(&self) {
        // The bump MUST happen before the drain (plan A §2.3): windows
        // capture the epoch before opening, so any lock from that point on
        // makes their republish skip instead of re-unlocking the vault.
        self.lock_epoch.fetch_add(1, Ordering::Release);
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
            secret_store: platform_default(),
            sync_secret_store: platform_sync_default(),
            exclusive_window: Mutex::new(()),
            lock_epoch: AtomicU64::new(0),
            #[cfg(test)]
            merge_window_gate: WindowGate::default(),
            #[cfg(test)]
            reseal_window_gate: WindowGate::default(),
        }
    }
}
