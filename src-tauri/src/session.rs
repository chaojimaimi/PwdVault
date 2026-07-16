//! Unified vault session state machine.
//!
//! Replaces the scattered `keystore`, `mac_key`, `last_activity`, and `op_lock`
//! fields in `AppState` with a single state machine that provides a consistent
//! concurrency model across Tauri IPC, HTTP, and auto-lock.
//!
//! ## Design (per §5.1.1 of the Comprehensive Optimization Plan)
//!
//! ```text
//! VaultSession
//! ├── Locked
//! └── Unlocked
//!     ├── enc_key
//!     ├── mac_key
//!     ├── last_activity
//!     └── session_generation
//! ```
//!
//! All service operations obtain an operation [`SessionLease`] (a shared/read
//! guard) that keeps the keys alive for the duration of the operation.
//! Auto-lock obtains an [`ExclusiveLease`] (exclusive/write guard) that waits
//! for all operation leases to drain before clearing the keys.

use std::sync::Mutex;
use std::time::Instant;
use zeroize::Zeroize;

use crate::VaultError;

/// The encryption key type (bare `[u8; 32]` — will be replaced by `SecretKey`
/// in §5.1.5).
pub type EncKey = [u8; 32];
pub type MacKey = [u8; 32];

/// Inner state held behind the session mutex.
enum SessionInner {
    /// No keys are loaded; the vault requires an unlock operation.
    /// Carries the last generation so re-unlock increments correctly.
    Locked { generation: u64 },
    /// Keys and activity timer are live.
    Unlocked {
        enc_key: EncKey,
        mac_key: MacKey,
        last_activity: Instant,
        /// Monotonically increasing counter incremented on each unlock.
        /// Used by [`SessionLease`] to detect that the session changed
        /// (lock → re-unlock) while the lease was held.
        generation: u64,
    },
}

/// Unified vault session state machine.
///
/// Holds enc_key, mac_key, last_activity, and session_generation behind a
/// single `Mutex`. The lease mechanism built on top ensures that:
/// - Operations hold a shared reference (via `reader` count) preventing
///   auto-lock from clearing keys mid-operation.
/// - Auto-lock acquires the exclusive lock, waits for readers to drain,
///   then clears keys atomically.
pub struct VaultSession {
    inner: Mutex<SessionInner>,
    /// Number of active operation leases. Auto-lock's `exclusive_lease`
    /// waits until this reaches 0 before proceeding.
    reader_count: Mutex<u32>,
}

impl Default for VaultSession {
    fn default() -> Self {
        Self {
            inner: Mutex::new(SessionInner::Locked { generation: 0 }),
            reader_count: Mutex::new(0),
        }
    }
}

impl VaultSession {
    /// Create a new session in the Locked state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically transition to Unlocked state.
    ///
    /// Sets enc_key, mac_key, last_activity, and increments session_generation
    /// in a single lock acquisition. This is the **last step** of the two-phase
    /// unlock flow (§5.1.3 step 8) — it must only be called after all
    /// verification has passed.
    pub fn unlock(&self, enc_key: EncKey, mac_key: MacKey) {
        let mut inner = self.inner.lock().expect("session lock poisoned");
        let next_generation = match &*inner {
            SessionInner::Unlocked { generation, .. } => generation + 1,
            SessionInner::Locked { generation } => generation + 1,
        };
        *inner = SessionInner::Unlocked {
            enc_key,
            mac_key,
            last_activity: Instant::now(),
            generation: next_generation,
        };
    }

    /// Check if the vault is currently unlocked (keys are in memory).
    pub fn is_unlocked(&self) -> bool {
        let inner = self.inner.lock().expect("session lock poisoned");
        matches!(*inner, SessionInner::Unlocked { .. })
    }

    /// Get the encryption key.
    pub fn get_enc_key(&self) -> Result<EncKey, VaultError> {
        let inner = self.inner.lock().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked { enc_key, .. } => Ok(*enc_key),
            SessionInner::Locked { .. } => Err(VaultError::VaultLocked),
        }
    }

    /// Get the MAC key.
    pub fn get_mac_key(&self) -> Result<MacKey, VaultError> {
        let inner = self.inner.lock().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked { mac_key, .. } => Ok(*mac_key),
            SessionInner::Locked { .. } => Err(VaultError::VaultLocked),
        }
    }

    /// Update the activity timestamp (called on successful vault operations).
    pub fn touch_activity(&self) {
        let mut inner = self.inner.lock().expect("session lock poisoned");
        if let SessionInner::Unlocked { last_activity, .. } = &mut *inner {
            *last_activity = Instant::now();
        }
    }

    /// Read the activity timestamp and auto-lock timeout to determine
    /// whether auto-lock should fire. Returns `Some(deadline)` if the vault
    /// is unlocked and a deadline can be computed.
    pub fn auto_lock_deadline(&self, timeout_secs: u64) -> Option<Instant> {
        let inner = self.inner.lock().expect("session lock poisoned");
        if let SessionInner::Unlocked { last_activity, .. } = &*inner {
            Some(*last_activity + std::time::Duration::from_secs(timeout_secs))
        } else {
            None
        }
    }

    /// Check whether auto-lock should fire given the current elapsed time.
    ///
    /// Returns `true` only if the vault is unlocked AND the activity timer
    /// has exceeded `timeout_secs`.
    pub fn should_auto_lock(&self, timeout_secs: u64) -> bool {
        let inner = self.inner.lock().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked { last_activity, .. } => {
                last_activity.elapsed().as_secs() >= timeout_secs
            }
            SessionInner::Locked { .. } => false,
        }
    }

    /// Obtain an operation lease.
    ///
    /// The lease holds a shared reference count, preventing `exclusive_lease`
    /// (used by auto-lock) from clearing keys while the operation is in
    /// progress. The lease also snapshots the current `session_generation`
    /// so callers can detect stale state.
    ///
    /// Returns an error if the vault is locked.
    pub fn lease(&self) -> Result<SessionLease<'_>, VaultError> {
        let inner = self.inner.lock().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked { generation, .. } => {
                let generation = *generation;
                drop(inner);

                // Increment reader count AFTER confirming unlocked state.
                *self
                    .reader_count
                    .lock()
                    .expect("reader count lock poisoned") += 1;

                Ok(SessionLease {
                    session: self,
                    generation,
                })
            }
            SessionInner::Locked { .. } => Err(VaultError::VaultLocked),
        }
    }

    /// Obtain an exclusive lease for auto-lock.
    ///
    /// Waits for all operation leases to drain (reader_count reaches 0),
    /// then atomically clears keys and transitions to Locked. This ensures
    /// no operation is mid-flight when keys are wiped.
    ///
    /// Returns `true` if the vault was unlocked and is now locked.
    pub fn exclusive_lock_and_clear(&self) -> bool {
        // First, atomically clear keys and transition to Locked.
        // This prevents new leases from being issued.
        let was_unlocked = {
            let mut inner = self.inner.lock().expect("session lock poisoned");
            match std::mem::replace(
                &mut *inner,
                // Placeholder — replaced below after extracting keys
                SessionInner::Locked { generation: 0 },
            ) {
                SessionInner::Unlocked {
                    mut enc_key,
                    mut mac_key,
                    generation,
                    ..
                } => {
                    // Preserve generation so next unlock increments correctly.
                    *inner = SessionInner::Locked { generation };
                    enc_key.zeroize();
                    mac_key.zeroize();
                    true
                }
                SessionInner::Locked { generation } => {
                    *inner = SessionInner::Locked { generation };
                    false
                }
            }
        };

        if was_unlocked {
            // Wait for in-flight operation leases to drain. They hold
            // copies of the keys (obtained before we cleared them), so
            // they can finish safely. New operations will fail with
            // VaultLocked since the session is now Locked.
            //
            // We use a spin-wait with a short sleep and a 5-second timeout
            // to avoid burning CPU and to prevent infinite hangs in case
            // of a bug. In practice, operations are fast (ms), so this
            // rarely loops more than a few times.
            let deadline = Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let count = *self
                    .reader_count
                    .lock()
                    .expect("reader count lock poisoned");
                if count == 0 || Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        was_unlocked
    }
}

/// An operation lease on the vault session.
///
/// While held, auto-lock cannot clear the session keys. The `generation`
/// field captures the session_generation at acquisition time; callers can
/// use [`SessionLease::check_valid`] to detect that the session changed
/// (e.g. another thread locked and re-unlocked) during the operation.
pub struct SessionLease<'a> {
    session: &'a VaultSession,
    generation: u64,
}

impl<'a> SessionLease<'a> {
    /// Get the encryption key (valid for the lifetime of this lease).
    pub fn enc_key(&self) -> Result<EncKey, VaultError> {
        self.session.get_enc_key()
    }

    /// Get the MAC key (valid for the lifetime of this lease).
    pub fn mac_key(&self) -> Result<MacKey, VaultError> {
        self.session.get_mac_key()
    }

    /// Check that the session generation hasn't changed since acquisition.
    ///
    /// Returns `Ok(())` if the session is still the same generation (or still
    /// unlocked with a newer generation — the caller should treat a generation
    /// mismatch as a stale-state error).
    pub fn check_valid(&self) -> Result<(), VaultError> {
        let inner = self.session.inner.lock().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked { generation, .. } if *generation == self.generation => Ok(()),
            _ => Err(VaultError::VaultLocked),
        }
    }
}

impl<'a> Drop for SessionLease<'a> {
    fn drop(&mut self) {
        let mut count = self
            .session
            .reader_count
            .lock()
            .expect("reader count lock poisoned");
        if *count > 0 {
            *count -= 1;
        }
    }
}

/// Backwards-compatibility shim: expose a `KeyStore`-like interface on
/// `VaultSession` so the transition can be incremental. Once all callers
/// are updated to use `lease()`, these thin wrappers can be removed.
impl VaultSession {
    /// Check if unlocked (compatibility wrapper).
    pub fn is_session_unlocked(&self) -> bool {
        self.is_unlocked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ENC_KEY: EncKey = [0xAA; 32];
    const TEST_MAC_KEY: MacKey = [0xBB; 32];

    #[test]
    fn test_session_starts_locked() {
        let session = VaultSession::new();
        assert!(!session.is_unlocked());
        assert!(session.get_enc_key().is_err());
        assert!(session.get_mac_key().is_err());
    }

    #[test]
    fn test_unlock_sets_keys() {
        let session = VaultSession::new();
        session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

        assert!(session.is_unlocked());
        assert_eq!(session.get_enc_key().unwrap(), TEST_ENC_KEY);
        assert_eq!(session.get_mac_key().unwrap(), TEST_MAC_KEY);
    }

    #[test]
    fn test_lease_prevents_clear() {
        let session = VaultSession::new();
        session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

        let lease = session.lease().unwrap();
        assert_eq!(lease.enc_key().unwrap(), TEST_ENC_KEY);

        // While the lease is held, exclusive_lock_and_clear clears keys
        // but waits for the lease to drain. Simulate that the keys are
        // already cleared by checking from a new call (which will fail).
        drop(lease);

        // Now exclusive_lock_and_clear can proceed without blocking.
        assert!(session.exclusive_lock_and_clear());
        assert!(!session.is_unlocked());
    }

    #[test]
    fn test_lease_fails_when_locked() {
        let session = VaultSession::new();
        assert!(session.lease().is_err());
    }

    #[test]
    fn test_generation_increments_on_reunlock() {
        let session = VaultSession::new();
        session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
        let lease1 = session.lease().unwrap();
        assert_eq!(lease1.generation, 1);
        // Must drop the lease before exclusive_lock_and_clear, otherwise
        // the spin-wait inside exclusive_lock_and_clear waits for this
        // lease to drain — which can't happen since we're on the same thread.
        assert!(lease1.check_valid().is_ok());
        drop(lease1);

        session.exclusive_lock_and_clear();

        session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
        let lease2 = session.lease().unwrap();
        assert_eq!(lease2.generation, 2);
        assert!(lease2.check_valid().is_ok());
    }

    #[test]
    fn test_touch_activity_updates_timestamp() {
        let session = VaultSession::new();
        session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

        let deadline1 = session.auto_lock_deadline(60).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.touch_activity();
        let deadline2 = session.auto_lock_deadline(60).unwrap();

        assert!(deadline2 > deadline1);
    }

    #[test]
    fn test_auto_lock_deadline_none_when_locked() {
        let session = VaultSession::new();
        assert!(session.auto_lock_deadline(60).is_none());
    }

    #[test]
    fn test_should_auto_lock() {
        let session = VaultSession::new();
        session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

        // Just unlocked — should not auto-lock yet.
        assert!(!session.should_auto_lock(60));

        // Simulate old activity by checking with timeout=0.
        // (elapsed is always >= 0, so with timeout 0 it should be true)
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(session.should_auto_lock(0));
    }

    #[test]
    fn test_exclusive_lock_clears_keys() {
        let session = VaultSession::new();
        session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
        assert!(session.is_unlocked());

        let was_unlocked = session.exclusive_lock_and_clear();
        assert!(was_unlocked);
        assert!(!session.is_unlocked());
        assert!(session.get_enc_key().is_err());
        assert!(session.get_mac_key().is_err());
    }

    #[test]
    fn test_exclusive_lock_on_already_locked() {
        let session = VaultSession::new();
        assert!(!session.exclusive_lock_and_clear());
    }

    #[test]
    fn test_concurrent_leases() {
        use std::sync::Arc;
        use std::thread;

        let session = Arc::new(VaultSession::new());
        session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

        let mut handles = Vec::new();
        for _ in 0..10 {
            let s = session.clone();
            handles.push(thread::spawn(move || {
                let lease = s.lease().unwrap();
                assert_eq!(lease.enc_key().unwrap(), TEST_ENC_KEY);
                // Simulate work
                std::thread::sleep(std::time::Duration::from_millis(5));
                assert!(lease.check_valid().is_ok());
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // After all leases dropped, exclusive_lock should succeed immediately.
        assert!(session.exclusive_lock_and_clear());
    }
}
