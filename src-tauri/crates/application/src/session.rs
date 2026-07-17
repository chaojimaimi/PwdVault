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

use pwdvault_infrastructure::crypto::SecretKey;
use crate::VaultError;
use std::sync::{Mutex, RwLock, RwLockReadGuard};
use std::time::Instant;

/// Raw key inputs accepted only at the atomic unlock boundary.
pub type EncKey = [u8; 32];
pub type MacKey = [u8; 32];

/// Inner state held behind the session mutex.
enum SessionInner {
    /// No keys are loaded; the vault requires an unlock operation.
    /// Carries the last generation so re-unlock increments correctly.
    Locked { generation: u64 },
    /// Keys and activity timer are live.
    Unlocked {
        enc_key: SecretKey,
        mac_key: SecretKey,
        last_activity: Mutex<Instant>,
        /// Monotonically increasing counter incremented on each unlock.
        /// Used by [`SessionLease`] to detect that the session changed
        /// (lock → re-unlock) while the lease was held.
        generation: u64,
    },
}

/// Unified vault session state machine.
///
/// Holds enc_key, mac_key, last_activity, and session_generation behind an
/// `RwLock`. Each operation lease owns a read guard, preventing auto-lock from
/// obtaining the write guard and clearing keys until the operation finishes.
pub struct VaultSession {
    inner: RwLock<SessionInner>,
}

impl Default for VaultSession {
    fn default() -> Self {
        Self {
            inner: RwLock::new(SessionInner::Locked { generation: 0 }),
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
    pub fn unlock(&self, enc_key: impl Into<SecretKey>, mac_key: impl Into<SecretKey>) {
        let mut inner = self.inner.write().expect("session lock poisoned");
        let next_generation = match &*inner {
            SessionInner::Unlocked { generation, .. } => generation + 1,
            SessionInner::Locked { generation } => generation + 1,
        };
        *inner = SessionInner::Unlocked {
            enc_key: enc_key.into(),
            mac_key: mac_key.into(),
            last_activity: Mutex::new(Instant::now()),
            generation: next_generation,
        };
    }

    /// Check if the vault is currently unlocked (keys are in memory).
    pub fn is_unlocked(&self) -> bool {
        let inner = self.inner.read().expect("session lock poisoned");
        matches!(*inner, SessionInner::Unlocked { .. })
    }

    /// Get the encryption key.
    #[cfg(test)]
    pub fn get_enc_key(&self) -> Result<EncKey, VaultError> {
        let inner = self.inner.read().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked { enc_key, .. } => Ok(*enc_key.as_ref()),
            SessionInner::Locked { .. } => Err(VaultError::VaultLocked),
        }
    }

    /// Get the MAC key.
    #[cfg(test)]
    pub fn get_mac_key(&self) -> Result<MacKey, VaultError> {
        let inner = self.inner.read().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked { mac_key, .. } => Ok(*mac_key.as_ref()),
            SessionInner::Locked { .. } => Err(VaultError::VaultLocked),
        }
    }

    /// Update the activity timestamp (called on successful vault operations).
    pub fn touch_activity(&self) {
        let inner = self.inner.read().expect("session lock poisoned");
        if let SessionInner::Unlocked { last_activity, .. } = &*inner {
            *last_activity.lock().expect("activity lock poisoned") = Instant::now();
        }
    }

    /// Read the activity timestamp and auto-lock timeout to determine
    /// whether auto-lock should fire. Returns `Some(deadline)` if the vault
    /// is unlocked and a deadline can be computed.
    pub fn auto_lock_deadline(&self, timeout_secs: u64) -> Option<Instant> {
        let inner = self.inner.read().expect("session lock poisoned");
        if let SessionInner::Unlocked { last_activity, .. } = &*inner {
            Some(
                *last_activity.lock().expect("activity lock poisoned")
                    + std::time::Duration::from_secs(timeout_secs),
            )
        } else {
            None
        }
    }

    /// Check whether auto-lock should fire given the current elapsed time.
    ///
    /// Returns `true` only if the vault is unlocked AND the activity timer
    /// has exceeded `timeout_secs`.
    pub fn should_auto_lock(&self, timeout_secs: u64) -> bool {
        let inner = self.inner.read().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked { last_activity, .. } => {
                last_activity
                    .lock()
                    .expect("activity lock poisoned")
                    .elapsed()
                    .as_secs()
                    >= timeout_secs
            }
            SessionInner::Locked { .. } => false,
        }
    }

    /// Obtain an operation lease.
    ///
    /// The lease holds a read guard, preventing auto-lock from clearing keys
    /// while the operation is in progress. It also snapshots the current
    /// `session_generation` so callers can detect stale state.
    ///
    /// Returns an error if the vault is locked.
    pub fn lease(&self) -> Result<SessionLease<'_>, VaultError> {
        let guard = self.inner.read().expect("session lock poisoned");
        match &*guard {
            SessionInner::Unlocked { generation, .. } => {
                let generation = *generation;
                Ok(SessionLease { guard, generation })
            }
            SessionInner::Locked { .. } => Err(VaultError::VaultLocked),
        }
    }

    /// Obtain an exclusive lease for auto-lock.
    ///
    /// Waits for all operation leases to release their read guards, then
    /// atomically clears keys and transitions to Locked. This ensures no
    /// operation is mid-flight when keys are wiped.
    ///
    /// Returns `true` if the vault was unlocked and is now locked.
    pub fn exclusive_lock_and_clear(&self) -> bool {
        // Taking the write lock blocks until every SessionLease has dropped
        // its read guard. New leases cannot pass while this guard is held.
        let mut inner = self.inner.write().expect("session lock poisoned");
        match std::mem::replace(&mut *inner, SessionInner::Locked { generation: 0 }) {
            SessionInner::Unlocked {
                enc_key,
                mac_key,
                generation,
                ..
            } => {
                // SecretKey zeroizes both values when they are dropped here.
                drop(enc_key);
                drop(mac_key);
                *inner = SessionInner::Locked { generation };
                true
            }
            SessionInner::Locked { generation } => {
                *inner = SessionInner::Locked { generation };
                false
            }
        }
    }
}

/// An operation lease on the vault session.
///
/// While held, auto-lock cannot clear the session keys. The `generation`
/// field captures the session_generation at acquisition time; callers can
/// use [`SessionLease::check_valid`] to detect that the session changed
/// (e.g. another thread locked and re-unlocked) during the operation.
pub struct SessionLease<'a> {
    guard: RwLockReadGuard<'a, SessionInner>,
    generation: u64,
}

impl<'a> SessionLease<'a> {
    /// Get the encryption key (valid for the lifetime of this lease).
    pub fn enc_key(&self) -> Result<&[u8; 32], VaultError> {
        match &*self.guard {
            SessionInner::Unlocked { enc_key, .. } => Ok(enc_key.as_ref()),
            SessionInner::Locked { .. } => Err(VaultError::VaultLocked),
        }
    }

    /// Get the MAC key (valid for the lifetime of this lease).
    pub fn mac_key(&self) -> Result<&[u8; 32], VaultError> {
        match &*self.guard {
            SessionInner::Unlocked { mac_key, .. } => Ok(mac_key.as_ref()),
            SessionInner::Locked { .. } => Err(VaultError::VaultLocked),
        }
    }

    /// Mark successful activity without re-entering the session RwLock.
    pub fn touch_activity(&self) {
        if let SessionInner::Unlocked { last_activity, .. } = &*self.guard {
            *last_activity.lock().expect("activity lock poisoned") = Instant::now();
        }
    }

    /// Check that the session generation hasn't changed since acquisition.
    ///
    /// Returns `Ok(())` if the session is still the same generation (or still
    /// unlocked with a newer generation — the caller should treat a generation
    /// mismatch as a stale-state error).
    pub fn check_valid(&self) -> Result<(), VaultError> {
        match &*self.guard {
            SessionInner::Unlocked { generation, .. } if *generation == self.generation => Ok(()),
            _ => Err(VaultError::VaultLocked),
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
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let session = Arc::new(VaultSession::new());
        session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

        let lease = session.lease().unwrap();
        assert_eq!(lease.enc_key().unwrap(), &TEST_ENC_KEY);
        let (tx, rx) = mpsc::channel();
        let locking_session = Arc::clone(&session);
        let handle = std::thread::spawn(move || {
            let locked = locking_session.exclusive_lock_and_clear();
            tx.send(locked).unwrap();
        });

        // The write lock must not clear the keys while the read lease exists.
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        assert_eq!(lease.enc_key().unwrap(), &TEST_ENC_KEY);
        drop(lease);
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
        handle.join().unwrap();
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
                assert_eq!(lease.enc_key().unwrap(), &TEST_ENC_KEY);
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

    #[test]
    fn test_one_thousand_mixed_session_operations() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let session = Arc::new(VaultSession::new());
        session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
        let barrier = Arc::new(Barrier::new(10));
        let mut handles = Vec::new();

        // Eight operation workers model IPC/HTTP service calls.
        for _ in 0..8 {
            let session = Arc::clone(&session);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..100 {
                    if let Ok(lease) = session.lease() {
                        assert_eq!(lease.enc_key().unwrap(), &TEST_ENC_KEY);
                        assert_eq!(lease.mac_key().unwrap(), &TEST_MAC_KEY);
                        assert!(lease.check_valid().is_ok());
                    }
                    thread::yield_now();
                }
            }));
        }

        // One activity worker models successful commands resetting auto-lock.
        {
            let session = Arc::clone(&session);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..100 {
                    session.touch_activity();
                    thread::yield_now();
                }
            }));
        }

        // One exclusive worker models auto-lock followed by user unlock.
        {
            let session = Arc::clone(&session);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..100 {
                    session.exclusive_lock_and_clear();
                    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
                    thread::yield_now();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
        assert!(session.is_unlocked());
    }
}
