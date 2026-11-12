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
//!     ├── last_remote_activity
//!     └── session_generation
//! ```
//!
//! All service operations obtain an operation [`SessionLease`] (a shared/read
//! guard) that keeps the keys alive for the duration of the operation.
//! Auto-lock obtains an [`ExclusiveLease`] (exclusive/write guard) that waits
//! for all operation leases to drain before clearing the keys.
//!
//! ## SEC-L5 remote-activity grace policy (v1.2.0)
//!
//! Service-layer operations serve both desktop IPC and the extension HTTP
//! bridge and cannot tell the callers apart, so every explicit vault
//! operation (`SessionLease::touch_remote_activity`) only extends a short
//! [`REMOTE_ACTIVITY_GRACE_SECS`] window instead of the full auto-lock
//! timeout. The vault stays alive while
//! `now < max(last_activity + timeout, last_remote_activity + grace)`:
//! the in-person desktop user is kept alive for the FULL window by the
//! webview input heartbeat (`src/App.tsx` pointermove/pointerdown/keydown →
//! the `touch_activity` IPC command), while an unattended extension fill
//! only buys the 120s grace — "no one at the keyboard ⇒ locks soon".

use crate::VaultError;
use pwdvault_domain::constants::REMOTE_ACTIVITY_GRACE_SECS;
use pwdvault_infrastructure::crypto::SecretKey;
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
        /// SEC-L5: last explicit vault-operation timestamp (desktop IPC and
        /// extension HTTP alike — the service layer cannot distinguish the
        /// callers). Deliberately a variant field: built as `None` by every
        /// unlock and discarded with the variant on lock, so a stale grace
        /// window can never survive a lock/unlock cycle.
        last_remote_activity: Mutex<Option<Instant>>,
        /// Monotonically increasing counter incremented on each unlock.
        /// Used by [`SessionLease`] to detect that the session changed
        /// (lock → re-unlock) while the lease was held.
        generation: u64,
        /// Phase 1 (D5): biometric wrap key, cached ONLY by the session that
        /// unlocked via Touch ID. Deliberately a session slot — never an
        /// AppState field — so a password-derived session naturally has none,
        /// a republish (key change) naturally drops it, and locking naturally
        /// zeroizes it.
        wrap_key: Option<SecretKey>,
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
        self.unlock_if(enc_key, mac_key, |_| true);
    }

    /// Atomically transition to Unlocked state ONLY while `predicate` holds
    /// (fix plan A §2.3: publish window keys without ever revoking a lock).
    ///
    /// The predicate is evaluated inside the SAME critical section as the
    /// state flip — under the session's write lock, immediately before it —
    /// so there is no check/publish gap for a concurrent lock to slip
    /// through. It receives the live session generation (the counter that
    /// locking preserves and each unlock bumps), letting callers detect a
    /// concurrent key rotation without taking a second lock (which would
    /// deadlock against this write guard).
    ///
    /// Returns whether the keys were published. On `false` the session is
    /// left EXACTLY as it was and the offered keys are dropped (zeroized).
    pub fn unlock_if(
        &self,
        enc_key: impl Into<SecretKey>,
        mac_key: impl Into<SecretKey>,
        predicate: impl FnOnce(u64) -> bool,
    ) -> bool {
        let mut inner = self.inner.write().expect("session lock poisoned");
        let live_generation = match &*inner {
            SessionInner::Unlocked { generation, .. } => *generation,
            SessionInner::Locked { generation } => *generation,
        };
        if !predicate(live_generation) {
            // Declined: the keys are dropped here (zeroized); the session
            // stays untouched (Locked for a drained D8 window).
            return false;
        }
        // Same increment rule as the unconditional unlock above.
        *inner = SessionInner::Unlocked {
            enc_key: enc_key.into(),
            mac_key: mac_key.into(),
            last_activity: Mutex::new(Instant::now()),
            // Fresh session: no remote activity has happened yet, so the
            // grace window contributes nothing to the deadline.
            last_remote_activity: Mutex::new(None),
            generation: live_generation + 1,
            // A fresh session never carries a wrap key; only
            // [`VaultSession::set_wrap_key`] installs one after a
            // successful Touch ID unlock (D5).
            wrap_key: None,
        };
        true
    }

    /// v1.8.3 F1/R3 republish variant of [`VaultSession::unlock_if`] for the
    /// sync cycle: the SAME state machine (predicate checked inside the
    /// write critical section, generation +1 on publish, refusal leaves the
    /// session untouched and drops the offered keys) — the only difference
    /// is that the rebuilt `Unlocked` inner carries the CALLER'S presence
    /// timestamps instead of `now`/`None`. The drain destroyed the
    /// originals, so the cycle passes its cycle-start `activity_snapshot`
    /// back through; the plain [`VaultSession::unlock_if`] stays for the
    /// password/recovery windows, whose republish happens with the user at
    /// the keyboard (a fresh `last_activity` is the correct presence signal
    /// there).
    pub fn unlock_if_restoring(
        &self,
        enc_key: impl Into<SecretKey>,
        mac_key: impl Into<SecretKey>,
        predicate: impl FnOnce(u64) -> bool,
        last_activity: Instant,
        last_remote_activity: Option<Instant>,
    ) -> bool {
        let mut inner = self.inner.write().expect("session lock poisoned");
        let live_generation = match &*inner {
            SessionInner::Unlocked { generation, .. } => *generation,
            SessionInner::Locked { generation } => *generation,
        };
        if !predicate(live_generation) {
            // Declined: the keys are dropped here (zeroized); the session
            // stays untouched — identical to `unlock_if`.
            return false;
        }
        // Same increment rule as `unlock_if` above.
        *inner = SessionInner::Unlocked {
            enc_key: enc_key.into(),
            mac_key: mac_key.into(),
            last_activity: Mutex::new(last_activity),
            last_remote_activity: Mutex::new(last_remote_activity),
            generation: live_generation + 1,
            // Fresh session, same rule as `unlock_if` (D5): a republish
            // never carries a wrap key — Touch ID re-prompts, as before.
            wrap_key: None,
        };
        true
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

    /// v1.8.3 F1/R3: snapshot the presence timestamps. The sync cycle
    /// captures them at cycle start because its merge window's drain
    /// (`exclusive_lock_and_clear`) DESTROYS them — and the republish must
    /// restore, not refresh, them (see [`VaultSession::unlock_if_restoring`];
    /// a plain `unlock_if` rebuild rebuilds with `now`/`None`, which kept an
    /// unattended desktop awake forever once auto-sync ran). Locked sessions
    /// report the current instant and no grace slot — the sync cycle only
    /// snapshots right after its key copy succeeded, i.e. while unlocked,
    /// so the arm is defensive only.
    pub fn activity_snapshot(&self) -> (Instant, Option<Instant>) {
        let inner = self.inner.read().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked {
                last_activity,
                last_remote_activity,
                ..
            } => (
                *last_activity.lock().expect("activity lock poisoned"),
                *last_remote_activity
                    .lock()
                    .expect("remote activity lock poisoned"),
            ),
            SessionInner::Locked { .. } => (Instant::now(), None),
        }
    }

    /// SEC-L5: record an explicit vault operation (desktop IPC or extension
    /// HTTP — the service layer cannot tell them apart). Extends only the
    /// short remote grace window, never the full auto-lock timeout; see the
    /// module-level policy note.
    pub fn touch_remote_activity(&self) {
        let inner = self.inner.read().expect("session lock poisoned");
        if let SessionInner::Unlocked {
            last_remote_activity,
            ..
        } = &*inner
        {
            *last_remote_activity
                .lock()
                .expect("remote activity lock poisoned") = Some(Instant::now());
        }
    }

    /// Cache the biometric wrap key into the current Unlocked session (D5).
    ///
    /// Must only be called after a successful Touch ID unlock. If the session
    /// has been locked (or replaced) meanwhile, the key is dropped — a Locked
    /// session never stores wrap keys.
    pub fn set_wrap_key(&self, wrap_key: SecretKey) {
        let mut inner = self.inner.write().expect("session lock poisoned");
        if let SessionInner::Unlocked { wrap_key: slot, .. } = &mut *inner {
            *slot = Some(wrap_key);
        }
        // Locked: `wrap_key` is dropped here and zeroized.
    }

    /// Get the cached biometric wrap key, if this session unlocked via
    /// Touch ID. Returns `None` when the caller must fall back to the
    /// credential store (which may prompt).
    ///
    /// The copy is handed over as a zeroizing [`SecretKey`] (never a bare
    /// array) so it is wiped on drop; it is never written to disk or logs by
    /// any caller in this codebase.
    pub fn cached_wrap_key(&self) -> Option<SecretKey> {
        let inner = self.inner.read().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked {
                wrap_key: Some(key),
                ..
            } => Some(SecretKey::new(*key.as_ref())),
            _ => None,
        }
    }

    /// Read the activity timestamps and auto-lock timeout to determine
    /// whether auto-lock should fire. Returns `Some(deadline)` if the vault
    /// is unlocked and a deadline can be computed.
    ///
    /// SEC-L5 max semantics: the vault stays alive while
    /// `now < max(last_activity + timeout, last_remote_activity + grace)`.
    /// A remote (extension) touch therefore never pushes the deadline past
    /// its short grace window, and a fresh local touch always wins over a
    /// stale remote one.
    pub fn auto_lock_deadline(&self, timeout_secs: u64) -> Option<Instant> {
        let inner = self.inner.read().expect("session lock poisoned");
        if let SessionInner::Unlocked {
            last_activity,
            last_remote_activity,
            ..
        } = &*inner
        {
            let local_deadline = *last_activity.lock().expect("activity lock poisoned")
                + std::time::Duration::from_secs(timeout_secs);
            let remote_deadline = (*last_remote_activity
                .lock()
                .expect("remote activity lock poisoned"))
            .map(|t| t + std::time::Duration::from_secs(REMOTE_ACTIVITY_GRACE_SECS));
            Some(match remote_deadline {
                Some(remote) if remote > local_deadline => remote,
                _ => local_deadline,
            })
        } else {
            None
        }
    }

    /// Check whether auto-lock should fire given the current elapsed time.
    ///
    /// Returns `true` only if the vault is unlocked AND both windows have
    /// expired: the local inactivity timer exceeds `timeout_secs` AND the
    /// remote grace window (SEC-L5) has lapsed — `now >= deadline` is
    /// equivalent to both when the deadline is their max.
    pub fn should_auto_lock(&self, timeout_secs: u64) -> bool {
        let inner = self.inner.read().expect("session lock poisoned");
        match &*inner {
            SessionInner::Unlocked {
                last_activity,
                last_remote_activity,
                ..
            } => {
                let local_expired = last_activity
                    .lock()
                    .expect("activity lock poisoned")
                    .elapsed()
                    .as_secs()
                    >= timeout_secs;
                let remote_expired = match *last_remote_activity
                    .lock()
                    .expect("remote activity lock poisoned")
                {
                    Some(t) => t.elapsed().as_secs() >= REMOTE_ACTIVITY_GRACE_SECS,
                    // No remote activity this session: nothing to wait for.
                    None => true,
                };
                local_expired && remote_expired
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
                last_activity: _,
                last_remote_activity: _,
                wrap_key,
                generation,
            } => {
                // All secret material zeroizes when dropped here.
                // (`last_activity` / `last_remote_activity` are Instants — no
                // Drop impl, nothing to release — so they are simply
                // discarded with the struct. Discarding the slot is what
                // clears a pending grace window on lock.)
                drop(enc_key);
                drop(mac_key);
                drop(wrap_key);
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
/// compare `generation()` against a fresh lease's snapshot later on to
/// detect that the session changed (e.g. another thread locked and
/// re-unlocked) during the operation.
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

    /// The session generation snapshot taken at lease acquisition.
    ///
    /// Callers that copy key material out of a lease (the D8 flows) compare
    /// this against a fresh lease's generation later on: a mismatch proves
    /// the session was re-published in the meantime (lock → re-unlock or a
    /// key-rotating re-seal), so the copied keys are stale.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Mark successful activity without re-entering the session RwLock.
    pub fn touch_activity(&self) {
        if let SessionInner::Unlocked { last_activity, .. } = &*self.guard {
            *last_activity.lock().expect("activity lock poisoned") = Instant::now();
        }
    }

    /// SEC-L5: mark a successful explicit vault operation (desktop IPC or
    /// extension HTTP) without re-entering the session RwLock. Extends only
    /// the short remote grace window, never the full auto-lock timeout.
    pub fn touch_remote_activity(&self) {
        if let SessionInner::Unlocked {
            last_remote_activity,
            ..
        } = &*self.guard
        {
            *last_remote_activity
                .lock()
                .expect("remote activity lock poisoned") = Some(Instant::now());
        }
    }

    /// Check that the session generation hasn't changed since acquisition.
    ///
    /// Returns `Ok(())` if the session is still the same generation (or still
    /// unlocked with a newer generation — the caller should treat a generation
    /// mismatch as a stale-state error).
    #[cfg(test)]
    pub(crate) fn check_valid(&self) -> Result<(), VaultError> {
        match &*self.guard {
            SessionInner::Unlocked { generation, .. } if *generation == self.generation => Ok(()),
            _ => Err(VaultError::VaultLocked),
        }
    }
}


#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
