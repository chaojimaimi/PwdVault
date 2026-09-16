//! Security operations on the vault master key (Phase 1).
//!
//! Three features share one wrap-key infrastructure:
//! - **Change master password** — re-benchmarks KDF params, re-derives the
//!   master key, re-seals the whole vault in a single transaction, and
//!   re-wraps any stored credential blobs (Touch ID / recovery).
//! - **Touch ID (biometric) unlock** — the master key is wrapped under a
//!   random wrap key kept in the platform credential store behind a biometric
//!   access control (macOS only, D7).
//! - **Recovery key** — the master key is wrapped under SHA-256 of a random
//!   256-bit key shown once to the user.
//!
//! ## D8 — exclusive-clear serialization of full re-seals
//!
//! Write services hold only a read lease (see `entries.rs`), so a naive
//! "read all → re-seal → write" window would let in-flight writes either (A)
//! be silently swallowed by a stale snapshot overwrite, or (B) commit under
//! the OLD key after the swap, mixing keys and refreshing the digest with the
//! old MAC — permanently locking the vault. Every re-seal therefore follows
//! this protocol:
//!
//! 1. *Preamble (no DB writes)*: validate inputs, verify the current
//!    password, derive the new keys, and complete ALL credential-store
//!    interaction (Touch ID prompts). Then take ONE lease to copy the old
//!    enc/mac into local `SecretKey`s and release it immediately.
//! 2. Call `session.exclusive_lock_and_clear()` — drains every in-flight
//!    lease and rejects new ones (never called while holding a lease).
//! 3. Assert the session is still Locked (a concurrent password unlock in
//!    between aborts the operation cleanly instead of mixing keys), read the
//!    full vault with the old-key copy, and re-seal everything — new
//!    verification row, re-encrypted header, re-wrapped blobs — in ONE
//!    `VaultStore::write` transaction.
//! 4. Success: republish the new keys exactly once. Failure: the transaction
//!    rolls back (disk unchanged) and the previous state is restored.
//!
//! Blob-writing settings operations (`enable_biometric`, `enable_recovery`,
//! `disable_*`) require an unlocked vault and hold a lease across their
//! `VaultStore::write`, so they are serialized against the re-seal window by
//! the same lease mechanism.

mod credentials;
mod password;
mod shared;

pub use credentials::{
    biometric_status, disable_biometric, disable_recovery, enable_biometric, enable_recovery,
    recovery_status, unlock_biometric,
};
pub use password::{change_password, recover_vault};
pub use shared::{
    complete_unlock, derive_master_for_unlock, verify_master_and_integrity, BIO_WRAP_BLOB_KEY,
    RECOVERY_WRAP_BLOB_KEY, SYNC_CEK_BLOB_KEY,
};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_credentials;
