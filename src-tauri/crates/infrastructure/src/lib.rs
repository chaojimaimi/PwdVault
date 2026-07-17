//! PwdVault infrastructure layer (§5.6.3).
//!
//! Concrete implementations: the redb repository, AES-GCM/Argon2id/HKDF
//! crypto, filesystem/permission helpers, native-host registration, and
//! extension auth/pairing state. Depends on `pwdvault_domain` for entity
//! types, DTOs, and the validation policy.

pub mod auth;
pub mod crypto;
pub mod database;
pub mod native_host_setup;
pub mod pairing;
pub mod paths;
pub mod vault_header;

// Re-export the crypto VerificationData at the crate root for compatibility
// with call sites that previously wrote `crate::crypto::VerificationData`.
pub use crypto::VerificationData;
