//! PwdVault application layer (§5.6.3).
//!
//! Use cases: vault lifecycle (init/unlock/lock/migrate), entry/group/settings
//! CRUD, backup import/export, session management, and update check. Depends
//! on `pwdvault_domain` (entities, DTOs, validation) and
//! `pwdvault_infrastructure` (redb, crypto, filesystem).

pub mod error;
pub mod service;
pub mod session;
pub mod state;

#[cfg(test)]
pub mod fixtures;

pub use error::VaultError;
pub use service::*;
pub use session::VaultSession;
pub use state::AppState;

// Re-export the validation policy so service modules can write
// `crate::validation::group_name(...)` — the canonical home is the domain
// crate, but the application call sites predate the split.
pub use pwdvault_domain::validation;
pub use validation::ValidationPolicy;

// Re-export domain types that adapters commonly need, so they can depend on
// `pwdvault_application` alone without also naming `pwdvault_domain`.
pub use pwdvault_domain::{
    BackupPayload, CreateEntryRequest, EntrySecretResponse, EntrySummary, ExportEntry, Group,
    ImportResult, PasswordEntry, Settings, UpdateEntryRequest, UpdateInfo, VaultBackup,
};
