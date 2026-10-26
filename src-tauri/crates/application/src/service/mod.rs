//! Business logic service layer shared by Tauri commands and HTTP handlers.

pub mod backup;
pub mod csv_import;
pub mod entries;
pub mod extension;
pub mod groups;
pub mod recovery_file;
pub mod security;
pub mod security_report;
pub mod settings;
pub mod sync;
pub mod totp;
pub mod trash_sweep;
pub mod utils;
pub mod vault;

pub use backup::{export_vault, import_vault, parse_backup_file_bytes};
// WP2 (v1.5.0): third-party CSV importer — Tauri-only commands (D6).
pub use csv_import::{import_csv_commit, import_csv_open, CsvImportPreview, CsvImportResult};
// WP1 (v1.5.0): security dashboard aggregation — Tauri-only (D6). The
// response container is the wire contract; ids/scores only, no plaintext.
pub use entries::{
    create_entry, empty_trash, get_entry_count, get_entry_meta, get_entry_secret, list_all_entries,
    list_deleted_entries, purge_entry, remove_entry, restore_entry, update_entry,
};
pub use extension::revoke_extension_access;
pub use groups::{create_group, list_all_groups, remove_group, update_group};
pub use recovery_file::{enable_recovery_with_file, EnableRecoveryResult};
pub use security::{
    biometric_status, change_password, complete_unlock, derive_master_for_unlock,
    disable_biometric, disable_recovery, enable_biometric, enable_recovery, recover_vault,
    recovery_status, unlock_biometric, verify_master_and_integrity,
};
pub use security_report::{security_report, SecurityReport};
pub use settings::{get_settings, update_settings};
pub use sync::baidu_oauth::{baidu_complete_auth, baidu_start_auth, BaiduAuthStart};
pub use sync::engine::{
    sync_connect, sync_disconnect, sync_now, sync_status, SyncBackendKind, SyncConfig, SyncState,
    SyncStatusResponse,
};
pub use totp::totp_code;
// WP3 (v1.5.0): post-unlock trash auto-purge. Pure function by design — the
// adapters that hold the emit capability surface `trash-auto-purged(count)`.
pub use trash_sweep::run_trash_auto_purge;
pub use utils::{generate_passphrase, generate_password, generate_pin};
pub use vault::{
    check_rate_limit, init_vault, is_initialized, is_unlocked, lock_vault, record_failed_attempt,
    reset_rate_limit, setup_vault, unlock_vault,
};

// SEC-L5 touch-policy regression test that needs a real service call.
#[cfg(test)]
mod touch_policy_tests;
