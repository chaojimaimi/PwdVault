//! Business logic service layer shared by Tauri commands and HTTP handlers.

pub mod backup;
pub mod entries;
pub mod groups;
pub mod settings;
pub mod utils;
pub mod vault;

pub use backup::{export_vault, import_vault};
pub use entries::{
    create_entry, get_entry_count, get_entry_meta, get_entry_secret, list_all_entries,
    remove_entry, update_entry,
};
pub use groups::{create_group, list_all_groups, remove_group, update_group};
pub use settings::{get_settings, update_settings};
pub use utils::generate_password;
pub use vault::{
    check_rate_limit, init_vault, is_initialized, is_unlocked, lock_vault, record_failed_attempt,
    reset_rate_limit, setup_vault, unlock_vault,
};
