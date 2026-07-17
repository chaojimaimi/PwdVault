use std::sync::Arc;

use pwdvault_infrastructure::database::{load_settings, vault_store, Settings};
use crate::service::vault::get_db;
use crate::{AppState, VaultError};

pub fn get_settings(state: &Arc<AppState>) -> Result<Settings, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let settings = load_settings(&db)?;
    lease.touch_activity();
    Ok(settings)
}

pub fn update_settings(state: &Arc<AppState>, settings: Settings) -> Result<Settings, VaultError> {
    let lease = state.lease()?;
    pwdvault_domain::validation::settings(&settings)?;
    let db = get_db(state)?;
    let mac_key = lease.mac_key()?;

    // Single transaction: settings write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_settings_in_txn(txn, &settings)?;
        Ok(())
    })?;

    // Apply auto-lock timeout immediately
    *state.auto_lock_secs.lock().expect("timeout lock poisoned") = settings.auto_lock_secs;
    lease.touch_activity();
    Ok(settings)
}
