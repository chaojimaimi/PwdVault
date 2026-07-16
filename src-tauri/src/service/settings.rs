use std::sync::Arc;

use crate::database::{integrity, load_settings, save_settings, Settings};
use crate::service::vault::{get_db, get_mac_key};
use crate::{AppState, VaultError};

pub fn get_settings(state: &Arc<AppState>) -> Result<Settings, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }
    let db = get_db(state)?;
    let settings = load_settings(&db)?;
    state.touch_activity();
    Ok(settings)
}

pub fn update_settings(state: &Arc<AppState>, settings: Settings) -> Result<Settings, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }
    if settings.auto_lock_secs < 30 || settings.auto_lock_secs > 3600 {
        return Err(VaultError::InternalError(
            "Auto-lock timeout must be between 30 and 3600 seconds".to_string(),
        ));
    }
    if settings.default_length < 4 || settings.default_length > 128 {
        return Err(VaultError::InternalError(
            "Password length must be between 4 and 128".to_string(),
        ));
    }
    let db = get_db(state)?;
    save_settings(&db, &settings)?;
    // Refresh integrity digest so the new settings are part of the protected
    // state. Without this, settings tampering would not be detected on next
    // unlock because the digest still covers the old settings blob.
    let mac_key = get_mac_key(state)?;
    integrity::refresh_digest(&db, &mac_key)?;
    // Apply auto-lock timeout immediately
    *state.auto_lock_secs.lock().expect("timeout lock poisoned") = settings.auto_lock_secs;
    state.touch_activity();
    Ok(settings)
}
