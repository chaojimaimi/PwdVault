use std::sync::Arc;

use crate::database::{self, delete_group, list_groups, load_group, save_group, Group};
use crate::service::vault::{get_db, get_mac_key};
use crate::{AppState, VaultError};

pub fn create_group(state: &Arc<AppState>, name: String) -> Result<Group, VaultError> {
    if !state.keystore.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.keystore.get_key()?;
    let group = Group::new(name);
    save_group(&db, &key, &group)?;

    let mac_key = get_mac_key(state)?;
    database::integrity::refresh_digest(&db, &mac_key)?;

    state.touch_activity();
    Ok(group)
}

pub fn list_all_groups(state: &Arc<AppState>) -> Result<Vec<Group>, VaultError> {
    if !state.keystore.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.keystore.get_key()?;
    let ids = list_groups(&db)?;
    let mut groups = Vec::new();
    for id in ids {
        if let Some(g) = load_group(&db, &key, &id)? {
            groups.push(g);
        }
    }

    state.touch_activity();
    Ok(groups)
}

pub fn update_group(
    state: &Arc<AppState>,
    id: String,
    name: String,
) -> Result<Group, VaultError> {
    if !state.keystore.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.keystore.get_key()?;
    let mut group = load_group(&db, &key, &id)?.ok_or(VaultError::InternalError(
        "Group not found".to_string(),
    ))?;
    group.name = name;
    group.updated_at = chrono::Utc::now().timestamp();
    save_group(&db, &key, &group)?;

    let mac_key = get_mac_key(state)?;
    database::integrity::refresh_digest(&db, &mac_key)?;

    state.touch_activity();
    Ok(group)
}

pub fn remove_group(state: &Arc<AppState>, id: String) -> Result<bool, VaultError> {
    if !state.keystore.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.keystore.get_key()?;
    let existed = delete_group(&db, &id)?;

    // Cascade: clear group_id on entries that referenced the deleted group
    if existed {
        let entry_ids = database::list_entries(&db)?;
        for entry_id in entry_ids {
            if let Some(mut entry) = database::load_entry(&db, &key, &entry_id)? {
                if entry.group_id.as_deref() == Some(id.as_str()) {
                    entry.group_id = None;
                    database::save_entry(&db, &key, &entry)?;
                }
            }
        }
    }

    let mac_key = get_mac_key(state)?;
    database::integrity::refresh_digest(&db, &mac_key)?;

    state.touch_activity();
    Ok(existed)
}
