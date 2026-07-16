use std::sync::Arc;

use crate::database::{self, list_groups, load_group, vault_store, Group};
use crate::service::vault::{get_db, get_mac_key};
use crate::{AppState, VaultError};

pub fn create_group(state: &Arc<AppState>, name: String) -> Result<Group, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.session.get_enc_key()?;
    let mac_key = get_mac_key(state)?;
    let group = Group::new(name);

    // Single transaction: business write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(&mac_key, |txn| {
        vault_store::save_group_in_txn(txn, &key, &group)?;
        Ok(())
    })?;

    state.touch_activity();
    Ok(group)
}

pub fn list_all_groups(state: &Arc<AppState>) -> Result<Vec<Group>, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.session.get_enc_key()?;
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

pub fn update_group(state: &Arc<AppState>, id: String, name: String) -> Result<Group, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.session.get_enc_key()?;
    let mac_key = get_mac_key(state)?;
    let mut group = load_group(&db, &key, &id)?
        .ok_or(VaultError::InternalError("Group not found".to_string()))?;
    group.name = name;
    group.updated_at = chrono::Utc::now().timestamp();

    // Single transaction: business write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(&mac_key, |txn| {
        vault_store::save_group_in_txn(txn, &key, &group)?;
        Ok(())
    })?;

    state.touch_activity();
    Ok(group)
}

pub fn remove_group(state: &Arc<AppState>, id: String) -> Result<bool, VaultError> {
    if !state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let db = get_db(state)?;
    let key = state.session.get_enc_key()?;
    let mac_key = get_mac_key(state)?;

    // Pre-load entries that reference this group for cascade clearing.
    let entry_ids = database::list_entries(&db)?;
    let mut entries_to_update = Vec::new();
    for entry_id in &entry_ids {
        if let Some(mut entry) = database::load_entry(&db, &key, entry_id)? {
            if entry.group_id.as_deref() == Some(id.as_str()) {
                entry.group_id = None;
                entries_to_update.push(entry);
            }
        }
    }

    // Single transaction: delete group + cascade clear entries + digest (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    let existed = store.write(&mac_key, |txn| {
        let existed = vault_store::delete_group_in_txn(txn, &id)?;
        // Cascade: clear group_id on entries that referenced the deleted group
        for entry in &entries_to_update {
            vault_store::save_entry_in_txn(txn, &key, entry)?;
        }
        Ok(existed)
    })?;

    state.touch_activity();
    Ok(existed)
}
