use std::sync::Arc;

use crate::service::vault::get_db;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::database::{
    list_all_entries_bulk, list_all_groups_bulk, load_group, vault_store, Group,
};

pub fn create_group(state: &Arc<AppState>, name: String) -> Result<Group, VaultError> {
    let lease = state.lease()?;
    let name = pwdvault_domain::validation::group_name(&name)?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    // §5.6.2: single bulk scan for the duplicate-name check instead of
    // list-groups-then-load-each.
    let name_lower = name.to_ascii_lowercase();
    for g in list_all_groups_bulk(&db, key)? {
        if g.name.to_ascii_lowercase() == name_lower {
            return Err(VaultError::InvalidInput {
                code: "DUPLICATE_GROUP_NAME".into(),
                message: "A group with this name already exists".into(),
            });
        }
    }
    let group = Group::new(name);

    // Single transaction: business write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_group_in_txn(txn, key, &group)?;
        Ok(())
    })?;

    lease.touch_activity();
    Ok(group)
}

pub fn list_all_groups(state: &Arc<AppState>) -> Result<Vec<Group>, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;

    // §5.6.2: single read transaction bulk scan instead of 1+N.
    let groups = list_all_groups_bulk(&db, key)?;

    lease.touch_activity();
    Ok(groups)
}

pub fn update_group(state: &Arc<AppState>, id: String, name: String) -> Result<Group, VaultError> {
    let lease = state.lease()?;
    pwdvault_domain::validation::id(&id)?;
    let name = pwdvault_domain::validation::group_name(&name)?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    // §5.6.2: single bulk scan for the duplicate-name check.
    let name_lower = name.to_ascii_lowercase();
    for g in list_all_groups_bulk(&db, key)? {
        if g.id != id && g.name.to_ascii_lowercase() == name_lower {
            return Err(VaultError::InvalidInput {
                code: "DUPLICATE_GROUP_NAME".into(),
                message: "A group with this name already exists".into(),
            });
        }
    }
    let mut group = load_group(&db, key, &id)?
        .ok_or(VaultError::InternalError("Group not found".to_string()))?;
    group.name = name;
    group.updated_at = chrono::Utc::now().timestamp();

    // Single transaction: business write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_group_in_txn(txn, key, &group)?;
        Ok(())
    })?;

    lease.touch_activity();
    Ok(group)
}

pub fn remove_group(state: &Arc<AppState>, id: String) -> Result<bool, VaultError> {
    let lease = state.lease()?;
    pwdvault_domain::validation::id(&id)?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    // §5.6.2: single bulk read transaction to find entries referencing this
    // group, instead of list-IDs + N×load_entry.
    let entries_to_update: Vec<_> = list_all_entries_bulk(&db, key, Some(id.as_str()))?
        .into_iter()
        .map(|mut e| {
            e.group_id = None;
            e
        })
        .collect();

    // Single transaction: delete group + cascade clear entries + digest (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    let existed = store.write(mac_key, |txn| {
        let existed = vault_store::delete_group_in_txn(txn, &id)?;
        // Cascade: clear group_id on entries that referenced the deleted group
        for entry in &entries_to_update {
            vault_store::save_entry_in_txn(txn, key, entry)?;
        }
        Ok(existed)
    })?;

    lease.touch_activity();
    Ok(existed)
}
