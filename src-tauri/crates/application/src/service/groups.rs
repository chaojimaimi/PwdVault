use std::sync::Arc;

use crate::service::vault::get_db;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::database::{list_all_groups_bulk, load_group, vault_store, Group};

/// Duplicate-name scans must ignore tombstones: a soft-deleted group's name
/// is free again (the row is retained only for sync merge arbitration).
fn is_live(group: &Group) -> bool {
    group.deleted_at.is_none()
}

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
        if is_live(&g) && g.name.to_ascii_lowercase() == name_lower {
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
    // Soft delete (P2.2): the infra bulk scan is raw; the service layer
    // filters tombstones out here.
    let groups = list_all_groups_bulk(&db, key)?
        .into_iter()
        .filter(is_live)
        .collect::<Vec<_>>();

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
        if is_live(&g) && g.id != id && g.name.to_ascii_lowercase() == name_lower {
            return Err(VaultError::InvalidInput {
                code: "DUPLICATE_GROUP_NAME".into(),
                message: "A group with this name already exists".into(),
            });
        }
    }
    let mut group = load_group(&db, key, &id, false)?
        .filter(is_live)
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

    // Soft delete (P2.2): stamp a tombstone and keep the row. The old
    // cascade that cleared group_id on member entries is deliberately GONE —
    // dangling group references are allowed and render as "ungrouped", and
    // keeping the row lets sync merge (P3.1) arbitrate the deletion.
    let mut group = match load_group(&db, key, &id, false)? {
        Some(group) => group,
        None => return Ok(false),
    };
    let now = chrono::Utc::now().timestamp();
    group.deleted_at = Some(now);
    // Bump updated_at so LWW merge arbitration sees the delete as newest.
    group.updated_at = now;

    // Single transaction: tombstone write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_group_in_txn(txn, key, &group)?;
        Ok(())
    })?;

    lease.touch_activity();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{create_entry, create_group, list_all_entries, list_all_groups};
    use pwdvault_domain::validation::MAX_GROUP_NAME_BYTES;
    use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
    use pwdvault_infrastructure::database::{self, Settings};
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    const TEST_PASSWORD: &str = "group-test-password";

    fn unlocked_state() -> (Arc<AppState>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(
            database::init_database(dir.path().join("groups.db")).unwrap(),
        );
        let salt = [0x61; 16];
        let params = AdaptiveParams {
            m_cost: 16384,
            t_cost: 1,
            p_cost: 1,
        };
        let (master_key, _) =
            pwdvault_infrastructure::crypto::kdf::derive_key_with_params(
                TEST_PASSWORD,
                &salt,
                &params,
            )
            .unwrap();
        let verification =
            pwdvault_infrastructure::crypto::create_verification_header(&master_key, salt, params)
                .unwrap();
        let (enc_key, mac_key) =
            pwdvault_infrastructure::crypto::kdf::derive_subkeys(&master_key, &salt);

        database::vault_store::VaultStore::new(&db)
            .write(&mac_key, |txn| {
                database::vault_store::save_verification_data_in_txn(txn, &verification)?;
                pwdvault_infrastructure::vault_header::save_header_in_txn(
                    txn,
                    &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
                    &enc_key,
                )?;
                database::vault_store::save_settings_in_txn(txn, &Settings::default())?;
                Ok(())
            })
            .unwrap();

        let state = Arc::new(AppState::default());
        *state.database.lock().unwrap() = Some(db);
        *state.verification_data.lock().unwrap() = Some(verification);
        state.session.unlock(enc_key, mac_key);
        (state, dir)
    }

    fn entry_in_group(state: &Arc<AppState>, group_id: &str) -> crate::EntrySummary {
        create_entry(
            state,
            crate::CreateEntryRequest {
                title: "Member entry".to_string(),
                url: None,
                username: "user".to_string(),
                password: Zeroizing::new("secret".to_string()),
                notes: None,
                tags: vec![],
                group_id: Some(group_id.to_string()),
            },
        )
        .unwrap()
    }

    /// P3.6 item 1: remove_group soft-deletes WITHOUT clearing member
    /// group_id, the tombstone stays in infra, list filters it, the name
    /// becomes reusable, and updating the deleted group 404s.
    #[test]
    fn remove_group_soft_deletes_without_cascading() {
        let (state, _dir) = unlocked_state();
        let group = create_group(&state, "Work".to_string()).unwrap();
        let _entry = entry_in_group(&state, &group.id);

        assert!(remove_group(&state, group.id.clone()).unwrap());

        // Service layer hides the tombstone.
        assert!(list_all_groups(&state).unwrap().is_empty());

        // The member entry keeps its (now dangling) group_id.
        let summaries = list_all_entries(&state).unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].group_id.as_deref(), Some(group.id.as_str()));

        // Infra stays raw: the tombstone row survives and decrypts.
        let db = get_db(&state).unwrap();
        let raw =
            database::list_all_groups_bulk(&db, &state.session.get_enc_key().unwrap()).unwrap();
        assert_eq!(raw.len(), 1);
        assert!(raw[0].deleted_at.is_some());
        assert_eq!(raw[0].id, group.id);

        // The deleted group's name is reusable.
        let recreated = create_group(&state, "Work".to_string()).unwrap();
        assert_ne!(recreated.id, group.id);

        // Updating the tombstoned group fails closed.
        assert!(update_group(&state, group.id.clone(), "Zombie".to_string()).is_err());

        // Removing an unknown group still reports false.
        assert!(!remove_group(&state, "missing-group".to_string()).unwrap());
    }

    /// Live groups still update normally (regression guard for the
    /// `.filter(is_live)` insertion).
    #[test]
    fn live_group_rename_and_duplicate_check_unchanged() {
        let (state, _dir) = unlocked_state();
        let group = create_group(&state, "A".to_string()).unwrap();
        let renamed = update_group(&state, group.id.clone(), "B".to_string()).unwrap();
        assert_eq!(renamed.name, "B");

        // Duplicate live name still rejected...
        assert!(create_group(&state, "b".to_string()).is_err());
        // ...and length validation still applies.
        let long = "A".repeat(MAX_GROUP_NAME_BYTES + 1);
        assert!(create_group(&state, long).is_err());
    }
}
