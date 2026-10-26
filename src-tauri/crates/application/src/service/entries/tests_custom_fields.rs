//! v1.6.0 WP1: custom-field service behavior — sealing on create/update,
//! the meta-only summary contract, and the one-shot secret-fetch channel.

use super::*;
use zeroize::Zeroizing;

use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
use pwdvault_infrastructure::database::Settings;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "custom-field-test-password";

/// Same scaffold shape as the sibling `tests` module: unlocked in-memory
/// AppState.
fn unlocked_state() -> (Arc<AppState>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(database::init_database(dir.path().join("custom-fields.db")).unwrap());
    let salt = [0x73; 16];
    let params = AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        pwdvault_infrastructure::crypto::kdf::derive_key_with_params(TEST_PASSWORD, &salt, &params)
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

fn input(label: &str, value: &str, secret: bool) -> CustomFieldInput {
    CustomFieldInput {
        label: label.to_string(),
        value: value.to_string(),
        secret,
    }
}

/// Create seals plaintext inputs into encrypted rows; the summary carries
/// label + secret ONLY (serialized JSON never grows a value key — the shape
/// shared by the Tauri list exit and both NM summary exits), and
/// get_entry_secret is the only channel returning the plaintext values.
#[test]
fn create_seals_custom_fields_and_summary_stays_meta_only() {
    let (state, _dir) = unlocked_state();
    let summary = create_entry(
        &state,
        CreateEntryRequest {
            title: "With fields".to_string(),
            url: None,
            username: "user".to_string(),
            password: Zeroizing::new("pw".to_string()),
            notes: None,
            tags: vec![],
            group_id: None,
            url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
            custom_fields: vec![
                input("API Key", "key-value-1", true),
                input("Visible", "plain-value", false),
                // Empty value = the legal placeholder row.
                input("Placeholder", "", true),
            ],
        },
    )
    .unwrap();

    // The row really stores ciphertext (values are opaque bytes on disk).
    let db = get_db(&state).unwrap();
    let key = state.session.get_enc_key().unwrap();
    let row = load_entry(&db, &key, &summary.id, false).unwrap().unwrap();
    assert_eq!(row.custom_fields.len(), 3);
    assert_eq!(row.custom_fields[0].label, "API Key");
    assert!(row.custom_fields[0].secret);
    assert!(
        !row.custom_fields[0].value.is_empty(),
        "a non-empty input must seal to a non-empty ciphertext"
    );
    assert!(
        row.custom_fields[2].value.is_empty(),
        "the empty input stays the empty-vec placeholder"
    );

    // Summary exit (list + NM meta shape): labels + secret, NO values.
    let listed = list_all_entries(&state).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].custom_fields.len(), 3);
    assert_eq!(listed[0].custom_fields[0].label, "API Key");
    assert!(listed[0].custom_fields[0].secret);
    let json = serde_json::to_value(&listed[0]).unwrap();
    for field in json["custom_fields"].as_array().unwrap() {
        assert!(
            field.get("value").is_none(),
            "summary leaked a custom-field value key: {field}"
        );
    }

    // Secret-fetch exit: the one-shot plaintext disclosure.
    let secret = get_entry_secret(&state, summary.id).unwrap();
    assert_eq!(secret.custom_fields.len(), 3);
    assert_eq!(secret.custom_fields[0].label, "API Key");
    assert_eq!(secret.custom_fields[0].value.as_str(), "key-value-1");
    assert!(secret.custom_fields[0].secret);
    assert_eq!(secret.custom_fields[1].value.as_str(), "plain-value");
    assert!(!secret.custom_fields[1].secret);
    assert_eq!(secret.custom_fields[2].value.as_str(), "");
}

/// The update tri-state: `None` leaves stored fields untouched (a
/// metadata-only edit never resubmits values), `Some(list)` replaces
/// wholesale.
#[test]
fn update_entry_custom_fields_tri_state() {
    let (state, _dir) = unlocked_state();
    let created = create_entry(
        &state,
        CreateEntryRequest {
            title: "Tri-state".to_string(),
            url: None,
            username: "user".to_string(),
            password: Zeroizing::new("pw".to_string()),
            notes: None,
            tags: vec![],
            group_id: None,
            url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
            custom_fields: vec![input("Keep", "original-value", false)],
        },
    )
    .unwrap();

    // None = leave unchanged.
    update_entry(
        &state,
        created.id.clone(),
        UpdateEntryRequest {
            title: "Retitled".to_string(),
            url: None,
            username: "user".to_string(),
            password: None,
            notes: None,
            update_notes: false,
            tags: vec![],
            group_id: None,
            totp_secret: None,
            url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
            custom_fields: None,
        },
    )
    .unwrap();
    let secret = get_entry_secret(&state, created.id.clone()).unwrap();
    assert_eq!(secret.custom_fields.len(), 1);
    assert_eq!(secret.custom_fields[0].label, "Keep");
    assert_eq!(secret.custom_fields[0].value.as_str(), "original-value");

    // Some(list) = replace wholesale.
    update_entry(
        &state,
        created.id.clone(),
        UpdateEntryRequest {
            title: "Tri-state".to_string(),
            url: None,
            username: "user".to_string(),
            password: None,
            notes: None,
            update_notes: false,
            tags: vec![],
            group_id: None,
            totp_secret: None,
            url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
            custom_fields: Some(vec![
                input("Replaced", "new-value", true),
                input("Extra", "", false),
            ]),
        },
    )
    .unwrap();
    let secret = get_entry_secret(&state, created.id).unwrap();
    assert_eq!(secret.custom_fields.len(), 2);
    assert_eq!(secret.custom_fields[0].label, "Replaced");
    assert_eq!(secret.custom_fields[0].value.as_str(), "new-value");
    assert!(secret.custom_fields[0].secret);
    assert_eq!(secret.custom_fields[1].label, "Extra");
    assert_eq!(secret.custom_fields[1].value.as_str(), "");
}
