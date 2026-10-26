//! v1.6.0 WP1: Native Messaging coverage for custom-field create/update —
//! split out of `tests.rs` (800-line cap playbook, v1.5.0 precedent).

use zeroize::Zeroizing;

use pwdvault_domain::constants;

use super::dispatcher::execute_command;
use super::protocol::NativeRequest;
use super::tests::{init_test_vault, setup_test_state};

/// v1.6.0 WP1: the NM create/update path carries custom-field inputs
/// (plaintext values, sealed by the service layer). A payload WITHOUT the
/// field (the pre-v1.6.0 extension wire shape) must leave stored custom
/// fields untouched on update — the serde default IS the tri-state None.
#[test]
fn test_create_update_entry_with_custom_fields() {
    let (state, _temp) = setup_test_state();
    init_test_vault(&state, "master123");

    let field = |label: &str, value: &str, secret: bool| serde_json::json!({ "label": label, "value": value, "secret": secret });
    let create_req = NativeRequest {
        url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
        id: 1,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "create_entry".to_string(),
        password: Some(Zeroizing::new("nm_pass".to_string())),
        url: None,
        id_param: None,
        code: None,
        session_nonce: None,
        title: Some("NM Fields".to_string()),
        username: Some("nm_user".to_string()),
        notes: None,
        tags: None,
        request: None,
        options: None,
        name: None,
        group_id: None,
        settings: None,
        export_password: None,
        import_password: None,
        backup: None,
        custom_fields: Some(
            serde_json::from_value(serde_json::Value::Array(vec![
                field("API Key", "nm-value", true),
                field("Placeholder", "", false),
            ]))
            .unwrap(),
        ),
        password_sha256: None,
    };
    let created = execute_command(create_req, state.clone(), None, None).unwrap();
    let entry_id = created["id"].as_str().unwrap().to_string();

    // Summary meta: labels + secret only, never a value key.
    assert_eq!(created["custom_fields"].as_array().unwrap().len(), 2);
    assert_eq!(created["custom_fields"][0]["label"], "API Key");
    assert_eq!(created["custom_fields"][0]["secret"], true);
    for field in created["custom_fields"].as_array().unwrap() {
        assert!(field.get("value").is_none(), "meta leaked a value: {field}");
    }

    // Update with an ABSENT custom_fields field (pre-v1.6.0 payload shape):
    // stored fields survive untouched.
    let retitle_req = NativeRequest {
        url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
        id: 2,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "update_entry".to_string(),
        password: None,
        url: None,
        id_param: Some(entry_id.clone()),
        code: None,
        session_nonce: None,
        title: Some("NM Fields Renamed".to_string()),
        username: Some("nm_user".to_string()),
        notes: None,
        tags: None,
        request: None,
        options: None,
        name: None,
        group_id: None,
        settings: None,
        export_password: None,
        import_password: None,
        backup: None,
        custom_fields: None,
        password_sha256: None,
    };
    let retitled = execute_command(retitle_req, state.clone(), None, None).unwrap();
    assert_eq!(retitled["custom_fields"].as_array().unwrap().len(), 2);
    assert_eq!(retitled["custom_fields"][0]["label"], "API Key");

    // Update with an explicit list: replaced wholesale.
    let replace_req = NativeRequest {
        url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
        id: 3,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "update_entry".to_string(),
        password: None,
        url: None,
        id_param: Some(entry_id.clone()),
        code: None,
        session_nonce: None,
        title: Some("NM Fields Renamed".to_string()),
        username: Some("nm_user".to_string()),
        notes: None,
        tags: None,
        request: None,
        options: None,
        name: None,
        group_id: None,
        settings: None,
        export_password: None,
        import_password: None,
        backup: None,
        custom_fields: Some(
            serde_json::from_value(serde_json::Value::Array(vec![field(
                "Replaced",
                "new-value",
                true,
            )]))
            .unwrap(),
        ),
        password_sha256: None,
    };
    let replaced = execute_command(replace_req, state, None, None).unwrap();
    let fields = replaced["custom_fields"].as_array().unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["label"], "Replaced");
    assert_eq!(fields[0]["secret"], true);
}
