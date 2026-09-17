use std::sync::Arc;

use super::*;
use pwdvault_application::AppState;
use pwdvault_domain::constants;
use pwdvault_infrastructure::crypto;
use pwdvault_infrastructure::database;
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::dispatcher::execute_command;

/// Helper: create a test AppState with a temp database
fn setup_test_state() -> (Arc<AppState>, TempDir) {
    let temp = TempDir::new().expect("create temp dir");
    let db_path = temp.path().join("test_vault.db");
    let db = Arc::new(database::init_database(&db_path).expect("init db"));

    let state = Arc::new(AppState::default());
    *state.database.lock().expect("db lock") = Some(db);
    (state, temp)
}

/// Helper: initialize vault with a password in the given state
fn init_test_vault(state: &Arc<AppState>, password: &str) {
    // Clear any existing session state
    state.lock_vault();

    let salt = crypto::kdf::generate_salt();
    let (master_key, params) = crypto::kdf::derive_key(password, &salt).expect("derive key");
    let verification =
        crypto::create_verification_header(&master_key, salt, params).expect("create verification");
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);

    let db = state
        .database
        .lock()
        .expect("db lock")
        .clone()
        .expect("db exists");
    database::save_verification_data(&db, &verification).expect("save verification");

    *state.verification_data.lock().expect("v lock") = Some(verification);
    state.session.unlock(enc_key, mac_key);
    state.touch_activity();
}

fn make_request(command: &str, id: u32) -> NativeRequest {
    NativeRequest {
        id,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: command.to_string(),
        password: None,
        url: None,
        id_param: None,
        code: None,
        session_nonce: None,
        title: None,
        username: None,
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
    }
}

// ---- start_server ----

/// B3: when another listener already holds the port, `start_server` must
/// fail with an error (which the app then surfaces in the UI) instead of
/// silently running without the extension bridge.
///
/// X2: the holder below is an ACTIVE listener, which `SO_REUSEADDR` does
/// not override on Unix — so the bounded bind retry runs its full
/// 1s + 2s + 4s schedule before failing. Expect this test to take ~7s.
#[test]
fn start_server_fails_when_port_is_already_bound() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();

    let (state, _temp) = setup_test_state();
    let result = start_server(port, state, None);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("Server error"),
        "bind failure must surface as a server error"
    );
}

// ---- is_vault_initialized ----

#[test]
fn test_handshake_reports_protocol_and_capabilities() {
    let (state, _temp) = setup_test_state();
    let req = make_request("handshake", 1);
    let result = execute_command(req, state, None, None).unwrap();
    assert_eq!(
        result["protocol_version"],
        constants::NATIVE_PROTOCOL_VERSION
    );
    assert!(result["capabilities"].as_array().unwrap().len() >= 3);
}

#[test]
fn test_is_vault_initialized_false() {
    let (state, _temp) = setup_test_state();
    let req = make_request("is_vault_initialized", 1);
    let result = execute_command(req, state, None, None).unwrap();
    assert_eq!(result, serde_json::json!(false));
}

#[test]
fn test_is_vault_initialized_true() {
    let (state, _temp) = setup_test_state();
    init_test_vault(&state, "master123");

    let req = make_request("is_vault_initialized", 1);
    let result = execute_command(req, state, None, None).unwrap();
    assert_eq!(result, serde_json::json!(true));
}

// ---- is_vault_unlocked ----

#[test]
fn test_is_vault_unlocked() {
    let (state, _temp) = setup_test_state();
    let req = make_request("is_vault_unlocked", 1);
    // Not unlocked initially
    let result = execute_command(req, state, None, None).unwrap();
    assert_eq!(result, serde_json::json!(false));
}

// ---- lock_vault ----

#[test]
fn test_lock_vault() {
    let (state, _temp) = setup_test_state();
    init_test_vault(&state, "master123");

    assert!(state.session.is_unlocked());

    let req = make_request("lock_vault", 1);
    let result = execute_command(req, state.clone(), None, None).unwrap();
    assert_eq!(result, serde_json::json!(null));

    assert!(!state.session.is_unlocked());
}

// ---- pair / pair_confirm ----

#[test]
fn test_pair_returns_pending() {
    let (state, _temp) = setup_test_state();
    let req = make_request("pair", 1);
    let result = execute_command(
        req,
        state,
        None,
        Some("chrome-extension://pair-test".to_string()),
    )
    .unwrap();
    assert_eq!(result["pending"], true);
    assert_eq!(result["session_nonce"].as_str().unwrap().len(), 32);
}

#[test]
fn test_pair_confirm_success() {
    let (state, _temp) = setup_test_state();
    let caller = "chrome-extension://confirm-success";
    let challenge = pwdvault_infrastructure::pairing::create_session(caller);
    let confirm_req = NativeRequest {
        id: 1,
        command: "pair_confirm".to_string(),
        code: Some(Zeroizing::new(challenge.code)),
        session_nonce: Some(Zeroizing::new(challenge.nonce)),
        ..make_request("pair_confirm", 1)
    };
    let result = execute_command(confirm_req, state, None, Some(caller.to_string())).unwrap();
    assert!(result["token"].as_str().unwrap().len() >= 32);
}

#[test]
fn test_pair_confirm_wrong_code_fails() {
    let (state, _temp) = setup_test_state();
    let caller = "chrome-extension://confirm-wrong-code";
    let challenge = pwdvault_infrastructure::pairing::create_session(caller);
    let req = NativeRequest {
        id: 1,
        command: "pair_confirm".to_string(),
        code: Some(Zeroizing::new("000000".to_string())),
        session_nonce: Some(Zeroizing::new(challenge.nonce)),
        ..make_request("pair_confirm", 1)
    };
    let result = execute_command(req, state, None, Some(caller.to_string()));
    assert!(result.is_err());
}

#[test]
fn test_pair_confirm_without_session_fails() {
    let (state, _temp) = setup_test_state();
    let req = NativeRequest {
        id: 1,
        command: "pair_confirm".to_string(),
        code: Some(Zeroizing::new("123456".to_string())),
        session_nonce: Some(Zeroizing::new("missing-session".to_string())),
        ..make_request("pair_confirm", 1)
    };
    let result = execute_command(
        req,
        state,
        None,
        Some("chrome-extension://no-session".to_string()),
    );
    assert!(result.is_err());
}

// ---- create_entry ----

#[test]
fn test_create_entry() {
    let (state, _temp) = setup_test_state();
    init_test_vault(&state, "master123");

    let req = NativeRequest {
        id: 1,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "create_entry".to_string(),
        password: Some(Zeroizing::new("secret123".to_string())),
        url: Some("https://github.com".to_string()),
        id_param: None,
        code: None,
        session_nonce: None,
        title: Some("GitHub".to_string()),
        username: Some("user@example.com".to_string()),
        notes: Some("My GitHub account".to_string()),
        tags: Some(vec!["dev".to_string()]),
        request: None,
        options: None,
        name: None,
        group_id: None,
        settings: None,
        export_password: None,
        import_password: None,
        backup: None,
    };

    let result = execute_command(req, state.clone(), None, None).unwrap();
    assert_eq!(result["title"], "GitHub");
    assert_eq!(result["username"], "user@example.com");
    assert_eq!(result["url"], "https://github.com");
    assert_eq!(result["tags"], serde_json::json!(["dev"]));
    assert!(result["id"].is_string());
}

#[test]
fn test_create_entry_locked() {
    let (state, _temp) = setup_test_state();
    // Don't init vault — stays locked

    let req = NativeRequest {
        id: 1,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "create_entry".to_string(),
        password: Some(Zeroizing::new("secret".to_string())),
        url: None,
        id_param: None,
        code: None,
        session_nonce: None,
        title: Some("Test".to_string()),
        username: Some("user".to_string()),
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
    };

    let result = execute_command(req, state, None, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("locked"));
}

// ---- get_entry_meta / get_entry_secret ----

#[test]
fn test_get_entry_meta_and_secret() {
    let (state, _temp) = setup_test_state();
    init_test_vault(&state, "master123");

    // Create an entry first
    let create_req = NativeRequest {
        id: 1,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "create_entry".to_string(),
        password: Some(Zeroizing::new("my_password".to_string())),
        url: None,
        id_param: None,
        code: None,
        session_nonce: None,
        title: Some("Site".to_string()),
        username: Some("user".to_string()),
        notes: Some("some notes".to_string()),
        tags: None,
        request: None,
        options: None,
        name: None,
        group_id: None,
        settings: None,
        export_password: None,
        import_password: None,
        backup: None,
    };
    let created = execute_command(create_req, state.clone(), None, None).unwrap();
    let entry_id = created["id"].as_str().unwrap().to_string();

    // Meta endpoint returns public fields without secrets
    let meta_req = NativeRequest {
        id: 2,
        command: "get_entry_meta".to_string(),
        id_param: Some(entry_id.clone()),
        ..make_request("get_entry_meta", 2)
    };
    let meta = execute_command(meta_req, state.clone(), None, None).unwrap();
    assert_eq!(meta["title"], "Site");
    assert_eq!(meta["username"], "user");
    assert!(meta["password"].is_null());
    assert!(meta["notes"].is_null());

    // Secret endpoint returns decrypted password/notes and updates last_used_at
    let secret_req = NativeRequest {
        id: 3,
        command: "get_entry_secret".to_string(),
        id_param: Some(entry_id),
        ..make_request("get_entry_secret", 3)
    };
    let secret = execute_command(secret_req, state, None, None).unwrap();
    assert_eq!(secret["password"], "my_password");
    assert_eq!(secret["notes"], "some notes");
    // §5.1.2: last_used_at is no longer persisted on secret access.
    // It returns the value from the stored entry (None for new entries).
    assert!(secret["last_used_at"].is_null());
}

// ---- list_all_entries ----

#[test]
fn test_list_all_entries() {
    let (state, _temp) = setup_test_state();
    init_test_vault(&state, "master123");

    // Create 3 entries
    for i in 0..3 {
        let req = NativeRequest {
            id: i,
            protocol_version: constants::NATIVE_PROTOCOL_VERSION,
            command: "create_entry".to_string(),
            password: Some(Zeroizing::new(format!("pass{}", i))),
            url: None,
            id_param: None,
            code: None,
            session_nonce: None,
            title: Some(format!("Site {}", i)),
            username: Some(format!("user{}@test.com", i)),
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
        };
        execute_command(req, state.clone(), None, None).unwrap();
    }

    let list_req = make_request("list_all_entries", 10);
    let result = execute_command(list_req, state, None, None).unwrap();
    let entries = result.as_array().unwrap();
    assert_eq!(entries.len(), 3);
}

// ---- update_entry ----

#[test]
fn test_update_entry() {
    let (state, _temp) = setup_test_state();
    init_test_vault(&state, "master123");

    // Create an entry
    let create_req = NativeRequest {
        id: 1,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "create_entry".to_string(),
        password: Some(Zeroizing::new("old_pass".to_string())),
        url: Some("https://old.com".to_string()),
        id_param: None,
        code: None,
        session_nonce: None,
        title: Some("Old Title".to_string()),
        username: Some("old_user".to_string()),
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
    };
    let created = execute_command(create_req, state.clone(), None, None).unwrap();
    let entry_id = created["id"].as_str().unwrap().to_string();

    // Update the entry
    let update_req = NativeRequest {
        id: 2,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "update_entry".to_string(),
        password: Some(Zeroizing::new("new_pass".to_string())),
        url: Some("https://new.com".to_string()),
        id_param: Some(entry_id),
        code: None,
        session_nonce: None,
        title: Some("New Title".to_string()),
        username: Some("new_user".to_string()),
        notes: Some("updated notes".to_string()),
        tags: Some(vec!["updated".to_string()]),
        request: None,
        options: None,
        name: None,
        group_id: None,
        settings: None,
        export_password: None,
        import_password: None,
        backup: None,
    };
    let result = execute_command(update_req, state.clone(), None, None).unwrap();
    assert_eq!(result["title"], "New Title");
    assert_eq!(result["username"], "new_user");
    assert_eq!(result["tags"], serde_json::json!(["updated"]));

    // Verify password was re-encrypted
    let db = state.database.lock().expect("db lock").clone().expect("db");
    let lease = state.lease().unwrap();
    let key = lease.enc_key().unwrap();
    let entry = database::load_entry(&db, key, result["id"].as_str().unwrap(), false)
        .unwrap()
        .unwrap();
    let enc: crypto::EncryptedData = bincode::deserialize(&entry.encrypted_password).unwrap();
    let decrypted = crypto::decrypt(key, &enc).unwrap();
    assert_eq!(String::from_utf8(decrypted).unwrap(), "new_pass");
}

// ---- remove_entry ----

#[test]
fn test_remove_entry() {
    let (state, _temp) = setup_test_state();
    init_test_vault(&state, "master123");

    // Create an entry
    let create_req = NativeRequest {
        id: 1,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "create_entry".to_string(),
        password: Some(Zeroizing::new("pass".to_string())),
        url: None,
        id_param: None,
        code: None,
        session_nonce: None,
        title: Some("To Delete".to_string()),
        username: Some("user".to_string()),
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
    };
    let created = execute_command(create_req, state.clone(), None, None).unwrap();
    let entry_id = created["id"].as_str().unwrap().to_string();

    // Remove it
    let remove_req = NativeRequest {
        id: 2,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "remove_entry".to_string(),
        password: None,
        url: None,
        id_param: Some(entry_id),
        code: None,
        session_nonce: None,
        title: None,
        username: None,
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
    };
    let result = execute_command(remove_req, state.clone(), None, None).unwrap();
    assert_eq!(result, serde_json::json!(true));

    // Verify count is 0
    let count_req = make_request("get_entry_count", 3);
    let count = execute_command(count_req, state, None, None).unwrap();
    assert_eq!(count, serde_json::json!(0));
}

// ---- get_entry_count ----

#[test]
fn test_get_entry_count() {
    let (state, _temp) = setup_test_state();
    init_test_vault(&state, "master123");

    let req = make_request("get_entry_count", 1);
    let result = execute_command(req, state.clone(), None, None).unwrap();
    assert_eq!(result, serde_json::json!(0));

    // Create an entry
    let create_req = NativeRequest {
        id: 2,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "create_entry".to_string(),
        password: Some(Zeroizing::new("pass".to_string())),
        url: None,
        id_param: None,
        code: None,
        session_nonce: None,
        title: Some("Test".to_string()),
        username: Some("u".to_string()),
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
    };
    execute_command(create_req, state.clone(), None, None).unwrap();

    let count_req = make_request("get_entry_count", 3);
    let count = execute_command(count_req, state, None, None).unwrap();
    assert_eq!(count, serde_json::json!(1));
}

// ---- generate_password ----

#[test]
fn test_generate_password_default() {
    let (state, _temp) = setup_test_state();
    let req = make_request("generate_password", 1);
    let result = execute_command(req, state, None, None).unwrap();
    let password = result.as_str().unwrap();
    assert_eq!(password.len(), 16);
}

#[test]
fn test_generate_password_custom_length() {
    let (state, _temp) = setup_test_state();
    let req = NativeRequest {
        id: 1,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "generate_password".to_string(),
        password: None,
        url: None,
        id_param: None,
        code: None,
        session_nonce: None,
        title: None,
        username: None,
        notes: None,
        tags: None,
        request: None,
        options: Some(GeneratorOptions {
            length: 32,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: false,
        }),
        name: None,
        group_id: None,
        settings: None,
        export_password: None,
        import_password: None,
        backup: None,
    };
    let result = execute_command(req, state, None, None).unwrap();
    let password = result.as_str().unwrap();
    assert_eq!(password.len(), 32);
}

#[test]
fn test_generate_password_guarantees_all_types() {
    let (state, _temp) = setup_test_state();
    let req = NativeRequest {
        id: 1,
        protocol_version: constants::NATIVE_PROTOCOL_VERSION,
        command: "generate_password".to_string(),
        password: None,
        url: None,
        id_param: None,
        code: None,
        session_nonce: None,
        title: None,
        username: None,
        notes: None,
        tags: None,
        request: None,
        options: Some(GeneratorOptions {
            length: 16,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
        }),
        name: None,
        group_id: None,
        settings: None,
        export_password: None,
        import_password: None,
        backup: None,
    };
    let result = execute_command(req, state, None, None).unwrap();
    let password = result.as_str().unwrap();

    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

    assert!(has_upper, "Password missing uppercase letters");
    assert!(has_lower, "Password missing lowercase letters");
    assert!(has_digit, "Password missing digits");
    assert!(has_symbol, "Password missing symbols");
}

#[test]
fn test_generate_password_short_guarantees_all_types() {
    let (state, _temp) = setup_test_state();
    // Even very short passwords should contain all requested types
    for _ in 0..50 {
        let req = NativeRequest {
            id: 1,
            protocol_version: constants::NATIVE_PROTOCOL_VERSION,
            command: "generate_password".to_string(),
            password: None,
            url: None,
            id_param: None,
            code: None,
            session_nonce: None,
            title: None,
            username: None,
            notes: None,
            tags: None,
            request: None,
            options: Some(GeneratorOptions {
                length: 4,
                include_uppercase: true,
                include_lowercase: true,
                include_numbers: true,
                include_symbols: true,
            }),
            name: None,
            group_id: None,
            settings: None,
            export_password: None,
            import_password: None,
            backup: None,
        };
        let result = execute_command(req, state.clone(), None, None).unwrap();
        let password = result.as_str().unwrap();
        assert_eq!(password.len(), 4);

        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

        assert!(
            has_upper && has_lower && has_digit && has_symbol,
            "Short password missing required character type: {}",
            password
        );
    }
}

// ---- unknown command ----

#[test]
fn test_unknown_command() {
    let (state, _temp) = setup_test_state();
    let req = make_request("nonexistent", 1);
    let result = execute_command(req, state, None, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unknown command"));
}

// ---- operations when locked ----

#[test]
fn test_get_entry_meta_locked() {
    let (state, _temp) = setup_test_state();
    let req = NativeRequest {
        id: 1,
        command: "get_entry_meta".to_string(),
        id_param: Some("some-id".to_string()),
        ..make_request("get_entry_meta", 1)
    };
    let result = execute_command(req, state, None, None);
    assert!(result.is_err());
}

#[test]
fn test_list_entries_locked() {
    let (state, _temp) = setup_test_state();
    let req = make_request("list_all_entries", 1);
    let result = execute_command(req, state, None, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("locked"));
}

#[test]
fn test_update_entry_locked() {
    let (state, _temp) = setup_test_state();
    let req = NativeRequest {
        id: 1,
        command: "update_entry".to_string(),
        id_param: Some("id".to_string()),
        title: Some("t".to_string()),
        username: Some("u".to_string()),
        password: Some(Zeroizing::new("p".to_string())),
        ..make_request("update_entry", 1)
    };
    let result = execute_command(req, state, None, None);
    assert!(result.is_err());
}

#[test]
fn test_remove_entry_locked() {
    let (state, _temp) = setup_test_state();
    let req = NativeRequest {
        id: 1,
        command: "remove_entry".to_string(),
        id_param: Some("id".to_string()),
        ..make_request("remove_entry", 1)
    };
    let result = execute_command(req, state, None, None);
    assert!(result.is_err());
}

#[test]
fn test_entry_count_locked() {
    let (state, _temp) = setup_test_state();
    let req = make_request("get_entry_count", 1);
    let result = execute_command(req, state, None, None);
    assert!(result.is_err());
}
