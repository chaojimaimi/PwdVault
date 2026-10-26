//! generate_password passthrough tests, split from `tests.rs` when it
//! crossed the 800-line cap (v1.5.0). The shared helpers live in
//! `tests.rs` and are reached through `pub(super)`.

use super::dispatcher::execute_command;
use super::tests::{init_test_vault, make_request, setup_test_state};
use super::*;
use pwdvault_domain::constants;

// ---- generate_password ----
// ---- generate_password ----

/// v1.4.0 wire contract: a payload written before the `mode` field existed
/// (old extension / pinned request) must keep landing on the password path
/// with the historical parameter defaults — `#[serde(default)]` on
/// `GeneratorOptions.mode`.
#[test]
fn generate_password_options_without_mode_deserialize_as_password() {
    let options: GeneratorOptions = serde_json::from_str("{}").expect("empty object is valid");
    assert_eq!(options.mode, GeneratorMode::Password);
    assert_eq!(options.length, 16);
    assert!(options.include_uppercase && options.include_lowercase);
    assert!(options.include_numbers && options.include_symbols);
    assert_eq!(options.words, 6);
    assert!(options.separator.is_none());
    assert!(!options.capitalize && !options.append_number);

    // An explicit legacy-shaped payload (exactly the five v1.3.x fields).
    let legacy: GeneratorOptions = serde_json::from_str(
        r#"{"length": 20, "include_uppercase": true, "include_lowercase": false,
            "include_numbers": true, "include_symbols": true}"#,
    )
    .expect("legacy payload is valid");
    assert_eq!(legacy.mode, GeneratorMode::Password);
    assert_eq!(legacy.length, 20);
    assert!(!legacy.include_lowercase);

    // An unknown mode fails the request deserialization (fail closed) —
    // it must NOT silently degrade to the password generator.
    assert!(serde_json::from_str::<GeneratorOptions>(r#"{"mode": "haiku"}"#).is_err());
}

/// v1.4.0 dispatcher: mode selects the backend over the same command.
#[test]
fn generate_password_dispatches_passphrase_and_pin_modes() {
    let (state, _temp) = setup_test_state();
    init_test_vault(&state, "master123");

    let mut req = make_request("generate_password", 1);
    req.options = Some(
        serde_json::from_str(
            r#"{"mode": "passphrase", "words": 5, "separator": ".", "capitalize": true,
            "append_number": true}"#,
        )
        .unwrap(),
    );
    let value = execute_command(req, state.clone(), None, None).unwrap();
    let passphrase = value.as_str().unwrap();
    // 4 dots = 5 words; the trailing 0-99 number glues onto the last word.
    assert_eq!(passphrase.matches('.').count(), 4, "{passphrase}");
    let without_number = passphrase.trim_end_matches(|c: char| c.is_ascii_digit());
    let words: Vec<&str> = without_number.split('.').collect();
    assert_eq!(words.len(), 5);
    assert!(
        words.iter().all(|w| {
            w.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                // '-' allows the EFF list's single hyphenated word ("yo-yo").
                && w.chars().skip(1).all(|c| c.is_ascii_lowercase() || c == '-')
        }),
        "{passphrase}"
    );

    let mut pin_req = make_request("generate_password", 2);
    pin_req.options = Some(serde_json::from_str(r#"{"mode": "pin", "length": 6}"#).unwrap());
    let pin = execute_command(pin_req, state, None, None).unwrap();
    let pin = pin.as_str().unwrap();
    assert_eq!(pin.len(), 6);
    assert!(pin.chars().all(|c| c.is_ascii_digit()));
}

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
        url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
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
            ..GeneratorOptions::default()
        }),
        name: None,
        group_id: None,
        settings: None,
        export_password: None,
        import_password: None,
        backup: None,
        custom_fields: None,
        password_sha256: None,
    };
    let result = execute_command(req, state, None, None).unwrap();
    let password = result.as_str().unwrap();
    assert_eq!(password.len(), 32);
}

#[test]
fn test_generate_password_guarantees_all_types() {
    let (state, _temp) = setup_test_state();
    let req = NativeRequest {
        url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
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
            ..GeneratorOptions::default()
        }),
        name: None,
        group_id: None,
        settings: None,
        export_password: None,
        import_password: None,
        backup: None,
        custom_fields: None,
        password_sha256: None,
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
            url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
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
                ..GeneratorOptions::default()
            }),
            name: None,
            group_id: None,
            settings: None,
            export_password: None,
            import_password: None,
            backup: None,
            custom_fields: None,
            password_sha256: None,
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
