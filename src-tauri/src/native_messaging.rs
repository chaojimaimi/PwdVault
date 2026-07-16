//! Native Messaging Server
//!
//! Provides an HTTP server for browser extension communication.

use std::io::Read;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::Emitter;
use tiny_http::{Request, Response, Server};
use zeroize::Zeroizing;

use crate::auth;
use crate::constants;
use crate::database;
use crate::service;
use crate::{AppState, CreateEntryRequest, VaultBackup, VaultError};

/// Native messaging request
///
/// Sensitive fields (`password`, `code`, `export_password`, `import_password`)
/// are wrapped in `Zeroizing<String>` so they are wiped from memory when the
/// request is dropped — including on error paths that never reach the service
/// layer (e.g. a missing `title` causing early return before `password` is
/// consumed).
#[derive(Debug, Deserialize)]
pub struct NativeRequest {
    pub id: u32,
    pub command: String,
    #[serde(default)]
    pub password: Option<Zeroizing<String>>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub id_param: Option<String>,
    #[serde(default)]
    pub code: Option<Zeroizing<String>>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub request: Option<database::PasswordEntry>,
    #[serde(default)]
    pub options: Option<GeneratorOptions>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    #[serde(default)]
    pub export_password: Option<Zeroizing<String>>,
    #[serde(default)]
    pub import_password: Option<Zeroizing<String>>,
    #[serde(default)]
    pub backup: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct GeneratorOptions {
    #[serde(default = "default_length")]
    pub length: usize,
    #[serde(default = "default_true")]
    pub include_uppercase: bool,
    #[serde(default = "default_true")]
    pub include_lowercase: bool,
    #[serde(default = "default_true")]
    pub include_numbers: bool,
    #[serde(default = "default_true")]
    pub include_symbols: bool,
}

fn default_length() -> usize {
    16
}
fn default_true() -> bool {
    true
}

/// Native messaging response
#[derive(Debug, Serialize)]
pub struct NativeResponse {
    pub id: u32,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Start the native messaging HTTP server
///
/// Each incoming request is handled on its own thread so that a slow
/// command (e.g. Argon2 key derivation during unlock) cannot stall
/// connection acceptance or pairing flow for other concurrent clients.
/// Vault-mutating commands are serialized via `AppState::op_lock` inside
/// `execute_command`, so multi-threading here only parallelizes
/// connection/parsing/auth — mutation correctness is preserved.
pub fn start_server(
    port: u16,
    state: Arc<AppState>,
    app_handle: Option<tauri::AppHandle>,
) -> Result<(), String> {
    let addr = format!("127.0.0.1:{}", port);

    let server = Server::http(&addr).map_err(|_| "Server error".to_string())?;

    tracing::info!(port = port, "native messaging server started");

    for request in server.incoming_requests() {
        let state = state.clone();
        let app_handle = app_handle.clone();
        std::thread::spawn(move || handle_request(request, state, app_handle));
    }

    Ok(())
}

/// Build CORS headers based on the request Origin.
/// Only allows localhost and browser extension origins.
fn get_cors_origin(origin: Option<&str>) -> Option<String> {
    match origin {
        Some(o) if o.starts_with("chrome-extension://") => Some(o.to_string()),
        Some(o) if o.starts_with("moz-extension://") => Some(o.to_string()),
        Some(o) if o.starts_with("http://localhost") => Some(o.to_string()),
        Some(o) if o.starts_with("http://127.0.0.1") => Some(o.to_string()),
        _ => None,
    }
}

fn add_cors_headers<T: std::io::Read>(response: &mut Response<T>, origin: Option<&str>) {
    if let Some(allowed) = get_cors_origin(origin) {
        response.add_header(
            tiny_http::Header::from_bytes(
                "Access-Control-Allow-Origin".as_bytes(),
                allowed.as_bytes(),
            )
            .expect("valid CORS header"),
        );
    }
    response.add_header(
        tiny_http::Header::from_bytes(
            "Access-Control-Allow-Methods".as_bytes(),
            "POST, OPTIONS".as_bytes(),
        )
        .expect("valid CORS header"),
    );
    response.add_header(
        tiny_http::Header::from_bytes(
            "Access-Control-Allow-Headers".as_bytes(),
            "Content-Type, Authorization".as_bytes(),
        )
        .expect("valid CORS header"),
    );
}

fn handle_request(
    mut request: Request,
    state: Arc<AppState>,
    app_handle: Option<tauri::AppHandle>,
) {
    let origin: Option<String> = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Origin"))
        .map(|h| h.value.to_string());

    // Handle CORS preflight
    if request.method() == &tiny_http::Method::Options {
        let mut response = Response::empty(204);
        add_cors_headers(&mut response, origin.as_deref());
        let _ = request.respond(response);
        return;
    }

    // Read request body with size limit
    let content_length: usize = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Content-Length"))
        .and_then(|h| h.value.as_str().parse().ok())
        .unwrap_or(0);

    if content_length > constants::MAX_BODY_SIZE {
        let response = create_error_response(0, "Request too large".to_string(), origin.as_deref());
        let _ = request.respond(response);
        return;
    }

    let mut body = String::new();
    // Limit the reader to the declared Content-Length so read_to_string
    // returns promptly instead of blocking for MAX_BODY_SIZE bytes.
    let mut reader = request
        .as_reader()
        .take(content_length.min(constants::MAX_BODY_SIZE) as u64);
    if let Err(_) = reader.read_to_string(&mut body) {
        let response = create_error_response(0, "Request failed".to_string(), origin.as_deref());
        let _ = request.respond(response);
        return;
    }

    // Parse request
    let native_req: NativeRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => {
            let response =
                create_error_response(0, "Invalid request".to_string(), origin.as_deref());
            let _ = request.respond(response);
            return;
        }
    };

    let id = native_req.id;
    let command = native_req.command.clone();

    // Origin check (defense in depth): every request must come from a browser
    // extension origin. CORS alone is browser-enforced and trivially bypassed
    // by non-browser clients; requiring an extension origin server-side
    // prevents any non-extension context (even one that stole a token) from
    // invoking the API.
    if !auth::is_extension_origin(origin.as_deref()) {
        let response = create_error_response(id, "Forbidden".to_string(), origin.as_deref());
        let _ = request.respond(response);
        return;
    }

    // Authentication: /api/pair and /api/pair_confirm are unauthenticated
    // (extension pairing flow — no token exists yet). All other endpoints
    // require Bearer token.
    if command != "pair" && command != "pair_confirm" {
        let auth_header = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .map(|h| h.value.as_str())
            .unwrap_or("");

        if !auth::validate_token(auth_header) {
            let response = create_error_response(id, "Unauthorized".to_string(), origin.as_deref());
            let _ = request.respond(response);
            return;
        }
    }

    // Execute command
    let result = execute_command(native_req, state, app_handle, origin.clone());

    // Send response
    let response = match result {
        Ok(data) => NativeResponse {
            id,
            success: true,
            data: Some(data),
            error: None,
        },
        Err(e) => NativeResponse {
            id,
            success: false,
            data: None,
            error: Some(e),
        },
    };

    let _ = request.respond(create_json_response(&response, origin.as_deref()));
}

fn create_json_response(
    response: &NativeResponse,
    origin: Option<&str>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(response).unwrap_or_default();
    let mut response = Response::from_data(body).with_header(
        tiny_http::Header::from_bytes("Content-Type".as_bytes(), "application/json".as_bytes())
            .expect("valid Content-Type header"),
    );
    add_cors_headers(&mut response, origin);
    response
}

fn create_error_response(
    id: u32,
    error: String,
    origin: Option<&str>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let response = NativeResponse {
        id,
        success: false,
        data: None,
        error: Some(error),
    };
    create_json_response(&response, origin)
}

/// Convert a `VaultError` into a sanitized user-facing error message for HTTP
/// responses. Internal details (paths, serialization errors, etc.) are stripped.
fn vault_error_to_message(err: VaultError) -> String {
    err.public_message()
}

fn execute_command(
    req: NativeRequest,
    state: Arc<AppState>,
    app_handle: Option<tauri::AppHandle>,
    origin: Option<String>,
) -> Result<serde_json::Value, String> {
    // Serialization lock: every command that touches the vault database
    // (everything except `pair` / `pair_confirm`, which only manipulate
    // in-memory pairing state) runs under `op_lock` so that concurrent
    // requests from the multi-threaded HTTP server cannot interleave a
    // read-modify-write cycle with another command and produce a lost
    // update or a stale integrity digest.
    let _op_guard = if req.command == "pair" || req.command == "pair_confirm" {
        None
    } else {
        Some(state.op_lock.lock().expect("op lock poisoned"))
    };

    match req.command.as_str() {
        // Extension pairing — returns API token (no auth required, origin checked in handle_request)
        // Rate limited to prevent token enumeration attacks
        "pair" => {
            // Check rate limit for pair endpoint (max 10 requests per minute)
            {
                let now = std::time::Instant::now();
                // Determine whether to reset the counter. We read
                // pair_last_reset in its own short-lived scope so its guard is
                // dropped before we write it back — re-locking a Mutex while
                // still holding it would deadlock.
                let needs_reset = {
                    let last_reset = state
                        .pair_last_reset
                        .lock()
                        .expect("pair reset lock poisoned");
                    match last_reset.as_ref() {
                        Some(t) => now.duration_since(*t).as_secs() > 60,
                        None => true,
                    }
                };
                if needs_reset {
                    *state
                        .pair_last_reset
                        .lock()
                        .expect("pair reset lock poisoned") = Some(now);
                }

                let mut pair_count = state
                    .pair_request_count
                    .lock()
                    .expect("pair count lock poisoned");
                if needs_reset {
                    *pair_count = 0;
                }

                // Rate limit: max MAX_PAIR_REQUESTS_PER_MIN pair requests per minute
                if *pair_count >= constants::MAX_PAIR_REQUESTS_PER_MIN {
                    return Err("Too many pair requests. Please try again later.".to_string());
                }

                *pair_count += 1;
            }

            let code = crate::pairing::create_session(origin.clone());
            // Notify desktop UI to display the pairing code.
            if let Some(handle) = app_handle {
                let _ = handle.emit("pair-request", &code);
            }
            Ok(serde_json::json!({ "pending": true }))
        }

        "pair_confirm" => {
            let user_code = req.code.ok_or("Code required")?;
            if crate::pairing::verify(user_code.as_str()) {
                let token = auth::get_token();
                Ok(serde_json::json!({ "token": token }))
            } else {
                Err("Invalid or expired code".to_string())
            }
        }

        "is_vault_initialized" => {
            Ok(serde_json::to_value(service::is_initialized(&state)).expect("bool serializable"))
        }

        "is_vault_unlocked" => {
            Ok(serde_json::to_value(service::is_unlocked(&state)).expect("bool serializable"))
        }

        "setup_vault" => service::setup_vault(&state)
            .map(|ok| serde_json::to_value(ok).expect("bool serializable"))
            .map_err(vault_error_to_message),

        "init_vault" => {
            let password = req.password.ok_or("Password required".to_string())?;
            service::init_vault(&state, password)
                .map(|()| serde_json::json!(true))
                .map_err(vault_error_to_message)
        }

        "unlock_vault" => {
            let password = req.password.ok_or("Password required".to_string())?;
            service::unlock_vault(&state, password)
                .map(|ok| serde_json::to_value(ok).expect("bool serializable"))
                .map_err(vault_error_to_message)
        }

        "lock_vault" => {
            service::lock_vault(&state);
            Ok(serde_json::json!(null))
        }

        "get_settings" => service::get_settings(&state)
            .map(|settings| serde_json::to_value(settings).expect("settings serializable"))
            .map_err(vault_error_to_message),

        "update_settings" => {
            let settings_json = req.settings.ok_or("Settings required".to_string())?;
            let settings: database::Settings = serde_json::from_value(settings_json)
                .map_err(|_| "Invalid settings".to_string())?;
            service::update_settings(&state, settings)
                .map(|s| serde_json::to_value(s).expect("settings serializable"))
                .map_err(vault_error_to_message)
        }

        "create_entry" => {
            let request = CreateEntryRequest {
                title: req.title.ok_or("Title required".to_string())?,
                username: req.username.ok_or("Username required".to_string())?,
                password: req.password.ok_or("Password required".to_string())?,
                url: req.url,
                notes: req.notes,
                tags: req.tags.unwrap_or_default(),
                group_id: req.group_id,
            };
            service::create_entry(&state, request)
                .map(|summary| serde_json::to_value(summary).expect("entry serializable"))
                .map_err(vault_error_to_message)
        }

        "list_all_entries" => service::list_all_entries(&state)
            .map(|entries| serde_json::to_value(entries).expect("entries serializable"))
            .map_err(vault_error_to_message),

        "get_entry_meta" => {
            let id = req.id_param.ok_or("Entry ID required".to_string())?;
            service::get_entry_meta(&state, id)
                .map(|entry| serde_json::to_value(entry).expect("entry serializable"))
                .map_err(vault_error_to_message)
        }

        "get_entry_secret" => {
            let id = req.id_param.ok_or("Entry ID required".to_string())?;
            service::get_entry_secret(&state, id)
                .map(|secret| serde_json::to_value(secret).expect("secret serializable"))
                .map_err(vault_error_to_message)
        }

        "generate_password" => {
            let options = req.options.unwrap_or(GeneratorOptions {
                length: 16,
                include_uppercase: true,
                include_lowercase: true,
                include_numbers: true,
                include_symbols: true,
            });
            service::generate_password(
                options.length,
                options.include_uppercase,
                options.include_lowercase,
                options.include_numbers,
                options.include_symbols,
            )
            .map(|password| serde_json::to_value(password).expect("password serializable"))
            .map_err(vault_error_to_message)
        }

        "update_entry" => {
            let id = req.id_param.ok_or("Entry ID required".to_string())?;
            let request = CreateEntryRequest {
                title: req.title.ok_or("Title required".to_string())?,
                username: req.username.ok_or("Username required".to_string())?,
                password: req.password.ok_or("Password required".to_string())?,
                url: req.url,
                notes: req.notes,
                tags: req.tags.unwrap_or_default(),
                group_id: req.group_id,
            };
            service::update_entry(&state, id, request)
                .map(|summary| serde_json::to_value(summary).expect("entry serializable"))
                .map_err(vault_error_to_message)
        }

        "remove_entry" => {
            let id = req.id_param.ok_or("Entry ID required".to_string())?;
            service::remove_entry(&state, id)
                .map(|ok| serde_json::to_value(ok).expect("bool serializable"))
                .map_err(vault_error_to_message)
        }

        "get_entry_count" => service::get_entry_count(&state)
            .map(|count| serde_json::to_value(count).expect("count serializable"))
            .map_err(vault_error_to_message),

        "create_group" => {
            let name = req.name.ok_or("Group name required".to_string())?;
            service::create_group(&state, name)
                .map(|group| serde_json::to_value(group).expect("group serializable"))
                .map_err(vault_error_to_message)
        }

        "list_all_groups" => service::list_all_groups(&state)
            .map(|groups| serde_json::to_value(groups).expect("groups serializable"))
            .map_err(vault_error_to_message),

        "update_group" => {
            let id = req.id_param.ok_or("Group ID required".to_string())?;
            let name = req.name.ok_or("Group name required".to_string())?;
            service::update_group(&state, id, name)
                .map(|group| serde_json::to_value(group).expect("group serializable"))
                .map_err(vault_error_to_message)
        }

        "remove_group" => {
            let id = req.id_param.ok_or("Group ID required".to_string())?;
            service::remove_group(&state, id)
                .map(|ok| serde_json::to_value(ok).expect("bool serializable"))
                .map_err(vault_error_to_message)
        }

        "export_vault" => {
            let export_password = req
                .export_password
                .ok_or("Export password required".to_string())?;
            service::export_vault(&state, export_password)
                .map(|backup| serde_json::to_value(backup).expect("backup serializable"))
                .map_err(vault_error_to_message)
        }

        "import_vault" => {
            let backup_json = req.backup.ok_or("Backup data required".to_string())?;
            let backup: VaultBackup =
                serde_json::from_value(backup_json).map_err(|_| "Invalid backup".to_string())?;
            let import_password = req
                .import_password
                .ok_or("Import password required".to_string())?;
            service::import_vault(&state, backup, import_password)
                .map(|result| serde_json::to_value(result).expect("result serializable"))
                .map_err(vault_error_to_message)
        }

        _ => Err("Unknown command".to_string()),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use tempfile::TempDir;

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
        state.keystore.clear_key();
        state.mac_key.lock().expect("mac key lock").take();

        let salt = crypto::kdf::generate_salt();
        let (master_key, params) = crypto::kdf::derive_key(password, &salt).expect("derive key");
        let verification = crypto::create_verification_header(&master_key, salt.clone(), params)
            .expect("create verification");
        let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);

        let db = state
            .database
            .lock()
            .expect("db lock")
            .clone()
            .expect("db exists");
        database::save_verification_data(&db, &verification).expect("save verification");

        *state.verification_data.lock().expect("v lock") = Some(verification);
        state.keystore.set_key(enc_key).expect("set key");
        *state.mac_key.lock().expect("mac key lock") = Some(mac_key);
        state.touch_activity();
    }

    fn make_request(command: &str, id: u32) -> NativeRequest {
        NativeRequest {
            id,
            command: command.to_string(),
            password: None,
            url: None,
            id_param: None,
            code: None,
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

    // ---- is_vault_initialized ----

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

        assert!(state.keystore.is_unlocked());

        let req = make_request("lock_vault", 1);
        let result = execute_command(req, state.clone(), None, None).unwrap();
        assert_eq!(result, serde_json::json!(null));

        assert!(!state.keystore.is_unlocked());
    }

    // ---- pair / pair_confirm ----

    #[test]
    fn test_pair_returns_pending() {
        let (state, _temp) = setup_test_state();
        let req = make_request("pair", 1);
        let result = execute_command(req, state, None, None).unwrap();
        assert_eq!(result["pending"], true);
    }

    #[test]
    fn test_pair_confirm_success() {
        let (state, _temp) = setup_test_state();
        let code = crate::pairing::create_session(None);
        let confirm_req = NativeRequest {
            id: 1,
            command: "pair_confirm".to_string(),
            code: Some(Zeroizing::new(code)),
            ..make_request("pair_confirm", 1)
        };
        let result = execute_command(confirm_req, state, None, None).unwrap();
        assert!(result["token"].as_str().unwrap().len() >= 32);
    }

    #[test]
    fn test_pair_confirm_wrong_code_fails() {
        let (state, _temp) = setup_test_state();
        let _ = crate::pairing::create_session(None);
        let req = NativeRequest {
            id: 1,
            command: "pair_confirm".to_string(),
            code: Some(Zeroizing::new("000000".to_string())),
            ..make_request("pair_confirm", 1)
        };
        let result = execute_command(req, state, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_pair_confirm_without_session_fails() {
        let (state, _temp) = setup_test_state();
        let req = NativeRequest {
            id: 1,
            command: "pair_confirm".to_string(),
            code: Some(Zeroizing::new("123456".to_string())),
            ..make_request("pair_confirm", 1)
        };
        let result = execute_command(req, state, None, None);
        assert!(result.is_err());
    }

    // ---- create_entry ----

    #[test]
    fn test_create_entry() {
        let (state, _temp) = setup_test_state();
        init_test_vault(&state, "master123");

        let req = NativeRequest {
            id: 1,
            command: "create_entry".to_string(),
            password: Some(Zeroizing::new("secret123".to_string())),
            url: Some("https://github.com".to_string()),
            id_param: None,
            code: None,
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
            command: "create_entry".to_string(),
            password: Some(Zeroizing::new("secret".to_string())),
            url: None,
            id_param: None,
            code: None,
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
            command: "create_entry".to_string(),
            password: Some(Zeroizing::new("my_password".to_string())),
            url: None,
            id_param: None,
            code: None,
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
        assert!(!secret["last_used_at"].is_null());
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
                command: "create_entry".to_string(),
                password: Some(Zeroizing::new(format!("pass{}", i))),
                url: None,
                id_param: None,
                code: None,
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
            command: "create_entry".to_string(),
            password: Some(Zeroizing::new("old_pass".to_string())),
            url: Some("https://old.com".to_string()),
            id_param: None,
            code: None,
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
            command: "update_entry".to_string(),
            password: Some(Zeroizing::new("new_pass".to_string())),
            url: Some("https://new.com".to_string()),
            id_param: Some(entry_id),
            code: None,
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
        let key = state.keystore.get_key().unwrap();
        let entry = database::load_entry(&db, &key, &result["id"].as_str().unwrap())
            .unwrap()
            .unwrap();
        let enc: crypto::EncryptedData = bincode::deserialize(&entry.encrypted_password).unwrap();
        let decrypted = crypto::decrypt(&key, &enc).unwrap();
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
            command: "create_entry".to_string(),
            password: Some(Zeroizing::new("pass".to_string())),
            url: None,
            id_param: None,
            code: None,
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
            command: "remove_entry".to_string(),
            password: None,
            url: None,
            id_param: Some(entry_id),
            code: None,
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
            command: "create_entry".to_string(),
            password: Some(Zeroizing::new("pass".to_string())),
            url: None,
            id_param: None,
            code: None,
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
            command: "generate_password".to_string(),
            password: None,
            url: None,
            id_param: None,
            code: None,
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
            command: "generate_password".to_string(),
            password: None,
            url: None,
            id_param: None,
            code: None,
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
                command: "generate_password".to_string(),
                password: None,
                url: None,
                id_param: None,
                code: None,
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
}
