//! Native Messaging Server
//!
//! Provides an HTTP server for browser extension communication.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tiny_http::{Request, Response, Server};

use crate::AppState;
use crate::crypto;
use crate::database;
use crate::paths;

/// Native messaging request
#[derive(Debug, Deserialize)]
pub struct NativeRequest {
    pub id: u32,
    pub command: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub id_param: Option<String>,
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
    pub export_password: Option<String>,
    #[serde(default)]
    pub import_password: Option<String>,
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

fn default_length() -> usize { 16 }
fn default_true() -> bool { true }

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
pub fn start_server(port: u16, state: Arc<AppState>) -> Result<(), String> {
    let addr = format!("127.0.0.1:{}", port);

    let server = Server::http(&addr)
        .map_err(|e| format!("Failed to bind server: {}", e))?;

    println!("Native messaging server listening on {}", addr);

    for request in server.incoming_requests() {
        handle_request(request, state.clone());
    }

    Ok(())
}

fn add_cors_headers(response: &mut Response<std::io::Cursor<Vec<u8>>>) {
    response.add_header(
        tiny_http::Header::from_bytes("Access-Control-Allow-Origin".as_bytes(), "*".as_bytes()).expect("valid CORS header")
    );
    response.add_header(
        tiny_http::Header::from_bytes("Access-Control-Allow-Methods".as_bytes(), "POST, OPTIONS".as_bytes()).expect("valid CORS header")
    );
    response.add_header(
        tiny_http::Header::from_bytes("Access-Control-Allow-Headers".as_bytes(), "Content-Type".as_bytes()).expect("valid CORS header")
    );
}

fn handle_request(mut request: Request, state: Arc<AppState>) {
    // Handle CORS preflight
    if request.method() == &tiny_http::Method::Options {
        let response = Response::empty(204)
            .with_header(
                tiny_http::Header::from_bytes("Access-Control-Allow-Origin".as_bytes(), "*".as_bytes()).expect("valid CORS header")
            )
            .with_header(
                tiny_http::Header::from_bytes("Access-Control-Allow-Methods".as_bytes(), "POST, OPTIONS".as_bytes()).expect("valid CORS header")
            )
            .with_header(
                tiny_http::Header::from_bytes("Access-Control-Allow-Headers".as_bytes(), "Content-Type".as_bytes()).expect("valid CORS header")
            );
        let _ = request.respond(response);
        return;
    }

    // Read request body
    let mut body = String::new();
    if let Err(e) = request.as_reader().read_to_string(&mut body) {
        let response = create_error_response(0, format!("Failed to read request: {}", e));
        let _ = request.respond(response);
        return;
    }

    // Parse request
    let native_req: NativeRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            let response = create_error_response(0, format!("Invalid JSON: {}", e));
            let _ = request.respond(response);
            return;
        }
    };

    let id = native_req.id;

    // Execute command
    let result = execute_command(native_req, state);

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

    let _ = request.respond(create_json_response(&response));
}

fn create_json_response(response: &NativeResponse) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(response).unwrap_or_default();
    let mut response = Response::from_data(body)
        .with_header(
            tiny_http::Header::from_bytes("Content-Type".as_bytes(), "application/json".as_bytes()).expect("valid Content-Type header")
        );
    add_cors_headers(&mut response);
    response
}

fn create_error_response(id: u32, error: String) -> Response<std::io::Cursor<Vec<u8>>> {
    let response = NativeResponse {
        id,
        success: false,
        data: None,
        error: Some(error),
    };
    create_json_response(&response)
}

fn execute_command(req: NativeRequest, state: Arc<AppState>) -> Result<serde_json::Value, String> {
    match req.command.as_str() {
        "is_vault_initialized" => {
            let initialized = state.verification_data.lock().expect("verification lock poisoned").is_some();
            Ok(serde_json::json!(initialized))
        }

        "is_vault_unlocked" => {
            Ok(serde_json::json!(crypto::is_unlocked()))
        }

        "setup_vault" => {
            // Check if database is already loaded in state
            {
                let db_guard = state.database.lock().expect("db lock poisoned");
                if db_guard.is_some() && state.verification_data.lock().expect("verification lock poisoned").is_some() {
                    return Ok(serde_json::json!(true));
                }
            }

            let db_path = paths::get_db_path();

            if !db_path.exists() {
                return Ok(serde_json::json!(false));
            }

            // Initialize database
            let db = std::sync::Arc::new(database::init_database(&db_path).map_err(|e| e.to_string())?);

            // Load verification data from database
            let verification_data = database::load_verification_data(&db).map_err(|e| e.to_string())?;

            if let Some(data) = verification_data {
                *state.verification_data.lock().expect("verification lock poisoned") = Some(data);
                *state.database.lock().expect("db lock poisoned") = Some(db);
                return Ok(serde_json::json!(true));
            }

            Ok(serde_json::json!(false))
        }

        "init_vault" => {
            let password = req.password.ok_or("Password required")?;

            // Check if already initialized
            if state.verification_data.lock().expect("verification lock poisoned").is_some() {
                return Err("Vault already initialized".to_string());
            }

            // Generate salt and derive key
            let salt = crypto::kdf::generate_salt();
            let (key, params) = crypto::kdf::derive_key(&password, &salt)
                .map_err(|e| e.to_string())?;

            // Create verification data
            let verification_data = crypto::create_verification_header(&key, salt, params)
                .map_err(|e| e.to_string())?;

            // Initialize database
            let db_path = paths::ensure_db_dir().map_err(|e| e.to_string())?;
            let db = database::init_database(&db_path)
                .map_err(|e| e.to_string())?;

            // Save verification data
            database::save_verification_data(&db, &verification_data)
                .map_err(|e| e.to_string())?;

            // Update state
            *state.verification_data.lock().expect("verification lock poisoned") = Some(verification_data);
            *state.database.lock().expect("db lock poisoned") = Some(std::sync::Arc::new(db));

            // Set key in memory
            crypto::set_key(key).map_err(|e| e.to_string())?;

            Ok(serde_json::json!(true))
        }

        "unlock_vault" => {
            let password = req.password.ok_or("Password required")?;
            let verification_data = state.verification_data.lock().expect("verification lock poisoned");
            let data = verification_data.as_ref().ok_or("Vault not initialized")?;
            let success = crypto::unlock_with_password(&password, data)
                .map_err(|e| e.to_string())?;
            if success {
                state.touch_activity();
                state.update_lock_menu("Lock Vault");
            }
            Ok(serde_json::json!(success))
        }

        "lock_vault" => {
            state.lock_vault();
            Ok(serde_json::json!(null))
        }

        "get_settings" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }
            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;
            let settings = database::load_settings(db).map_err(|e| e.to_string())?;
            state.touch_activity();
            Ok(serde_json::to_value(settings).expect("settings serializable"))
        }

        "update_settings" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }
            let settings_json = req.settings.ok_or("Settings required")?;
            let settings: database::Settings = serde_json::from_value(settings_json)
                .map_err(|e| format!("Invalid settings: {}", e))?;
            if settings.auto_lock_secs < 30 || settings.auto_lock_secs > 3600 {
                return Err("Auto-lock timeout must be between 30 and 3600 seconds".to_string());
            }
            if settings.default_length < 4 || settings.default_length > 128 {
                return Err("Password length must be between 4 and 128".to_string());
            }
            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;
            database::save_settings(db, &settings).map_err(|e| e.to_string())?;
            *state.auto_lock_secs.lock().expect("timeout lock poisoned") = settings.auto_lock_secs;
            state.touch_activity();
            Ok(serde_json::to_value(settings).expect("settings serializable"))
        }

        "create_entry" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let title = req.title.ok_or("Title required")?;
            let username = req.username.ok_or("Username required")?;
            let password = req.password.ok_or("Password required")?;

            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let key = crypto::get_key().map_err(|e| e.to_string())?;

            // Encrypt password
            let encrypted_password = crypto::encrypt(&key, password.as_bytes())
                .map_err(|e| e.to_string())?;
            let encrypted_password_bytes = bincode::serialize(&encrypted_password)
                .map_err(|e| e.to_string())?;

            // Encrypt notes if present
            let encrypted_notes = if let Some(notes) = &req.notes {
                let encrypted = crypto::encrypt(&key, notes.as_bytes())
                    .map_err(|e| e.to_string())?;
                Some(bincode::serialize(&encrypted).map_err(|e| e.to_string())?)
            } else {
                None
            };

            let mut entry = database::PasswordEntry::new(title, req.url.clone(), username);
            entry.encrypted_password = encrypted_password_bytes;
            entry.encrypted_notes = encrypted_notes;
            entry.tags = req.tags.unwrap_or_default();
            entry.group_id = req.group_id;

            database::save_entry(db, &entry).map_err(|e| e.to_string())?;

            state.touch_activity();

            Ok(serde_json::json!({
                "id": entry.id,
                "title": entry.title,
                "url": entry.url,
                "username": entry.username,
                "tags": entry.tags,
                "group_id": entry.group_id,
                "created_at": entry.created_at,
                "updated_at": entry.updated_at,
            }))
        }

        "list_all_entries" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let ids = database::list_entries(db).map_err(|e| e.to_string())?;
            let mut entries = Vec::new();

            for id in ids {
                if let Some(entry) = database::load_entry(db, &id).map_err(|e| e.to_string())? {
                    entries.push(serde_json::to_value(entry).expect("entry serializable"));
                }
            }

            state.touch_activity();

            Ok(serde_json::json!(entries))
        }

        "get_entry" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let id = req.id_param.ok_or("Entry ID required")?;
            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let entry = database::load_entry(db, &id)
                .map_err(|e| e.to_string())?
                .ok_or("Entry not found")?;

            // Decrypt password
            let key = crypto::get_key().map_err(|e| e.to_string())?;
            let encrypted: crypto::EncryptedData = bincode::deserialize(&entry.encrypted_password)
                .map_err(|e| e.to_string())?;
            let password_bytes = crypto::decrypt(&key, &encrypted).map_err(|e| e.to_string())?;
            let password = String::from_utf8(password_bytes).map_err(|e| e.to_string())?;

            // Decrypt notes
            let notes = if let Some(ref encrypted_notes) = entry.encrypted_notes {
                let encrypted: crypto::EncryptedData = bincode::deserialize(encrypted_notes)
                    .map_err(|e| e.to_string())?;
                let notes_bytes = crypto::decrypt(&key, &encrypted).map_err(|e| e.to_string())?;
                Some(String::from_utf8(notes_bytes).map_err(|e| e.to_string())?)
            } else {
                None
            };

            state.touch_activity();

            Ok(serde_json::json!({
                "id": entry.id,
                "title": entry.title,
                "url": entry.url,
                "username": entry.username,
                "password": password,
                "notes": notes,
                "tags": entry.tags,
                "group_id": entry.group_id,
                "created_at": entry.created_at,
                "updated_at": entry.updated_at,
            }))
        }

        "generate_password" => {
            let options = req.options.unwrap_or(GeneratorOptions {
                length: 16,
                include_uppercase: true,
                include_lowercase: true,
                include_numbers: true,
                include_symbols: true,
            });

            use rand::{rngs::OsRng, Rng};

            let mut charset = String::new();
            let mut required_chars = Vec::new();

            // Collect all available character classes and their representatives
            if options.include_uppercase {
                charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                required_chars.push('A');
            }
            if options.include_lowercase {
                charset.push_str("abcdefghijklmnopqrstuvwxyz");
                required_chars.push('a');
            }
            if options.include_numbers {
                charset.push_str("0123456789");
                required_chars.push('0');
            }
            if options.include_symbols {
                charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
                required_chars.push('!');
            }

            if charset.is_empty() {
                charset = "abcdefghijklmnopqrstuvwxyz".to_string();
                required_chars = vec!['a'];
            }

            let mut rng = OsRng; // Use OS entropy source for better security
            let bytes: Vec<u8> = charset.bytes().collect();

            let num_required = required_chars.len();
            let mut password_chars: Vec<char> = required_chars;

            // Fill remaining positions with random characters from full charset
            for _ in 0..(options.length.saturating_sub(num_required)) {
                let idx = rng.gen_range(0..bytes.len());
                password_chars.push(bytes[idx] as char);
            }

            // Fisher-Yates shuffle to avoid predictable patterns (e.g., always starting with uppercase)
            let len = password_chars.len();
            for i in 0..len {
                let j = rng.gen_range(i..len);
                password_chars.swap(i, j);
            }

            let password: String = password_chars.into_iter().collect();

            Ok(serde_json::json!(password))
        }

        "update_entry" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let id = req.id_param.ok_or("Entry ID required")?;
            let title = req.title.ok_or("Title required")?;
            let username = req.username.ok_or("Username required")?;
            let password = req.password.ok_or("Password required")?;

            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;
            let key = crypto::get_key().map_err(|e| e.to_string())?;

            let mut entry = database::load_entry(db, &id)
                .map_err(|e| e.to_string())?
                .ok_or("Entry not found")?;

            entry.title = title;
            entry.url = req.url;
            entry.username = username;
            entry.tags = req.tags.unwrap_or_default();
            entry.updated_at = chrono::Utc::now().timestamp();

            let encrypted_password = crypto::encrypt(&key, password.as_bytes())
                .map_err(|e| e.to_string())?;
            entry.encrypted_password = bincode::serialize(&encrypted_password)
                .map_err(|e| e.to_string())?;

            entry.encrypted_notes = if let Some(notes) = &req.notes {
                let encrypted = crypto::encrypt(&key, notes.as_bytes())
                    .map_err(|e| e.to_string())?;
                Some(bincode::serialize(&encrypted).map_err(|e| e.to_string())?)
            } else {
                None
            };

            database::save_entry(db, &entry).map_err(|e| e.to_string())?;

            state.touch_activity();

            Ok(serde_json::json!({
                "id": entry.id,
                "title": entry.title,
                "url": entry.url,
                "username": entry.username,
                "tags": entry.tags,
                "created_at": entry.created_at,
                "updated_at": entry.updated_at,
            }))
        }

        "remove_entry" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let id = req.id_param.ok_or("Entry ID required")?;
            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let existed = database::delete_entry(db, &id).map_err(|e| e.to_string())?;

            state.touch_activity();

            Ok(serde_json::json!(existed))
        }

        "get_entry_count" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let count = database::count_entries(db).map_err(|e| e.to_string())?;

            state.touch_activity();

            Ok(serde_json::json!(count))
        }

        "create_group" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let name = req.name.ok_or("Group name required")?;
            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let group = database::Group::new(name);
            database::save_group(db, &group).map_err(|e| e.to_string())?;

            state.touch_activity();

            Ok(serde_json::json!({
                "id": group.id,
                "name": group.name,
                "created_at": group.created_at,
                "updated_at": group.updated_at,
            }))
        }

        "list_all_groups" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let ids = database::list_groups(db).map_err(|e| e.to_string())?;
            let mut groups = Vec::new();
            for id in ids {
                if let Some(g) = database::load_group(db, &id).map_err(|e| e.to_string())? {
                    groups.push(serde_json::json!({
                        "id": g.id,
                        "name": g.name,
                        "created_at": g.created_at,
                        "updated_at": g.updated_at,
                    }));
                }
            }

            state.touch_activity();

            Ok(serde_json::json!(groups))
        }

        "update_group" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let id = req.id_param.ok_or("Group ID required")?;
            let name = req.name.ok_or("Group name required")?;
            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let mut group = database::load_group(db, &id)
                .map_err(|e| e.to_string())?
                .ok_or("Group not found")?;
            group.name = name;
            group.updated_at = chrono::Utc::now().timestamp();
            database::save_group(db, &group).map_err(|e| e.to_string())?;

            state.touch_activity();

            Ok(serde_json::json!({
                "id": group.id,
                "name": group.name,
                "created_at": group.created_at,
                "updated_at": group.updated_at,
            }))
        }

        "remove_group" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let id = req.id_param.ok_or("Group ID required")?;
            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let existed = database::delete_group(db, &id).map_err(|e| e.to_string())?;

            state.touch_activity();

            Ok(serde_json::json!(existed))
        }

        "export_vault" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }
            let export_password = req.export_password.ok_or("Export password required")?;
            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;
            let key = crypto::get_key().map_err(|e| e.to_string())?;

            // Load all entries and decrypt
            let entry_ids = database::list_entries(db).map_err(|e| e.to_string())?;
            let mut export_entries = Vec::new();
            for id in entry_ids {
                if let Some(entry) = database::load_entry(db, &id).map_err(|e| e.to_string())? {
                    let enc_pwd: crypto::EncryptedData = bincode::deserialize(&entry.encrypted_password)
                        .map_err(|e| e.to_string())?;
                    let pwd_bytes = crypto::decrypt(&key, &enc_pwd).map_err(|e| e.to_string())?;
                    let password = String::from_utf8(pwd_bytes).map_err(|e| e.to_string())?;

                    let notes = if let Some(ref enc_notes_bytes) = entry.encrypted_notes {
                        let enc: crypto::EncryptedData = bincode::deserialize(enc_notes_bytes)
                            .map_err(|e| e.to_string())?;
                        let notes_bytes = crypto::decrypt(&key, &enc).map_err(|e| e.to_string())?;
                        Some(String::from_utf8(notes_bytes).map_err(|e| e.to_string())?)
                    } else {
                        None
                    };

                    export_entries.push(serde_json::json!({
                        "id": entry.id,
                        "title": entry.title,
                        "url": entry.url,
                        "username": entry.username,
                        "password": password,
                        "notes": notes,
                        "tags": entry.tags,
                        "group_id": entry.group_id,
                        "created_at": entry.created_at,
                        "updated_at": entry.updated_at,
                    }));
                }
            }

            // Load groups
            let group_ids = database::list_groups(db).map_err(|e| e.to_string())?;
            let mut groups = Vec::new();
            for id in group_ids {
                if let Some(g) = database::load_group(db, &id).map_err(|e| e.to_string())? {
                    groups.push(serde_json::json!({
                        "id": g.id,
                        "name": g.name,
                        "created_at": g.created_at,
                        "updated_at": g.updated_at,
                    }));
                }
            }

            // Load settings
            let settings = database::load_settings(db).map_err(|e| e.to_string())?;

            let payload = serde_json::json!({
                "entries": export_entries,
                "groups": groups,
                "settings": settings,
            });
            let payload_bytes = serde_json::to_vec(&payload)
                .map_err(|e| e.to_string())?;

            // Derive export key
            let salt = crypto::kdf::generate_salt();
            let (export_key, params) = crypto::kdf::derive_key(&export_password, &salt)
                .map_err(|e| e.to_string())?;

            let encrypted = crypto::encrypt(&export_key, &payload_bytes)
                .map_err(|e| e.to_string())?;

            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD;

            state.touch_activity();
            Ok(serde_json::json!({
                "version": 1,
                "created_at": chrono::Utc::now().timestamp(),
                "salt": b64.encode(&salt),
                "kdf_memory": params.m_cost,
                "kdf_iterations": params.t_cost,
                "kdf_parallelism": params.p_cost,
                "nonce": b64.encode(&encrypted.nonce),
                "data": b64.encode(&encrypted.ciphertext),
            }))
        }

        "import_vault" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }
            let backup_json = req.backup.ok_or("Backup data required")?;
            let import_password = req.import_password.ok_or("Import password required")?;

            let version = backup_json.get("version")
                .and_then(|v| v.as_u64())
                .ok_or("Missing version in backup")?;
            if version != 1 {
                return Err("Unsupported backup version".to_string());
            }

            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD;

            let salt_str = backup_json.get("salt").and_then(|v| v.as_str()).ok_or("Missing salt")?;
            let nonce_str = backup_json.get("nonce").and_then(|v| v.as_str()).ok_or("Missing nonce")?;
            let data_str = backup_json.get("data").and_then(|v| v.as_str()).ok_or("Missing data")?;
            let kdf_memory = backup_json.get("kdf_memory").and_then(|v| v.as_u64()).ok_or("Missing kdf_memory")? as u32;
            let kdf_iterations = backup_json.get("kdf_iterations").and_then(|v| v.as_u64()).ok_or("Missing kdf_iterations")? as u32;
            let kdf_parallelism = backup_json.get("kdf_parallelism").and_then(|v| v.as_u64()).unwrap_or(4) as u32;

            let salt = b64.decode(salt_str).map_err(|e| format!("Invalid salt: {}", e))?;
            let nonce_bytes = b64.decode(nonce_str).map_err(|e| format!("Invalid nonce: {}", e))?;
            let ciphertext = b64.decode(data_str).map_err(|e| format!("Invalid data: {}", e))?;

            if salt.len() != 16 {
                return Err("Invalid salt length".to_string());
            }

            let salt_array: [u8; 16] = salt.try_into().map_err(|_| "Invalid salt")?;
            let (import_key, _) = crypto::kdf::derive_key_with_params(
                &import_password,
                &salt_array,
                &crypto::kdf::AdaptiveParams {
                    m_cost: kdf_memory,
                    t_cost: kdf_iterations,
                    p_cost: kdf_parallelism,
                },
            ).map_err(|e| e.to_string())?;

            let encrypted_data = crypto::EncryptedData {
                nonce: nonce_bytes,
                ciphertext,
            };
            let payload_bytes = crypto::decrypt(&import_key, &encrypted_data)
                .map_err(|_| "Invalid password or corrupted backup".to_string())?;

            let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
                .map_err(|e| format!("Invalid payload: {}", e))?;

            let db_guard = state.database.lock().expect("db lock poisoned");
            let db = db_guard.as_ref().ok_or("Database not initialized")?;
            let key = crypto::get_key().map_err(|e| e.to_string())?;

            // Clear existing data
            let existing_ids = database::list_entries(db).map_err(|e| e.to_string())?;
            for id in existing_ids {
                database::delete_entry(db, &id).map_err(|e| e.to_string())?;
            }
            let existing_groups = database::list_groups(db).map_err(|e| e.to_string())?;
            for id in existing_groups {
                database::delete_group(db, &id).map_err(|e| e.to_string())?;
            }

            // Import groups
            let groups = payload.get("groups").and_then(|v| v.as_array()).ok_or("Missing groups")?;
            let mut group_id_map = std::collections::HashMap::new();
            for g in groups {
                let old_id = g.get("id").and_then(|v| v.as_str()).ok_or("Missing group id")?;
                let name = g.get("name").and_then(|v| v.as_str()).ok_or("Missing group name")?;
                let new_group = database::Group::new(name.to_string());
                group_id_map.insert(old_id.to_string(), new_group.id.clone());
                database::save_group(db, &new_group).map_err(|e| e.to_string())?;
            }

            // Import entries
            let entries = payload.get("entries").and_then(|v| v.as_array()).ok_or("Missing entries")?;
            for e in entries {
                let title = e.get("title").and_then(|v| v.as_str()).ok_or("Missing title")?;
                let username = e.get("username").and_then(|v| v.as_str()).ok_or("Missing username")?;
                let password = e.get("password").and_then(|v| v.as_str()).ok_or("Missing password")?;
                let url = e.get("url").and_then(|v| v.as_str()).map(|s| s.to_string());
                let notes = e.get("notes").and_then(|v| v.as_str()).map(|s| s.to_string());
                let tags = e.get("tags").and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|t| t.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let group_id = e.get("group_id").and_then(|v| v.as_str())
                    .and_then(|gid| group_id_map.get(gid).cloned());

                let mut entry = database::PasswordEntry::new(title.to_string(), url, username.to_string());
                let enc_pwd = crypto::encrypt(&key, password.as_bytes()).map_err(|e| e.to_string())?;
                entry.encrypted_password = bincode::serialize(&enc_pwd).map_err(|e| e.to_string())?;
                entry.encrypted_notes = if let Some(ref n) = notes {
                    let enc = crypto::encrypt(&key, n.as_bytes()).map_err(|e| e.to_string())?;
                    Some(bincode::serialize(&enc).map_err(|e| e.to_string())?)
                } else {
                    None
                };
                entry.tags = tags;
                entry.group_id = group_id;
                entry.created_at = e.get("created_at").and_then(|v| v.as_i64()).unwrap_or(entry.created_at);
                entry.updated_at = e.get("updated_at").and_then(|v| v.as_i64()).unwrap_or(entry.updated_at);

                database::save_entry(db, &entry).map_err(|e| e.to_string())?;
            }

            state.touch_activity();
            Ok(serde_json::json!({
                "entries_imported": entries.len(),
                "groups_imported": groups.len(),
            }))
        }

        _ => Err(format!("Unknown command: {}", req.command))
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
        crypto::clear_key();

        let temp = TempDir::new().expect("create temp dir");
        let db_path = temp.path().join("test_vault.db");
        let db = Arc::new(database::init_database(&db_path).expect("init db"));

        let state = Arc::new(AppState::default());
        *state.database.lock().expect("db lock") = Some(db);
        (state, temp)
    }

    /// Helper: initialize vault with a password in the given state
    fn init_test_vault(state: &Arc<AppState>, password: &str) {
        // Clear any leftover key from parallel tests sharing global keystore
        crypto::clear_key();

        let salt = crypto::kdf::generate_salt();
        let (key, params) = crypto::kdf::derive_key(password, &salt).expect("derive key");
        let verification = crypto::create_verification_header(&key, salt.clone(), params).expect("create verification");

        let db = state.database.lock().expect("db lock").clone().expect("db exists");
        database::save_verification_data(&db, &verification).expect("save verification");

        *state.verification_data.lock().expect("v lock") = Some(verification);
        crypto::set_key(key).expect("set key");
        state.touch_activity();
    }

    fn make_request(command: &str, id: u32) -> NativeRequest {
        NativeRequest {
            id,
            command: command.to_string(),
            password: None,
            url: None,
            id_param: None,
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
        let result = execute_command(req, state).unwrap();
        assert_eq!(result, serde_json::json!(false));
    }

    #[test]
    fn test_is_vault_initialized_true() {
        let (state, _temp) = setup_test_state();
        init_test_vault(&state, "master123");

        let req = make_request("is_vault_initialized", 1);
        let result = execute_command(req, state).unwrap();
        assert_eq!(result, serde_json::json!(true));
    }

    // ---- is_vault_unlocked ----

    #[test]
    fn test_is_vault_unlocked() {
        let (state, _temp) = setup_test_state();
        let req = make_request("is_vault_unlocked", 1);
        // Not unlocked initially
        let result = execute_command(req, state).unwrap();
        assert_eq!(result, serde_json::json!(false));
    }

    // ---- lock_vault ----

    #[test]
    fn test_lock_vault() {
        let (state, _temp) = setup_test_state();
        init_test_vault(&state, "master123");

        assert!(crypto::is_unlocked());

        let req = make_request("lock_vault", 1);
        let result = execute_command(req, state).unwrap();
        assert_eq!(result, serde_json::json!(null));

        assert!(!crypto::is_unlocked());
    }

    // ---- create_entry ----

    #[test]
    fn test_create_entry() {
        let (state, _temp) = setup_test_state();
        init_test_vault(&state, "master123");

        let req = NativeRequest {
            id: 1,
            command: "create_entry".to_string(),
            password: Some("secret123".to_string()),
            url: Some("https://github.com".to_string()),
            id_param: None,
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

        let result = execute_command(req, state.clone()).unwrap();
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
            password: Some("secret".to_string()),
            url: None,
            id_param: None,
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

        let result = execute_command(req, state);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("locked"));
    }

    // ---- get_entry ----

    #[test]
    fn test_get_entry() {
        let (state, _temp) = setup_test_state();
        init_test_vault(&state, "master123");

        // Create an entry first
        let create_req = NativeRequest {
            id: 1,
            command: "create_entry".to_string(),
            password: Some("my_password".to_string()),
            url: None,
            id_param: None,
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
        let created = execute_command(create_req, state.clone()).unwrap();
        let entry_id = created["id"].as_str().unwrap().to_string();

        // Get the entry
        let get_req = NativeRequest {
            id: 2,
            command: "get_entry".to_string(),
            password: None,
            url: None,
            id_param: Some(entry_id),
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
        let result = execute_command(get_req, state).unwrap();
        assert_eq!(result["password"], "my_password");
        assert_eq!(result["notes"], "some notes");
        assert_eq!(result["title"], "Site");
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
                password: Some(format!("pass{}", i)),
                url: None,
                id_param: None,
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
            execute_command(req, state.clone()).unwrap();
        }

        let list_req = make_request("list_all_entries", 10);
        let result = execute_command(list_req, state).unwrap();
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
            password: Some("old_pass".to_string()),
            url: Some("https://old.com".to_string()),
            id_param: None,
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
        let created = execute_command(create_req, state.clone()).unwrap();
        let entry_id = created["id"].as_str().unwrap().to_string();

        // Update the entry
        let update_req = NativeRequest {
            id: 2,
            command: "update_entry".to_string(),
            password: Some("new_pass".to_string()),
            url: Some("https://new.com".to_string()),
            id_param: Some(entry_id),
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
        let result = execute_command(update_req, state.clone()).unwrap();
        assert_eq!(result["title"], "New Title");
        assert_eq!(result["username"], "new_user");
        assert_eq!(result["tags"], serde_json::json!(["updated"]));

        // Verify password was re-encrypted
        let db = state.database.lock().expect("db lock").clone().expect("db");
        let entry = database::load_entry(&db, &result["id"].as_str().unwrap()).unwrap().unwrap();
        let key = crypto::get_key().unwrap();
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
            password: Some("pass".to_string()),
            url: None,
            id_param: None,
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
        let created = execute_command(create_req, state.clone()).unwrap();
        let entry_id = created["id"].as_str().unwrap().to_string();

        // Remove it
        let remove_req = NativeRequest {
            id: 2,
            command: "remove_entry".to_string(),
            password: None,
            url: None,
            id_param: Some(entry_id),
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
        let result = execute_command(remove_req, state.clone()).unwrap();
        assert_eq!(result, serde_json::json!(true));

        // Verify count is 0
        let count_req = make_request("get_entry_count", 3);
        let count = execute_command(count_req, state).unwrap();
        assert_eq!(count, serde_json::json!(0));
    }

    // ---- get_entry_count ----

    #[test]
    fn test_get_entry_count() {
        let (state, _temp) = setup_test_state();
        init_test_vault(&state, "master123");

        let req = make_request("get_entry_count", 1);
        let result = execute_command(req, state.clone()).unwrap();
        assert_eq!(result, serde_json::json!(0));

        // Create an entry
        let create_req = NativeRequest {
            id: 2,
            command: "create_entry".to_string(),
            password: Some("pass".to_string()),
            url: None,
            id_param: None,
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
        execute_command(create_req, state.clone()).unwrap();

        let count_req = make_request("get_entry_count", 3);
        let count = execute_command(count_req, state).unwrap();
        assert_eq!(count, serde_json::json!(1));
    }

    // ---- generate_password ----

    #[test]
    fn test_generate_password_default() {
        let (state, _temp) = setup_test_state();
        let req = make_request("generate_password", 1);
        let result = execute_command(req, state).unwrap();
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
        let result = execute_command(req, state).unwrap();
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
        let result = execute_command(req, state).unwrap();
        let password = result.as_str().unwrap();

        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

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
            let result = execute_command(req, state.clone()).unwrap();
            let password = result.as_str().unwrap();
            assert_eq!(password.len(), 4);

            let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
            let has_digit = password.chars().any(|c| c.is_ascii_digit());
            let has_symbol = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

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
        let result = execute_command(req, state);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown command"));
    }

    // ---- operations when locked ----

    #[test]
    fn test_get_entry_locked() {
        let (state, _temp) = setup_test_state();
        let req = NativeRequest {
            id: 1,
            command: "get_entry".to_string(),
            id_param: Some("some-id".to_string()),
            ..make_request("get_entry", 1)
        };
        let result = execute_command(req, state);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_entries_locked() {
        let (state, _temp) = setup_test_state();
        let req = make_request("list_all_entries", 1);
        let result = execute_command(req, state);
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
            password: Some("p".to_string()),
            ..make_request("update_entry", 1)
        };
        let result = execute_command(req, state);
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
        let result = execute_command(req, state);
        assert!(result.is_err());
    }

    #[test]
    fn test_entry_count_locked() {
        let (state, _temp) = setup_test_state();
        let req = make_request("get_entry_count", 1);
        let result = execute_command(req, state);
        assert!(result.is_err());
    }
}