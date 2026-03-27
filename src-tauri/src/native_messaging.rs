//! Native Messaging Server
//!
//! Provides an HTTP server for browser extension communication.

use std::sync::Arc;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tiny_http::{Request, Response, Server};

use crate::AppState;
use crate::crypto;
use crate::database;

/// Get the database file path (same as Tauri app)
fn get_db_path() -> PathBuf {
    // Use platform-specific app data directory
    let base_dir = {
        #[cfg(target_os = "macos")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join("com.pwdvault.app")
        }
        #[cfg(target_os = "windows")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join("PwdVault")
        }
        #[cfg(target_os = "linux")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join("pwdvault")
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            std::env::current_dir().unwrap()
        }
    };
    base_dir.join("vault.db")
}

/// Ensure database directory exists
fn ensure_db_dir() -> Result<PathBuf, String> {
    let db_path = get_db_path();
    eprintln!("[DEBUG NM] Database path: {:?}", db_path);
    if let Some(parent) = db_path.parent() {
        eprintln!("[DEBUG NM] Parent directory: {:?}", parent);
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }
    Ok(db_path)
}

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
        tiny_http::Header::from_bytes("Access-Control-Allow-Origin".as_bytes(), "*".as_bytes()).unwrap()
    );
    response.add_header(
        tiny_http::Header::from_bytes("Access-Control-Allow-Methods".as_bytes(), "POST, OPTIONS".as_bytes()).unwrap()
    );
    response.add_header(
        tiny_http::Header::from_bytes("Access-Control-Allow-Headers".as_bytes(), "Content-Type".as_bytes()).unwrap()
    );
}

fn handle_request(mut request: Request, state: Arc<AppState>) {
    // Handle CORS preflight
    if request.method() == &tiny_http::Method::Options {
        let response = Response::empty(204)
            .with_header(
                tiny_http::Header::from_bytes("Access-Control-Allow-Origin".as_bytes(), "*".as_bytes()).unwrap()
            )
            .with_header(
                tiny_http::Header::from_bytes("Access-Control-Allow-Methods".as_bytes(), "POST, OPTIONS".as_bytes()).unwrap()
            )
            .with_header(
                tiny_http::Header::from_bytes("Access-Control-Allow-Headers".as_bytes(), "Content-Type".as_bytes()).unwrap()
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
            tiny_http::Header::from_bytes("Content-Type".as_bytes(), "application/json".as_bytes()).unwrap()
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
            let initialized = state.verification_data.lock().unwrap().is_some();
            Ok(serde_json::json!(initialized))
        }

        "is_vault_unlocked" => {
            Ok(serde_json::json!(crypto::is_unlocked()))
        }

        "setup_vault" => {
            // Check if database is already loaded in state
            {
                let db_guard = state.database.lock().unwrap();
                if db_guard.is_some() && state.verification_data.lock().unwrap().is_some() {
                    return Ok(serde_json::json!(true));
                }
            }

            let db_path = get_db_path();

            if !db_path.exists() {
                return Ok(serde_json::json!(false));
            }

            // Initialize database
            let db = std::sync::Arc::new(database::init_database(&db_path).map_err(|e| e.to_string())?);

            // Load verification data from database
            let verification_data = database::load_verification_data(&db).map_err(|e| e.to_string())?;

            if let Some(data) = verification_data {
                *state.verification_data.lock().unwrap() = Some(data);
                *state.database.lock().unwrap() = Some(db);
                return Ok(serde_json::json!(true));
            }

            Ok(serde_json::json!(false))
        }

        "init_vault" => {
            let password = req.password.ok_or("Password required")?;

            // Check if already initialized
            if state.verification_data.lock().unwrap().is_some() {
                return Err("Vault already initialized".to_string());
            }

            // Generate salt and derive key
            let salt = crypto::kdf::generate_salt();
            let (key, params) = crypto::kdf::derive_key(&password, &salt)
                .map_err(|e| e.to_string())?;

            // Create verification data
            let verification_data = crypto::create_verification_header(&key, salt, params)
                .map_err(|e| e.to_string())?;

            // Initialize database with consistent path
            let db_path = ensure_db_dir()?;
            eprintln!("[DEBUG] About to init database at: {:?}", db_path);
            eprintln!("[DEBUG] Path exists: {}", db_path.exists());
            if db_path.exists() {
                eprintln!("[DEBUG] Is directory: {}", db_path.is_dir());
            }
            let db = database::init_database(&db_path).map_err(|e| {
                eprintln!("[DEBUG] Database init error: {}", e);
                e.to_string()
            })?;

            // Save verification data
            database::save_verification_data(&db, &verification_data)
                .map_err(|e| e.to_string())?;

            // Update state
            *state.verification_data.lock().unwrap() = Some(verification_data);
            *state.database.lock().unwrap() = Some(std::sync::Arc::new(db));

            // Set key in memory
            crypto::set_key(key).map_err(|e| e.to_string())?;

            Ok(serde_json::json!(true))
        }

        "unlock_vault" => {
            let password = req.password.ok_or("Password required")?;
            let verification_data = state.verification_data.lock().unwrap();
            let data = verification_data.as_ref().ok_or("Vault not initialized")?;
            let success = crypto::unlock_with_password(&password, data)
                .map_err(|e| e.to_string())?;
            Ok(serde_json::json!(success))
        }

        "lock_vault" => {
            crypto::clear_key();
            Ok(serde_json::json!(null))
        }

        "create_entry" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let title = req.title.ok_or("Title required")?;
            let username = req.username.ok_or("Username required")?;
            let password = req.password.ok_or("Password required")?;

            let db_guard = state.database.lock().unwrap();
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

            database::save_entry(db, &entry).map_err(|e| e.to_string())?;

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

        "list_all_entries" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let db_guard = state.database.lock().unwrap();
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let ids = database::list_entries(db).map_err(|e| e.to_string())?;
            let mut entries = Vec::new();

            for id in ids {
                if let Some(entry) = database::load_entry(db, &id).map_err(|e| e.to_string())? {
                    entries.push(serde_json::to_value(entry).unwrap());
                }
            }

            Ok(serde_json::json!(entries))
        }

        "get_entry" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let id = req.id_param.ok_or("Entry ID required")?;
            let db_guard = state.database.lock().unwrap();
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

            Ok(serde_json::json!({
                "id": entry.id,
                "title": entry.title,
                "url": entry.url,
                "username": entry.username,
                "password": password,
                "notes": notes,
                "tags": entry.tags,
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

            use rand::Rng;
            let mut charset = String::new();
            if options.include_uppercase {
                charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
            }
            if options.include_lowercase {
                charset.push_str("abcdefghijklmnopqrstuvwxyz");
            }
            if options.include_numbers {
                charset.push_str("0123456789");
            }
            if options.include_symbols {
                charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
            }

            if charset.is_empty() {
                charset = "abcdefghijklmnopqrstuvwxyz".to_string();
            }

            let bytes: Vec<u8> = charset.bytes().collect();
            let mut rng = rand::thread_rng();

            let password: String = (0..options.length)
                .map(|_| {
                    let idx = rng.gen_range(0..bytes.len());
                    bytes[idx] as char
                })
                .collect();

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

            let db_guard = state.database.lock().unwrap();
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
            let db_guard = state.database.lock().unwrap();
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let existed = database::delete_entry(db, &id).map_err(|e| e.to_string())?;
            Ok(serde_json::json!(existed))
        }

        "get_entry_count" => {
            if !crypto::is_unlocked() {
                return Err("Vault locked".to_string());
            }

            let db_guard = state.database.lock().unwrap();
            let db = db_guard.as_ref().ok_or("Database not initialized")?;

            let count = database::count_entries(db).map_err(|e| e.to_string())?;
            Ok(serde_json::json!(count))
        }

        _ => Err(format!("Unknown command: {}", req.command))
    }
}