//! Native Messaging Server
//!
//! Provides an HTTP server for browser extension communication.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::Emitter;
use zeroize::Zeroizing;

use pwdvault_infrastructure::auth;
use pwdvault_domain::constants;
use pwdvault_infrastructure::database;
use pwdvault_application::service;
use pwdvault_application::{AppState, CreateEntryRequest, UpdateEntryRequest, VaultBackup, VaultError};

const HTTP_WORKERS: usize = 8;
const HTTP_QUEUE_CAPACITY: usize = 64;
const HTTP_HEADER_LIMIT: usize = 16 * 1024;
const HTTP_IO_TIMEOUT: Duration = Duration::from_secs(5);

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
    #[serde(default)]
    pub protocol_version: u16,
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
    pub session_nonce: Option<Zeroizing<String>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

/// Start the native messaging HTTP server
///
/// Requests are processed by a fixed worker pool and bounded queue. This keeps
/// slow or malformed loopback clients from creating unbounded OS threads.
pub fn start_server(
    port: u16,
    state: Arc<AppState>,
    app_handle: Option<tauri::AppHandle>,
) -> Result<(), String> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).map_err(|error| format!("Server error: {error}"))?;

    tracing::info!(port = port, "native messaging server started");

    // Bound accepted sockets before HTTP parsing. tiny_http's internal task
    // pool grew one thread per slow connection, so bounding only parsed
    // requests was insufficient against slowloris traffic.
    let (sender, receiver) = mpsc::sync_channel::<TcpStream>(HTTP_QUEUE_CAPACITY);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..HTTP_WORKERS {
        let receiver = receiver.clone();
        let state = state.clone();
        let app_handle = app_handle.clone();
        std::thread::Builder::new()
            .name(format!("pwdvault-http-{index}"))
            .spawn(move || loop {
                let request = {
                    let guard = receiver.lock().expect("HTTP queue lock poisoned");
                    guard.recv()
                };
                match request {
                    Ok(stream) => handle_connection(stream, state.clone(), app_handle.clone()),
                    Err(_) => break,
                }
            })
            .map_err(|error| format!("Failed to start HTTP worker: {error}"))?;
    }

    for incoming in listener.incoming() {
        let stream = incoming.map_err(|error| format!("Accept failed: {error}"))?;
        if let Err(error) = sender.try_send(stream) {
            match error {
                mpsc::TrySendError::Full(mut stream) => {
                    reject_busy_connection(&mut stream);
                }
                mpsc::TrySendError::Disconnected(_) => {
                    return Err("HTTP worker pool stopped".to_string());
                }
            }
        }
    }

    Ok(())
}

fn reject_busy_connection(stream: &mut TcpStream) {
    // Drain bytes already delivered by a complete client request so macOS does
    // not replace the 503 response with an immediate RST when the socket is
    // dropped. Never wait here: the accept loop must remain bounded even for
    // slow clients.
    if stream.set_nonblocking(true).is_ok() {
        let mut drained = 0usize;
        let mut buffer = [0u8; 4096];
        while drained < HTTP_HEADER_LIMIT {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => drained += read,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        let _ = stream.set_nonblocking(false);
    }
    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
    let response = error_response(0, "Server busy; retry later".to_string());
    let _ = write_http_response(stream, 503, &response);
    let _ = stream.shutdown(Shutdown::Write);
}

#[derive(Debug)]
struct ParsedHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Zeroizing<String>,
}

#[derive(Debug)]
struct HttpFailure {
    status: u16,
    message: String,
}

impl HttpFailure {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_http_request(stream: &mut TcpStream) -> Result<ParsedHttpRequest, HttpFailure> {
    stream
        .set_read_timeout(Some(HTTP_IO_TIMEOUT))
        .map_err(|_| HttpFailure::new(500, "Request failed"))?;
    stream
        .set_write_timeout(Some(HTTP_IO_TIMEOUT))
        .map_err(|_| HttpFailure::new(500, "Request failed"))?;

    let mut buffer = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
        if buffer.len() >= HTTP_HEADER_LIMIT {
            return Err(HttpFailure::new(431, "Request headers too large"));
        }
        let mut chunk = [0u8; 4096];
        let read = stream
            .read(&mut chunk)
            .map_err(|_| HttpFailure::new(408, "Request timeout"))?;
        if read == 0 {
            return Err(HttpFailure::new(400, "Invalid request"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > HTTP_HEADER_LIMIT + constants::MAX_BODY_SIZE {
            return Err(HttpFailure::new(413, "Request too large"));
        }
    };

    let header_bytes = &buffer[..header_end];
    let header_text =
        std::str::from_utf8(header_bytes).map_err(|_| HttpFailure::new(400, "Invalid request"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| HttpFailure::new(400, "Invalid request"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| HttpFailure::new(400, "Invalid request"))?;
    let path = request_parts
        .next()
        .ok_or_else(|| HttpFailure::new(400, "Invalid request"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| HttpFailure::new(400, "Invalid request"))?;
    if request_parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(HttpFailure::new(400, "Invalid request"));
    }

    let mut headers = HashMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| HttpFailure::new(400, "Invalid request"))?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || value.contains(['\r', '\n']) || headers.contains_key(&name) {
            return Err(HttpFailure::new(400, "Invalid request"));
        }
        headers.insert(name, value.trim().to_string());
    }

    if method != "POST" {
        return Err(HttpFailure::new(405, "POST required"));
    }
    if headers.contains_key("transfer-encoding") {
        return Err(HttpFailure::new(400, "Transfer-Encoding is not supported"));
    }
    let content_type_is_json = headers
        .get("content-type")
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !content_type_is_json {
        return Err(HttpFailure::new(
            415,
            "Content-Type application/json required",
        ));
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length > 0)
        .ok_or_else(|| HttpFailure::new(411, "Valid Content-Length required"))?;
    if content_length > constants::MAX_BODY_SIZE {
        return Err(HttpFailure::new(413, "Request too large"));
    }

    let body_start = header_end + 4;
    let mut body = Vec::with_capacity(content_length);
    let already_read = buffer.len().saturating_sub(body_start).min(content_length);
    body.extend_from_slice(&buffer[body_start..body_start + already_read]);
    while body.len() < content_length {
        let mut chunk = [0u8; 8192];
        let remaining = content_length - body.len();
        let read_limit = remaining.min(chunk.len());
        let read = stream
            .read(&mut chunk[..read_limit])
            .map_err(|_| HttpFailure::new(408, "Request timeout"))?;
        if read == 0 {
            return Err(HttpFailure::new(400, "Content-Length mismatch"));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    let body = String::from_utf8(body).map_err(|_| HttpFailure::new(400, "Invalid request"))?;

    Ok(ParsedHttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body: Zeroizing::new(body),
    })
}

fn handle_connection(
    mut stream: TcpStream,
    state: Arc<AppState>,
    app_handle: Option<tauri::AppHandle>,
) {
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(error) => {
            let response = error_response(0, error.message);
            let _ = write_http_response(&mut stream, error.status, &response);
            return;
        }
    };
    debug_assert_eq!(request.method, "POST");
    let origin = request.headers.get("origin").cloned();
    // This is a caller label derived by the native host from browser process
    // arguments. The loopback header is not itself an authentication boundary;
    // it binds pairing state after the host has validated the browser caller.
    let caller = request.headers.get("x-pwdvault-caller").cloned();

    // Parse request
    let native_req: NativeRequest = match serde_json::from_str(&request.body) {
        Ok(r) => r,
        Err(_) => {
            let response = error_response(0, "Invalid request".to_string());
            let _ = write_http_response(&mut stream, 400, &response);
            return;
        }
    };

    let id = native_req.id;
    let command = native_req.command.clone();

    if request.path != format!("/api/{command}") {
        let response = error_response(id, "Invalid API path".to_string());
        let _ = write_http_response(&mut stream, 404, &response);
        return;
    }

    if native_req.protocol_version != constants::NATIVE_PROTOCOL_VERSION {
        let response = error_response(
            id,
            "Unsupported protocol version; update PwdVault and the browser extension".to_string(),
        );
        let _ = write_http_response(&mut stream, 400, &response);
        return;
    }

    // Origin is a browser-caller label supplied by the native host. It rejects
    // accidental/direct clients but is not an authentication boundary on a
    // loopback HTTP socket; Bearer auth and user-confirmed pairing remain the
    // security controls until the socket/pipe transport phase.
    if !auth::is_extension_origin(origin.as_deref()) {
        let response = error_response(id, "Forbidden".to_string());
        let _ = write_http_response(&mut stream, 403, &response);
        return;
    }

    // Authentication: /api/pair and /api/pair_confirm are unauthenticated
    // (extension pairing flow — no token exists yet). All other endpoints
    // require Bearer token.
    if command != "handshake" && command != "pair" && command != "pair_confirm" {
        let auth_header = request
            .headers
            .get("authorization")
            .map(String::as_str)
            .unwrap_or("");

        if !auth::validate_token(auth_header) {
            let response = error_response(id, "Unauthorized".to_string());
            let _ = write_http_response(&mut stream, 401, &response);
            return;
        }
    }

    // Execute command
    let result = execute_command(native_req, state, app_handle, caller);

    // Send response
    let response = match result {
        Ok(data) => NativeResponse {
            id,
            success: true,
            data: Some(data),
            error: None,
            error_code: None,
            error_message: None,
            retry_after: None,
        },
        Err(e) => NativeResponse {
            id,
            success: false,
            data: None,
            error: Some(e.clone()),
            error_code: Some("COMMAND_FAILED".to_string()),
            error_message: Some(e),
            retry_after: None,
        },
    };

    let _ = write_http_response(&mut stream, 200, &response);
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    response: &NativeResponse,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(response).unwrap_or_default();
    let headers = format!(
        "HTTP/1.1 {status} {}\r\n\
         Content-Type: application/json\r\n\
         Cache-Control: no-store\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        status_reason(status),
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

fn error_response(id: u32, error: String) -> NativeResponse {
    NativeResponse {
        id,
        success: false,
        data: None,
        error: Some(error.clone()),
        error_code: Some("REQUEST_REJECTED".to_string()),
        error_message: Some(error),
        retry_after: None,
    }
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
    caller: Option<String>,
) -> Result<serde_json::Value, String> {
    // Vault operations now acquire a session lease (§5.1.1) inside each
    // service function, which provides the same serialization guarantee
    // that op_lock formerly provided — but uniformly across HTTP and Tauri
    // IPC paths. Pair/pair_confirm only manipulate in-memory state and
    // don't need a lease.
    //
    // NOTE: The per-operation lease will be added in the service layer
    // migration. For now, the service functions check is_unlocked() and
    // obtain keys from the session directly.

    match req.command.as_str() {
        "handshake" => Ok(serde_json::json!({
            "protocol_version": constants::NATIVE_PROTOCOL_VERSION,
            "app_version": env!("CARGO_PKG_VERSION"),
            "capabilities": [
                "caller_bound_pairing",
                "entry_secret_split",
                "trusted_token_storage",
            ],
        })),

        "revoke_extension_access" => {
            auth::revoke_extension_access();
            pwdvault_infrastructure::pairing::cancel_all_sessions();
            Ok(serde_json::json!(true))
        }

        // Extension pairing — returns API token (no auth required, origin checked in handle_request)
        // Rate limited to prevent token enumeration attacks
        "pair" => {
            let caller = caller.as_deref().ok_or("Browser caller required")?;
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

            let challenge = pwdvault_infrastructure::pairing::create_session(caller);
            // Notify desktop UI to display the pairing code.
            if let Some(handle) = app_handle {
                let _ = handle.emit("pair-request", &challenge.code);
            }
            Ok(serde_json::json!({
                "pending": true,
                "session_nonce": challenge.nonce,
            }))
        }

        "pair_confirm" => {
            let caller = caller.as_deref().ok_or("Browser caller required")?;
            let session_nonce = req.session_nonce.ok_or("Pairing session required")?;
            let user_code = req.code.ok_or("Code required")?;
            if pwdvault_infrastructure::pairing::verify(caller, session_nonce.as_str(), user_code.as_str()) {
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
            let update_notes = req.notes.is_some();
            let request = UpdateEntryRequest {
                title: req.title.ok_or("Title required".to_string())?,
                username: req.username.ok_or("Username required".to_string())?,
                password: req.password,
                url: req.url,
                notes: req.notes,
                update_notes,
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
    use pwdvault_infrastructure::crypto;
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
        // Clear any existing session state
        state.lock_vault();

        let salt = crypto::kdf::generate_salt();
        let (master_key, params) = crypto::kdf::derive_key(password, &salt).expect("derive key");
        let verification = crypto::create_verification_header(&master_key, salt, params)
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
        let entry = database::load_entry(&db, key, result["id"].as_str().unwrap())
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
}
