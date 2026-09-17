//! Native Messaging protocol layer.
//!
//! Wire types (`NativeRequest` / `NativeResponse`) plus the gates applied to
//! every request before dispatch: API path shape, protocol version, Origin
//! label, Bearer token, and the pair-endpoint rate limit.

use std::net::TcpStream;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use pwdvault_application::AppState;
use pwdvault_domain::constants;
use pwdvault_infrastructure::auth;
use pwdvault_infrastructure::database;

use super::dispatcher::execute_command;
use super::server::{read_http_request, write_http_response};

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

pub(super) fn error_response(id: u32, error: String) -> NativeResponse {
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

/// Check rate limit for pair endpoint (max 10 requests per minute)
pub(super) fn enforce_pair_rate_limit(state: &AppState) -> Result<(), String> {
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

    Ok(())
}

pub(super) fn handle_connection(
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
