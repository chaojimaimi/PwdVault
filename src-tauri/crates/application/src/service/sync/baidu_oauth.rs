//! P3.4 Baidu Netdisk OAuth2 authorization-code flow (D6 — Tauri-only).
//!
//! Authorization-code flow WITHOUT PKCE (Baidu does not support it — plan
//! decision). `baidu_start_auth` assembles the authorize URL and parks a
//! detached listener on the fixed loopback port ([`BAIDU_OAUTH_PORT`], kept
//! distinct from the extension bridge port 17429); the browser redirect
//! lands in a process-level slot that `baidu_complete_auth` exchanges for
//! tokens stored in the NON-INTERACTIVE credential store (`sync-baidu-token`
//! account, never behind Touch ID — a background sync must not prompt).
//! AppKey/SecretKey are compile-time placeholders ([`BAIDU_APP_KEY`] /
//! [`BAIDU_SECRET_KEY`], docs/BAIDU-SETUP.md).

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::backend::BackendError;
use super::baidu::{
    now_secs, OAUTH_API_BASE, REQUEST_TIMEOUT, USER_AGENT,
};
use super::engine::backend_error;
use crate::{AppState, VaultError};
use pwdvault_domain::constants::{
    BAIDU_APP_KEY, BAIDU_OAUTH_PORT, BAIDU_REDIRECT_URI, BAIDU_SECRET_KEY,
};
use pwdvault_infrastructure::keychain::{SecretStore, SYNC_BAIDU_TOKEN_ACCOUNT};

/// How long the loopback listener waits for the browser redirect (P3.4).
const OAUTH_CALLBACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Loopback interface the OAuth listener binds.
const CALLBACK_HOST: &str = "127.0.0.1";

/// Baidu token pair + expiry, stored as JSON in the non-interactive
/// credential store under `sync-baidu-token`. Zeroized on drop.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct BaiduTokens {
    pub(crate) access_token: String,
    /// Single-use: every refresh mints a fresh pair which must be persisted.
    pub(crate) refresh_token: String,
    /// Unix seconds after which the access token should be considered stale.
    /// (Refresh is reactive — on 401/`errno -6` — not proactive.)
    pub(crate) expires_at: i64,
}

/// Result of `baidu_start_auth` (D6: `-> {auth_url}`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BaiduAuthStart {
    /// Authorization URL for the system browser.
    pub auth_url: String,
}

/// Outcome of the loopback callback wait.
pub(crate) type CallbackOutcome = Result<String, String>;

/// The single pending-callback slot: `baidu_start_auth` parks the browser
/// redirect result here (the detached listener thread outlives the command
/// call), `baidu_complete_auth` consumes it. `pub(crate)` for the tests.
pub(crate) static PENDING_CALLBACK: Mutex<Option<CallbackOutcome>> = Mutex::new(None);

/// Whether this build carries compiled-in Baidu credentials (P3.8: the
/// shipped placeholders are empty → `NotConfigured`, and the frontend shows
/// the BAIDU-SETUP.md guidance instead).
pub fn baidu_configured() -> bool {
    !BAIDU_APP_KEY.trim().is_empty() && !BAIDU_SECRET_KEY.trim().is_empty()
}

fn auth_failed(message: impl Into<String>) -> VaultError {
    VaultError::InvalidInput {
        code: "SYNC_BAIDU_AUTH_FAILED".to_string(),
        message: message.into(),
    }
}

/// Assemble the authorize URL (P3.4): authorization code, our registered
/// loopback redirect (exact match including port), netdisk scope, page
/// display. No PKCE — Baidu's OAuth does not support it (plan decision).
pub(crate) fn build_auth_url(app_key: &str, redirect_uri: &str, oauth_base: &str) -> String {
    format!(
        "{oauth_base}/oauth/2.0/authorize?\
         response_type=code&client_id={}&redirect_uri={}&scope=basic,netdisk&display=page",
        super::baidu::encode_value(app_key),
        super::baidu::encode_value(redirect_uri),
    )
}

/// D6: assemble the authorization URL and park a listener on the fixed
/// loopback callback port. Returns immediately with the URL — the browser
/// redirect is consumed by the detached waiter thread (5-minute budget)
/// into [`PENDING_CALLBACK`], which [`baidu_complete_auth`] exchanges.
/// Tauri-only (D6); the command wrapper runs it under `spawn_blocking`
/// because binding the port can block.
pub fn baidu_start_auth(_state: &Arc<AppState>) -> Result<BaiduAuthStart, VaultError> {
    if !baidu_configured() {
        return Err(backend_error(BackendError::NotConfigured));
    }
    let listener = TcpListener::bind((CALLBACK_HOST, BAIDU_OAUTH_PORT)).map_err(|e| {
        auth_failed(format!(
            "cannot listen on the OAuth callback port {BAIDU_OAUTH_PORT} \
             (is another authorization still in progress?): {e}"
        ))
    })?;
    let server = tiny_http::Server::from_listener(listener, None)
        .map_err(|e| auth_failed(format!("cannot start the OAuth callback server: {e}")))?;
    // One pending authorization at a time: a new start supersedes an old
    // (possibly stale) callback result.
    *PENDING_CALLBACK.lock().expect("pending callback lock poisoned") = None;
    let auth_url = build_auth_url(BAIDU_APP_KEY, BAIDU_REDIRECT_URI, OAUTH_API_BASE);
    std::thread::spawn(move || {
        let outcome = wait_for_callback(&server, OAUTH_CALLBACK_TIMEOUT);
        *PENDING_CALLBACK.lock().expect("pending callback lock poisoned") = Some(outcome);
    });
    Ok(BaiduAuthStart { auth_url })
}

/// D6: exchange the authorization `code` for tokens and store them in the
/// non-interactive credential store. `None`/empty consumes the code
/// captured by the pending [`baidu_start_auth`] callback listener; an
/// explicit code (manual paste / tests) takes precedence.
pub fn baidu_complete_auth(state: &Arc<AppState>, code: Option<String>) -> Result<(), VaultError> {
    if !baidu_configured() {
        return Err(backend_error(BackendError::NotConfigured));
    }
    complete_auth_with(
        &state.sync_secret_store,
        BAIDU_APP_KEY,
        BAIDU_SECRET_KEY,
        OAUTH_API_BASE,
        code.as_deref(),
    )
    .map_err(backend_error)
}

/// [`baidu_complete_auth`] with injected credentials/endpoints (test seam).
pub(crate) fn complete_auth_with(
    store: &Arc<dyn SecretStore>,
    app_key: &str,
    secret_key: &str,
    oauth_base: &str,
    code: Option<&str>,
) -> Result<(), BackendError> {
    let code = match code.filter(|value| !value.trim().is_empty()) {
        Some(code) => code.to_string(),
        None => match PENDING_CALLBACK.lock().expect("pending callback lock poisoned").take()
        {
            Some(Ok(code)) => code,
            Some(Err(reason)) => return Err(BackendError::Auth(reason)),
            None => {
                return Err(BackendError::Auth(
                    "no pending Baidu authorization — start the flow first".to_string(),
                ))
            }
        },
    };
    // The redirect_uri must repeat the authorize-request value verbatim
    // (standard OAuth + Baidu requirement).
    let query = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}",
        super::baidu::encode_value(&code),
        super::baidu::encode_value(app_key),
        super::baidu::encode_value(secret_key),
        super::baidu::encode_value(BAIDU_REDIRECT_URI),
    );
    let tokens = token_request(oauth_base, &query)?;
    let bytes = serde_json::to_vec(&tokens)
        .map_err(|e| BackendError::Network(format!("token serialization failed: {e}")))?;
    store
        .set(SYNC_BAIDU_TOKEN_ACCOUNT, &bytes)
        .map_err(|err| BackendError::Auth(format!("cannot persist Baidu token: {err}")))?;
    Ok(())
}

/// Exchange/refresh at the OAuth token endpoint. `query` carries grant_type
/// plus the grant-specific parameters; the client credentials are included
/// by every caller. Shared with [`super::baidu::BaiduBackend::refresh_tokens`].
pub(crate) fn token_request(oauth_base: &str, query: &str) -> Result<BaiduTokens, BackendError> {
    let url = format!("{oauth_base}/oauth/2.0/token?{query}");
    // Throwaway agent — token calls happen once per link/refresh.
    let agent: ureq::Agent = ureq::config::Config::builder()
        .timeout_global(Some(REQUEST_TIMEOUT))
        .http_status_as_error(false)
        .build()
        .into();
    let request = ureq::http::Request::builder()
        .method("GET")
        .uri(&url)
        .header("User-Agent", USER_AGENT)
        .body(Vec::new())
        .map_err(|e| BackendError::Network(format!("token request build failed: {e}")))?;
    let mut response = agent
        .run(request)
        .map_err(|e| BackendError::Network(format!("token request failed: {e}")))?;
    let status = response.status().as_u16();
    let bytes = response
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_vec()
        .map_err(|e| BackendError::Network(format!("token response read failed: {e}")))?;
    if !(200..300).contains(&status) {
        // OAuth error JSON: {"error": "...", "error_description": "..."} —
        // the grant or client credentials were rejected.
        return Err(BackendError::Auth(format!(
            "Baidu token endpoint returned HTTP {status}"
        )));
    }
    let parsed: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| BackendError::Network("token endpoint returned non-JSON".to_string()))?;
    if let Some(error) = parsed.get("error").and_then(|error| error.as_str()) {
        return Err(BackendError::Auth(format!(
            "Baidu token endpoint rejected the grant: {error}"
        )));
    }
    let access_token = parsed
        .get("access_token")
        .and_then(|value| value.as_str())
        .ok_or_else(|| BackendError::Network("token response missing access_token".to_string()))?
        .to_string();
    // Refresh tokens are single-use — a response without one would leave a
    // dead pair behind, so it is required.
    let refresh_token = parsed
        .get("refresh_token")
        .and_then(|value| value.as_str())
        .ok_or_else(|| BackendError::Network("token response missing refresh_token".to_string()))?
        .to_string();
    let expires_in = parsed.get("expires_in").and_then(|value| value.as_i64()).unwrap_or(0);
    Ok(BaiduTokens {
        access_token,
        refresh_token,
        expires_at: now_secs() + expires_in,
    })
}

/// Wait (blocking) for exactly one browser callback on the loopback server;
/// serve a small completion page and hand back the authorization code (or a
/// human-readable failure reason). Bounded by `timeout`.
pub(crate) fn wait_for_callback(server: &tiny_http::Server, timeout: Duration) -> CallbackOutcome {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("authorization timed out — no callback within 5 minutes".to_string());
        }
        match server.recv_timeout(deadline - now) {
            Ok(Some(request)) => {
                let url = request.url().to_string();
                let (outcome, page) = callback_page_for(&url);
                let status = if outcome.is_ok() { 200 } else { 400 };
                let response = tiny_http::Response::from_string(page).with_status_code(status);
                let _ = request.respond(response);
                return outcome;
            }
            // Poll again; the deadline check above terminates us.
            Ok(None) => continue,
            Err(e) => return Err(format!("callback listener failed: {e}")),
        }
    }
}

/// Parse `?code=`/`?error=` from the callback URL and build the HTML answer
/// for the browser (the user just sees "return to PwdVault").
pub(crate) fn callback_page_for(url: &str) -> (CallbackOutcome, String) {
    let query = url.split_once('?').map(|(_, query)| query).unwrap_or("");
    let mut code = None;
    let mut error = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "code" => code = Some(percent_decode(value)),
            "error" => error = Some(percent_decode(value)),
            _ => {}
        }
    }
    if let Some(error) = error {
        (
            Err(format!("authorization was denied by Baidu ({error})")),
            "<html><body><h3>PwdVault</h3><p>Authorization failed — you can close this tab \
             and try again from PwdVault.</p></body></html>"
                .to_string(),
        )
    } else if let Some(code) = code.filter(|code| !code.is_empty()) {
        (
            Ok(code),
            "<html><body><h3>PwdVault</h3><p>Authorization received. Return to PwdVault \
             to finish connecting Baidu Netdisk.</p></body></html>"
                .to_string(),
        )
    } else {
        (
            Err("callback did not carry an authorization code".to_string()),
            "<html><body><h3>PwdVault</h3><p>Missing authorization code — please restart \
             the connection from PwdVault.</p></body></html>"
                .to_string(),
        )
    }
}

/// Minimal percent-decoding for callback query values (`%XX`; `+` handled
/// by the caller's query convention). Malformed escapes pass through.
pub(crate) fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 3 <= bytes.len() => {
                let decoded = std::str::from_utf8(&bytes[index + 1..index + 3])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok());
                match decoded {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
