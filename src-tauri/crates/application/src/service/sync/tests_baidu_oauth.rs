//! P3.4 Baidu Netdisk OAuth flow tests: authorize-URL shape, the loopback
//! callback listener (real TCP + real timeout path), the code exchange with
//! token persistence, and the NotConfigured gating of the shipped
//! placeholder credentials (P3.8).

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

use super::backend::BackendError;
use super::baidu_oauth::{
    baidu_complete_auth, baidu_configured, baidu_start_auth, build_auth_url, callback_page_for,
    complete_auth_with, wait_for_callback, CallbackGrant, CallbackOutcome, PendingAuth,
    PENDING_CALLBACK,
};
use super::engine::{sync_connect, SyncBackendKind, SyncConfig};
use super::tests_baidu::{error_code, stub_with_files};
use crate::AppState;
use pwdvault_infrastructure::keychain::{MemorySecretStore, SecretStore, SYNC_BAIDU_TOKEN_ACCOUNT};

/// Park a pending authorization in the process-global slot (test setup).
fn parked(expected_state: &str, outcome: CallbackOutcome) -> Option<PendingAuth> {
    Some(PendingAuth {
        expected_state: expected_state.to_string(),
        outcome: Some(outcome),
    })
}

#[test]
fn auth_url_carries_registered_parameters() {
    let url = build_auth_url(
        "my-app-key",
        "http://127.0.0.1:17777/",
        "https://openapi.baidu.com",
        "0123456789abcdef0123456789abcdef",
    );
    assert!(url.starts_with("https://openapi.baidu.com/oauth/2.0/authorize?"));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("client_id=my-app-key"));
    // Exact-match loopback redirect (percent-encoded), port included.
    assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A17777%2F"));
    // P2-2: the CSPRNG state token rides in the authorize URL.
    assert!(url.contains("state=0123456789abcdef0123456789abcdef"));
    assert!(url.contains("scope=basic,netdisk"));
    assert!(url.contains("display=page"));
    // Baidu OAuth has no PKCE (plan decision) — none may be offered.
    assert!(!url.contains("code_challenge"));
}

/// The loopback listener receives the browser redirect and extracts the
/// code together with the echoed state (P2-2).
#[test]
fn callback_listener_receives_the_code() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tiny_http::Server::from_listener(listener, None).unwrap();
    let waiter = thread::spawn(move || wait_for_callback(&server, Duration::from_secs(10)));

    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .write_all(b"GET /?code=abc123&state=x HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    drop(stream);

    let grant = waiter.join().unwrap().unwrap();
    assert_eq!(grant.code, "abc123");
    assert_eq!(grant.state.as_deref(), Some("x"));
}

/// Baidu error redirects and timeouts surface as failures.
#[test]
fn callback_listener_surfaces_error_and_timeout() {
    let (outcome, _) = callback_page_for("/?error=access_denied&error_description=user+denied");
    assert_eq!(
        outcome.unwrap_err(),
        "authorization was denied by Baidu (access_denied)"
    );
    let (outcome, _) = callback_page_for("/?state=x");
    assert!(outcome.is_err(), "missing code must fail");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = tiny_http::Server::from_listener(listener, None).unwrap();
    let outcome = wait_for_callback(&server, Duration::from_millis(150));
    assert!(outcome.unwrap_err().contains("timed out"));
}

/// complete_auth exchanges the code and stores {access, refresh, expires_at}
/// in the credential store; bad codes fail closed.
#[test]
fn complete_auth_exchanges_and_stores_tokens() {
    let (base, _state, _server) = stub_with_files(vec![]);
    let store: Arc<dyn SecretStore> = Arc::new(MemorySecretStore::new());

    complete_auth_with(&store, "test-app-key", "test-secret-key", &base, Some("good-code"))
        .unwrap();
    let stored: serde_json::Value =
        serde_json::from_slice(&store.get(SYNC_BAIDU_TOKEN_ACCOUNT).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "AT-CODE");
    assert_eq!(stored["refresh_token"], "RT-CODE");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        stored["expires_at"].as_i64().unwrap() > now,
        "expires_at must be a future unix timestamp"
    );

    // Wrong code → Auth, nothing written.
    let fresh: Arc<dyn SecretStore> = Arc::new(MemorySecretStore::new());
    assert!(matches!(
        complete_auth_with(&fresh, "test-app-key", "test-secret-key", &base, Some("wrong")),
        Err(BackendError::Auth(_))
    ));
    assert!(fresh.get(SYNC_BAIDU_TOKEN_ACCOUNT).is_err());
}

/// The pending-authorization slot: `None` consumes the parked result —
/// success (state echoed), failure, state mismatch/missing, or
/// nothing-pending. (Only this test touches the process-global slot, so
/// parallel test execution cannot race it.)
#[test]
fn complete_auth_consumes_the_pending_callback() {
    let (base, _state, _server) = stub_with_files(vec![]);
    let store: Arc<dyn SecretStore> = Arc::new(MemorySecretStore::new());

    // Nothing pending → Auth.
    assert!(matches!(
        complete_auth_with(&store, "test-app-key", "test-secret-key", &base, None),
        Err(BackendError::Auth(_))
    ));

    // Parked but the redirect has not landed yet → Auth.
    *PENDING_CALLBACK.lock().unwrap() = Some(PendingAuth {
        expected_state: "s1".to_string(),
        outcome: None,
    });
    assert!(matches!(
        complete_auth_with(&store, "test-app-key", "test-secret-key", &base, None),
        Err(BackendError::Auth(_))
    ));

    // Pending failure → the reason becomes the Auth message.
    *PENDING_CALLBACK.lock().unwrap() =
        parked("s1", Err("authorization timed out".to_string()));
    assert!(matches!(
        complete_auth_with(&store, "test-app-key", "test-secret-key", &base, None),
        Err(BackendError::Auth(reason)) if reason.contains("timed out")
    ));

    // P2-2: pending success with the state echoed → exchanged and stored.
    *PENDING_CALLBACK.lock().unwrap() = parked(
        "s1",
        Ok(CallbackGrant { code: "good-code".to_string(), state: Some("s1".to_string()) }),
    );
    complete_auth_with(&store, "test-app-key", "test-secret-key", &base, None).unwrap();
    let stored: serde_json::Value =
        serde_json::from_slice(&store.get(SYNC_BAIDU_TOKEN_ACCOUNT).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "AT-CODE");
    assert!(
        PENDING_CALLBACK.lock().unwrap().is_none(),
        "pending slot must be consumed"
    );

    // P2-2: a DIFFERENT state (forged/CSRF redirect) → rejected, slot
    // consumed, nothing stored.
    let fresh: Arc<dyn SecretStore> = Arc::new(MemorySecretStore::new());
    *PENDING_CALLBACK.lock().unwrap() = parked(
        "s1",
        Ok(CallbackGrant { code: "evil-code".to_string(), state: Some("s2".to_string()) }),
    );
    assert!(matches!(
        complete_auth_with(&fresh, "test-app-key", "test-secret-key", &base, None),
        Err(BackendError::Auth(reason)) if reason.contains("state mismatch")
    ));
    assert!(fresh.get(SYNC_BAIDU_TOKEN_ACCOUNT).is_err());
    assert!(PENDING_CALLBACK.lock().unwrap().is_none());

    // P2-2: a redirect with the state MISSING → rejected as well.
    *PENDING_CALLBACK.lock().unwrap() = parked(
        "s1",
        Ok(CallbackGrant { code: "good-code".to_string(), state: None }),
    );
    assert!(matches!(
        complete_auth_with(&fresh, "test-app-key", "test-secret-key", &base, None),
        Err(BackendError::Auth(reason)) if reason.contains("state mismatch")
    ));
    assert!(fresh.get(SYNC_BAIDU_TOKEN_ACCOUNT).is_err());

    // An explicit code takes precedence over any pending result.
    *PENDING_CALLBACK.lock().unwrap() = parked(
        "s1",
        Ok(CallbackGrant { code: "good-code".to_string(), state: Some("s1".to_string()) }),
    );
    complete_auth_with(&store, "test-app-key", "test-secret-key", &base, Some("good-code"))
        .unwrap();
}

/// Unconfigured build (empty placeholder constants, P3.8): the Tauri-facing
/// flows answer NotConfigured before any network or port binding, and the
/// engine's open path reports the same.
#[test]
fn unconfigured_build_reports_not_configured() {
    assert!(!baidu_configured(), "shipped constants must be empty placeholders");
    let state = Arc::new(AppState::default());

    let err = baidu_start_auth(&state).unwrap_err();
    assert_eq!(error_code(&err), "SYNC_BACKEND_NOT_CONFIGURED");
    let err = baidu_complete_auth(&state, Some("code".into())).unwrap_err();
    assert_eq!(error_code(&err), "SYNC_BACKEND_NOT_CONFIGURED");

    // Engine wiring: selecting the baidu backend fails before any session
    // or database access (open_backend runs first).
    let config = SyncConfig {
        enabled: true,
        backend: SyncBackendKind::Baidu,
        server_url: String::new(),
        remote_dir: "apps/testdir".to_string(),
        username: String::new(),
    };
    let err = sync_connect(&state, config, Zeroizing::new("pw".into()), None).unwrap_err();
    assert_eq!(error_code(&err), "SYNC_BACKEND_NOT_CONFIGURED");
}
