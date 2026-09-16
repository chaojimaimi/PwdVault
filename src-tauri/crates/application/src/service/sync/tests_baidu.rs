//! P3.4 Baidu Netdisk adapter tests: a hand-written tiny_http stub speaking
//! the pan API (filemetas / precreate / superfile / create / filemanager) and
//! the OAuth token endpoints.
//!
//! The stub pins the wire SHAPES the plan fixes (P3.4): filemetas with
//! `path` + `dlink=1`, dlink downloads with a mandatory User-Agent, the
//! precreate→superfile→create upload chain with slice MD5 block_lists, the
//! SIMULATED manifest-rev conditional write (D4), and the single-shot
//! refresh on `errno: -6`. The OAuth listener and the pending-callback slot
//! are exercised directly (real loopback, real timeout path). The engine
//! tests keep using MockCloudBackend — the two test doubles are independent.

use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

use super::backend::{BackendError, CloudBackend, MockCloudBackend, Precondition};
use super::baidu::{md5_hex, BaiduBackend};
use super::engine::{sync_connect_with_backend, SyncBackendKind, SyncConfig};
use crate::{AppState, VaultError};
use pwdvault_infrastructure::keychain::{
    MemorySecretStore, SecretStore, SYNC_BAIDU_TOKEN_ACCOUNT,
};

/// The exact User-Agent the backend must send (Baidu requires one on dlink).
const EXPECTED_UA: &str = concat!("pwdvault/", env!("CARGO_PKG_VERSION"));
/// Slice size of the backend upload (mirrors UPLOAD_SLICE_SIZE — the 2-slice
/// test below fails if someone silently changes it).
const SLICE_SIZE: usize = 4 * 1024 * 1024;
const CONTAINER_PATH: &str = "apps/testdir/pwdvault-sync.pwsync";
const MANIFEST_BODY: &[u8] = br#"{"rev":5,"device_id":"stub","sha256":"x","ts":1}"#;

fn baidu_path(relative: &str) -> String {
    format!("/{relative}")
}

fn manifest_rel_path() -> &'static str {
    "apps/testdir/pwdvault-sync.manifest.json"
}

// ---------------------------------------------------------------------------
// Stub server
// ---------------------------------------------------------------------------

/// What the stub saw for one request (wire-shape assertions).
#[derive(Debug, Clone)]
struct SeenRequest {
    url: String,
    user_agent: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct StubState {
    /// Baidu-absolute path → committed bytes.
    files: Mutex<HashMap<String, Vec<u8>>>,
    /// Uploaded-but-uncommitted slices keyed by (path, partseq).
    uploading: Mutex<HashMap<(String, usize), Vec<u8>>>,
    /// Token pairs issued by the stub, oldest first: (access, refresh).
    issued: Mutex<Vec<(String, String)>>,
    /// Next filemetas answers `errno: -6` regardless of the token.
    expire_next_filemetas: AtomicBool,
    /// Refresh-token grants are rejected (refresh failure path).
    fail_refresh: AtomicBool,
    seen: Mutex<Vec<SeenRequest>>,
}

fn spawn_stub(state: Arc<StubState>) -> (String, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let server = tiny_http::Server::from_listener(listener, None).expect("tiny_http server");
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    // The server loop runs until the returned sender is dropped (end of the
    // test) — a fixed idle timeout would kill it mid-test under the load of
    // parallel test execution.
    let _handle = thread::spawn(move || loop {
        match server.recv_timeout(Duration::from_millis(25)) {
            Ok(Some(request)) => handle_request(request, &state),
            Ok(None) => {
                if shutdown_rx.try_recv() != Err(mpsc::TryRecvError::Empty) {
                    break;
                }
            }
            Err(_) => break,
        }
    });
    (format!("http://127.0.0.1:{port}"), shutdown_tx)
}

fn handle_request(mut request: tiny_http::Request, state: &StubState) {
    let method = request.method().to_string();
    let url = request.url().to_string();
    let mut body = Vec::new();
    let _ = request.as_reader().read_to_end(&mut body);
    let header = |name: &str| -> Option<String> {
        request
            .headers()
            .iter()
            .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str().to_string())
    };
    let host = header("Host").unwrap_or_default();
    state.seen.lock().unwrap().push(SeenRequest {
        url: url.clone(),
        user_agent: header("User-Agent"),
        content_type: header("Content-Type"),
        body,
    });

    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let query = parse_query(query);
    let (status, payload): (u16, Vec<u8>) = if path == "/oauth/2.0/token" && method == "GET" {
        token_endpoint(&query, state)
    } else if path == "/rest/2.0/xpan/file" {
        file_endpoint(&query, state, &host)
    } else if path == "/rest/2.0/xpan/filemanager" {
        filemanager_endpoint(&query, state)
    } else if let Some(target) = path.strip_prefix("/dlink") {
        // The dlink hop exists to enforce the User-Agent requirement (P3.4).
        if state.seen.lock().unwrap().last().and_then(|r| r.user_agent.clone()) != Some(EXPECTED_UA.to_string()) {
            (403, b"missing user agent".to_vec())
        } else {
            match state.files.lock().unwrap().get(target) {
                Some(bytes) => (200, bytes.clone()),
                None => (404, b"not found".to_vec()),
            }
        }
    } else {
        (404, b"not found".to_vec())
    };
    let _ = request.respond(tiny_http::Response::from_data(payload).with_status_code(status));
}

fn token_accepted(token: &str, state: &StubState) -> bool {
    state.issued.lock().unwrap().iter().any(|(access, _)| access == token)
}

fn token_rejected() -> (u16, Vec<u8>) {
    (200, br#"{"errno":-6}"#.to_vec())
}

fn file_endpoint(query: &HashMap<String, String>, state: &StubState, host: &str) -> (u16, Vec<u8>) {
    let token = query.get("access_token").cloned().unwrap_or_default();
    match query.get("method").map(String::as_str).unwrap_or("") {
        "filemetas" => {
            if state.expire_next_filemetas.swap(false, Ordering::SeqCst) || !token_accepted(&token, state)
            {
                return token_rejected();
            }
            let target = query.get("path").cloned().unwrap_or_default();
            let files = state.files.lock().unwrap();
            match files.get(&target) {
                None => (200, br#"{"errno":31066,"list":[]}"#.to_vec()),
                Some(bytes) => {
                    let payload = serde_json::json!({
                        "errno": 0,
                        "list": [{
                            "path": target,
                            "size": bytes.len(),
                            "md5": md5_hex(bytes),
                            "dlink": format!("http://{host}/dlink{target}"),
                        }],
                    });
                    (200, payload.to_string().into_bytes())
                }
            }
        }
        "precreate" => {
            if !token_accepted(&token, state) {
                return token_rejected();
            }
            let form = parse_query(&String::from_utf8_lossy(
                &state.seen.lock().unwrap().last().unwrap().body,
            ));
            (
                200,
                serde_json::json!({
                    "errno": 0,
                    "path": form.get("path").cloned().unwrap_or_default(),
                    "uploadid": "UP-1",
                })
                .to_string()
                .into_bytes(),
            )
        }
        "superfile" => {
            if !token_accepted(&token, state) {
                return token_rejected();
            }
            let seen = state.seen.lock().unwrap();
            let request = seen.last().unwrap();
            let content_type = request.content_type.clone().unwrap_or_default();
            let path = query.get("path").cloned().unwrap_or_default();
            let partseq: usize = query.get("partseq").and_then(|s| s.parse().ok()).unwrap_or(0);
            drop(seen);
            match extract_multipart_file(&content_type, &state.seen.lock().unwrap().last().unwrap().body)
            {
                Some(content) => {
                    state
                        .uploading
                        .lock()
                        .unwrap()
                        .insert((path, partseq), content);
                    (200, br#"{"errno":0}"#.to_vec())
                }
                None => (400, br#"{"errno":-65}"#.to_vec()),
            }
        }
        "create" => {
            if !token_accepted(&token, state) {
                return token_rejected();
            }
            let form = parse_query(&String::from_utf8_lossy(
                &state.seen.lock().unwrap().last().unwrap().body,
            ));
            let path = form.get("path").cloned().unwrap_or_default();
            let mut parts: Vec<(usize, Vec<u8>)> = state
                .uploading
                .lock()
                .unwrap()
                .iter()
                .filter(|((target, _), _)| *target == path)
                .map(|((_, seq), bytes)| (*seq, bytes.clone()))
                .collect();
            parts.sort_by_key(|(seq, _)| *seq);
            let joined: Vec<u8> = parts.into_iter().flat_map(|(_, bytes)| bytes).collect();
            state.files.lock().unwrap().insert(path, joined.clone());
            (
                200,
                serde_json::json!({"errno": 0, "md5": md5_hex(&joined)}).to_string().into_bytes(),
            )
        }
        other => (400, format!(r#"{{"errno":-99,"method":"{other}"}}"#).into_bytes()),
    }
}

fn filemanager_endpoint(query: &HashMap<String, String>, state: &StubState) -> (u16, Vec<u8>) {
    let token = query.get("access_token").cloned().unwrap_or_default();
    if !token_accepted(&token, state) {
        return token_rejected();
    }
    let filelist: Vec<String> = query
        .get("filelist")
        .and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or_default();
    let mut files = state.files.lock().unwrap();
    let mut removed_any = false;
    for path in filelist {
        removed_any |= files.remove(&path).is_some();
    }
    if removed_any {
        (200, br#"{"errno":0}"#.to_vec())
    } else {
        // 12 = file does not exist (delete stays idempotent).
        (200, br#"{"errno":12}"#.to_vec())
    }
}

fn token_endpoint(query: &HashMap<String, String>, state: &StubState) -> (u16, Vec<u8>) {
    match query.get("grant_type").map(String::as_str).unwrap_or("") {
        "authorization_code" => {
            let code_ok = query.get("code").map(String::as_str) == Some("good-code");
            let client_ok = query.get("client_id").map(String::as_str) == Some("test-app-key")
                && query.get("client_secret").map(String::as_str) == Some("test-secret-key")
                && query.get("redirect_uri").map(String::as_str) == Some("http://127.0.0.1:17777/");
            if code_ok && client_ok {
                state
                    .issued
                    .lock()
                    .unwrap()
                    .push(("AT-CODE".to_string(), "RT-CODE".to_string()));
                (
                    200,
                    br#"{"access_token":"AT-CODE","refresh_token":"RT-CODE","expires_in":3600}"#
                        .to_vec(),
                )
            } else {
                (400, br#"{"error":"bad_verification_code"}"#.to_vec())
            }
        }
        "refresh_token" => {
            if state.fail_refresh.load(Ordering::SeqCst) {
                return (400, br#"{"error":"invalid_grant"}"#.to_vec());
            }
            let issued = state.issued.lock().unwrap();
            let current = issued.last().expect("stub always seeds a token").clone();
            drop(issued);
            if query.get("refresh_token").map(String::as_str) != Some(current.1.as_str()) {
                return (400, br#"{"error":"invalid_grant"}"#.to_vec());
            }
            let generation = {
                let mut issued = state.issued.lock().unwrap();
                let next = issued.len() + 1;
                issued.push((format!("AT{next}"), format!("RT{next}")));
                issued.len()
            };
            (
                200,
                serde_json::json!({
                    "access_token": format!("AT{generation}"),
                    "refresh_token": format!("RT{generation}"),
                    "expires_in": 3600,
                })
                .to_string()
                .into_bytes(),
            )
        }
        _ => (400, br#"{"error":"unsupported_grant_type"}"#.to_vec()),
    }
}

// ---------------------------------------------------------------------------
// Stub helpers
// ---------------------------------------------------------------------------

/// Parse `a=1&b=2` (URL query or urlencoded form) with percent-decoding.
fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode_component(key), decode_component(value))
        })
        .collect()
}

fn decode_component(value: &str) -> String {
    super::baidu_oauth::percent_decode(&value.replace('+', " "))
}

/// Extract the single `file` part body from a multipart/form-data request.
fn extract_multipart_file(content_type: &str, body: &[u8]) -> Option<Vec<u8>> {
    const MARKER: &str = "boundary=";
    let index = content_type.find(MARKER)? + MARKER.len();
    let boundary = content_type[index..].trim().trim_matches('"');
    let delimiter = format!("--{boundary}");
    let head = find_subslice(body, delimiter.as_bytes())? + delimiter.len();
    let content_start = find_subslice(&body[head..], b"\r\n\r\n")? + head + 4;
    let content_end =
        find_subslice(&body[content_start..], format!("\r\n{delimiter}").as_bytes())? + content_start;
    Some(body[content_start..content_end].to_vec())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

pub(crate) fn token_bytes(access: &str, refresh: &str) -> Vec<u8> {
    serde_json::json!({
        "access_token": access,
        "refresh_token": refresh,
        "expires_at": 4_102_444_800i64, // far future (2100)
    })
    .to_string()
    .into_bytes()
}

pub(crate) fn stub_with_files(files: Vec<(&str, &[u8])>) -> (String, Arc<StubState>, mpsc::Sender<()>) {
    let state = Arc::new(StubState {
        issued: Mutex::new(vec![("AT1".to_string(), "RT1".to_string())]),
        ..StubState::default()
    });
    {
        let mut map = state.files.lock().unwrap();
        for (path, bytes) in files {
            map.insert(baidu_path(path), bytes.to_vec());
        }
    }
    let (base, server) = spawn_stub(Arc::clone(&state));
    (base, state, server)
}

fn make_backend(base: &str) -> (BaiduBackend, Arc<MemorySecretStore>) {
    let store = Arc::new(MemorySecretStore::new());
    store
        .set(SYNC_BAIDU_TOKEN_ACCOUNT, &token_bytes("AT1", "RT1"))
        .unwrap();
    let backend = BaiduBackend::with_endpoints(
        base,
        base,
        "test-app-key",
        "test-secret-key",
        store.clone(),
    );
    (backend, store)
}

pub(crate) fn error_code(err: &VaultError) -> &str {
    match err {
        VaultError::InvalidInput { code, .. } => code,
        other => panic!("unexpected error variant: {other}"),
    }
}

/// A primed, unlocked device — own redb file, weak KDF (fast tests), memory
/// credential stores, session unlocked directly (same shape as the engine
/// tests' `test_state`).
pub(crate) fn primed_state() -> (Arc<AppState>, tempfile::TempDir) {
    use pwdvault_infrastructure::crypto::kdf::{derive_key_with_params, derive_subkeys, AdaptiveParams};
    use pwdvault_infrastructure::database::{self, vault_store::{self, VaultStore}};

    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(database::init_database(dir.path().join("baidu-sync.db")).unwrap());
    let salt = [0x2A; 16];
    let params = AdaptiveParams { m_cost: 16384, t_cost: 1, p_cost: 1 };
    let (master_key, _) =
        derive_key_with_params("sync-test-password", &salt, &params).unwrap();
    let verification = pwdvault_infrastructure::crypto::create_verification_header(
        &master_key, salt, params,
    )
    .unwrap();
    let (enc_key, mac_key) = derive_subkeys(&master_key, &salt);

    VaultStore::new(&db)
        .write(&mac_key, |txn| {
            vault_store::save_verification_data_in_txn(txn, &verification)?;
            pwdvault_infrastructure::vault_header::save_header_in_txn(
                txn,
                &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
                &enc_key,
            )?;
            vault_store::save_settings_in_txn(txn, &pwdvault_domain::Settings::default())?;
            Ok(())
        })
        .unwrap();

    let state = Arc::new(AppState {
        secret_store: Arc::new(MemorySecretStore::new()) as Arc<dyn SecretStore>,
        sync_secret_store: Arc::new(MemorySecretStore::new()) as Arc<dyn SecretStore>,
        ..AppState::default()
    });
    *state.database.lock().unwrap() = Some(db);
    *state.verification_data.lock().unwrap() = Some(verification);
    state.session.unlock(enc_key, mac_key);
    (state, dir)
}

// ---------------------------------------------------------------------------
// File API: stat / download / conditional upload / refresh / delete
// ---------------------------------------------------------------------------

/// stat reports the sibling manifest rev as the conditional-write token
/// (D4), the true size, and Ok(None) for missing files.
#[test]
fn stat_reports_manifest_rev_token_and_missing_files() {
    let (base, _state, _server) = stub_with_files(vec![
        (CONTAINER_PATH, b"container-bytes".as_slice()),
        (manifest_rel_path(), MANIFEST_BODY),
    ]);
    let (backend, _store) = make_backend(&base);

    let stat = backend.stat(CONTAINER_PATH).unwrap().unwrap();
    assert_eq!(stat.etag.as_deref(), Some("rev:5"));
    assert_eq!(stat.size, "container-bytes".len() as u64);

    assert!(backend.stat("apps/testdir/absent.pwsync").unwrap().is_none());
}

/// Without a manifest there is no token (degraded mode — the engine then
/// runs its own manifest-rev check or writes unconditionally).
#[test]
fn stat_without_manifest_has_no_etag_token() {
    let (base, _state, _server) = stub_with_files(vec![(CONTAINER_PATH, b"bytes".as_slice())]);
    let (backend, _store) = make_backend(&base);
    let stat = backend.stat(CONTAINER_PATH).unwrap().unwrap();
    assert_eq!(stat.etag, None);
    assert_eq!(stat.size, 5);
}

/// download = filemetas → dlink GET; the dlink hop requires User-Agent.
#[test]
fn download_follows_dlink_with_user_agent() {
    let (base, state, _server) = stub_with_files(vec![(CONTAINER_PATH, b"payload".as_slice())]);
    let (backend, _store) = make_backend(&base);

    assert_eq!(backend.download(CONTAINER_PATH).unwrap(), b"payload".to_vec());

    let seen = state.seen.lock().unwrap();
    let dlink_hits: Vec<&SeenRequest> =
        seen.iter().filter(|r| r.url.starts_with("/dlink/")).collect();
    assert_eq!(dlink_hits.len(), 1, "expected exactly one dlink GET");
    assert_eq!(dlink_hits[0].user_agent.as_deref(), Some(EXPECTED_UA));
    // The filemetas request carries the path parameter and dlink=1.
    let metas: Vec<&SeenRequest> =
        seen.iter().filter(|r| r.url.contains("method=filemetas")).collect();
    assert_eq!(metas.len(), 1);
    assert!(metas[0].url.contains("method=filemetas"));
    assert!(metas[0].url.contains("dlink=1"));
    // encode_value percent-encodes the slashes of the Baidu-absolute path.
    assert!(metas[0].url.contains(&format!("path={}", super::baidu::encode_value(&baidu_path(CONTAINER_PATH)))));
}

/// Unconditional upload: precreate (path/size/block_list) → superfile
/// (multipart, partseq) → create → post-upload stat verification.
#[test]
fn unconditional_upload_slices_then_verifies() {
    let (base, state, _server) = stub_with_files(vec![]);
    let (backend, _store) = make_backend(&base);
    let body = vec![0xA5u8; 5000];

    backend
        .upload(CONTAINER_PATH, &body, Precondition::Unconditional)
        .unwrap();

    // Content landed on the (simulated) disk.
    assert_eq!(
        state.files.lock().unwrap().get(&baidu_path(CONTAINER_PATH)).unwrap(),
        &body
    );

    let seen = state.seen.lock().unwrap();
    let urls: Vec<&str> = seen.iter().map(|r| r.url.as_str()).collect();
    assert!(
        matches!(&urls[..], [a, b, c, d]
            if a.contains("method=precreate")
                && b.contains("method=superfile")
                && c.contains("method=create")
                && d.contains("method=filemetas")),
        "expected precreate → superfile → create → verify, got {urls:?}"
    );

    // precreate wire shape.
    let form = parse_query(std::str::from_utf8(&seen[0].body).unwrap());
    assert_eq!(form.get("path").unwrap(), &baidu_path(CONTAINER_PATH));
    assert_eq!(form.get("size").unwrap(), "5000");
    assert_eq!(form.get("isdir").unwrap(), "0");
    assert!(
        form.get("block_list").unwrap().contains(&md5_hex(&body)),
        "block_list must carry the slice md5"
    );
    assert!(seen[1].url.contains("uploadid=UP-1"), "superfile must carry the upload id");
    assert!(seen[1].url.contains("partseq=0"));
    assert!(
        seen[1].content_type.as_deref().unwrap_or("").starts_with("multipart/form-data; boundary="),
        "superfile must be multipart: {:?}",
        seen[1].content_type
    );
    let create_form = parse_query(std::str::from_utf8(&seen[2].body).unwrap());
    assert_eq!(create_form.get("uploadid").unwrap(), "UP-1");
    assert_eq!(create_form.get("isdir").unwrap(), "0");
    assert!(create_form.get("mtime").is_some(), "create must sync mtime (plan P3.4)");
}

/// Bodies larger than 4 MiB are split into ordered slices and reassembled.
#[test]
fn upload_splits_large_bodies_into_ordered_slices() {
    let (base, state, _server) = stub_with_files(vec![]);
    let (backend, _store) = make_backend(&base);
    let body: Vec<u8> = (0..(SLICE_SIZE + 100)).map(|index| (index % 251) as u8).collect();

    backend
        .upload(CONTAINER_PATH, &body, Precondition::Unconditional)
        .unwrap();

    let seen = state.seen.lock().unwrap();
    let superfiles: Vec<&SeenRequest> = seen
        .iter()
        .filter(|r| r.url.contains("method=superfile"))
        .collect();
    assert_eq!(superfiles.len(), 2, "4 MiB + 100 bytes must split into 2 slices");
    assert!(superfiles[0].url.contains("partseq=0"));
    assert!(superfiles[1].url.contains("partseq=1"));
    assert_eq!(
        state.files.lock().unwrap().get(&baidu_path(CONTAINER_PATH)).unwrap(),
        &body,
        "slices must reassemble in partseq order"
    );
}

/// The simulated If-Match (D4): the current manifest rev passes, a stale
/// rev (or a foreign token) Conflicts BEFORE any upload step; IfAbsent
/// fails on existing files and creates missing ones.
#[test]
fn conditional_upload_guarded_by_manifest_rev() {
    let (base, state, _server) = stub_with_files(vec![(manifest_rel_path(), MANIFEST_BODY)]);
    let (backend, _store) = make_backend(&base);

    backend
        .upload(CONTAINER_PATH, b"v2", Precondition::IfMatch("rev:5".into()))
        .unwrap();
    assert!(matches!(
        backend.upload(CONTAINER_PATH, b"v3", Precondition::IfMatch("rev:4".into())),
        Err(BackendError::Conflict)
    ));
    let foreign = backend.upload(CONTAINER_PATH, b"v3", Precondition::IfMatch("not-a-rev".into()));
    assert!(
        matches!(foreign, Err(BackendError::Conflict)),
        "foreign tokens (e.g. WebDAV ETags) must fail closed"
    );

    // The manifest rev comparison ran BEFORE the first upload step.
    let seen = state.seen.lock().unwrap();
    let manifest_read = seen
        .iter()
        .position(|r| {
            r.url.contains("method=filemetas")
                && r.url.contains(&super::baidu::encode_value(&baidu_path(manifest_rel_path())))
        })
        .expect("guard must stat the manifest");
    let first_precreate = seen.iter().position(|r| r.url.contains("method=precreate")).unwrap();
    assert!(manifest_read < first_precreate, "guard must run before precreate");
    // The stale-rev attempts never reached precreate (fail-closed guard).
    assert_eq!(
        seen.iter().filter(|r| r.url.contains("method=precreate")).count(),
        1,
        "conflicting uploads must be rejected before the upload chain"
    );
    drop(seen);

    // IfAbsent: existing → Conflict; missing → creates.
    assert!(matches!(
        backend.upload(CONTAINER_PATH, b"x", Precondition::IfAbsent),
        Err(BackendError::Conflict)
    ));
    backend
        .upload("apps/testdir/new.pwsync", b"created", Precondition::IfAbsent)
        .unwrap();
    assert_eq!(
        state
            .files
            .lock()
            .unwrap()
            .get(&baidu_path("apps/testdir/new.pwsync"))
            .unwrap(),
        b"created"
    );
}

/// upload_unique writes without any precondition (unique names, D4).
#[test]
fn upload_unique_writes_unconditionally() {
    let (base, state, _server) = stub_with_files(vec![(manifest_rel_path(), MANIFEST_BODY)]);
    let (backend, _store) = make_backend(&base);
    backend
        .upload_unique("apps/testdir/history/pwdvault-sync-r6.pwsync", b"snapshot")
        .unwrap();
    assert_eq!(
        state
            .files
            .lock()
            .unwrap()
            .get(&baidu_path("apps/testdir/history/pwdvault-sync-r6.pwsync"))
            .unwrap(),
        b"snapshot"
    );
}

/// Token rejection (errno -6) refreshes ONCE with the current refresh token
/// and retries with the rotated pair, which is persisted.
#[test]
fn expired_token_refreshes_once_and_retries() {
    let (base, state, _server) = stub_with_files(vec![(CONTAINER_PATH, b"payload".as_slice())]);
    let (backend, store) = make_backend(&base);
    state.expire_next_filemetas.store(true, Ordering::SeqCst);

    assert_eq!(backend.download(CONTAINER_PATH).unwrap(), b"payload".to_vec());

    let seen = state.seen.lock().unwrap();
    let refreshes: Vec<&SeenRequest> = seen
        .iter()
        .filter(|r| r.url.contains("grant_type=refresh_token"))
        .collect();
    assert_eq!(refreshes.len(), 1, "exactly one refresh");
    assert!(refreshes[0].url.contains("refresh_token=RT1"), "must use the CURRENT refresh token");
    assert!(refreshes[0].url.contains("client_id=test-app-key"));

    let metas: Vec<&SeenRequest> =
        seen.iter().filter(|r| r.url.contains("method=filemetas")).collect();
    assert_eq!(metas.len(), 2);
    assert!(metas[0].url.contains("access_token=AT1"), "first try used the stale token");
    assert!(metas[1].url.contains("access_token=AT2"), "retry must use the rotated token");
    drop(seen);

    // The rotated pair was persisted to the credential store.
    let stored: serde_json::Value =
        serde_json::from_slice(&store.get(SYNC_BAIDU_TOKEN_ACCOUNT).unwrap()).unwrap();
    assert_eq!(stored["access_token"], "AT2");
    assert_eq!(stored["refresh_token"], "RT2");
}

/// A failed refresh maps to BackendError::Auth and is not retried.
#[test]
fn failed_refresh_maps_to_auth() {
    let (base, state, _server) = stub_with_files(vec![(CONTAINER_PATH, b"payload".as_slice())]);
    let (backend, _store) = make_backend(&base);
    state.fail_refresh.store(true, Ordering::SeqCst);
    state.expire_next_filemetas.store(true, Ordering::SeqCst);

    let result = backend.download(CONTAINER_PATH);
    assert!(matches!(result, Err(BackendError::Auth(_))));
    let refreshes = state
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.url.contains("grant_type=refresh_token"))
        .count();
    assert_eq!(refreshes, 1, "no retry after a failed refresh");
}

/// Missing credentials (never linked) map to Auth, not Network.
#[test]
fn missing_token_maps_to_auth() {
    let (base, _state, _server) = stub_with_files(vec![]);
    let store = Arc::new(MemorySecretStore::new());
    let backend =
        BaiduBackend::with_endpoints(&base, &base, "test-app-key", "test-secret-key", store);
    assert!(matches!(backend.stat(CONTAINER_PATH), Err(BackendError::Auth(_))));
}

/// delete removes and is idempotent (errno 12 = already gone).
#[test]
fn delete_is_idempotent() {
    let (base, state, _server) = stub_with_files(vec![(CONTAINER_PATH, b"x".as_slice())]);
    let (backend, _store) = make_backend(&base);
    backend.delete(CONTAINER_PATH).unwrap();
    backend.delete(CONTAINER_PATH).unwrap();
    assert!(!state.files.lock().unwrap().contains_key(&baidu_path(CONTAINER_PATH)));
    let seen = state.seen.lock().unwrap();
    let deletes: Vec<&SeenRequest> = seen
        .iter()
        .filter(|r| r.url.contains("/rest/2.0/xpan/filemanager"))
        .collect();
    assert_eq!(deletes.len(), 2);
    assert!(
        deletes[0].url.contains(&format!(
            "filelist={}",
            super::baidu::encode_value(&format!(r#"["{}"]"#, baidu_path(CONTAINER_PATH)))
        )),
        "filelist must carry the JSON-encoded path"
    );
}

/// Baidu config shares the remote-layout validation (traversal rejected)
/// even though the WebDAV URL check does not apply; a valid dir connects
/// through the injected backend end to end (backend doubles stay
/// independent: the engine never needs the real adapter for this path).
#[test]
fn baidu_config_validation_and_connect_through_injected_backend() {
    let (state, _dir) = primed_state();
    let mut config = SyncConfig {
        enabled: true,
        backend: SyncBackendKind::Baidu,
        server_url: String::new(), // unused for Baidu — must stay valid
        remote_dir: "../evil".to_string(),
        username: String::new(),
    };
    let cloud = MockCloudBackend::new();
    let err = sync_connect_with_backend(
        &state,
        &cloud,
        config.clone(),
        Zeroizing::new("container-passphrase".into()),
        None,
    )
    .unwrap_err();
    assert_eq!(error_code(&err), "SYNC_INVALID_CONFIG");

    config.remote_dir = "apps/testdir".to_string();
    let status = sync_connect_with_backend(
        &state,
        &cloud,
        config,
        Zeroizing::new("container-passphrase".into()),
        None,
    )
    .unwrap();
    assert_eq!(status.backend.as_deref(), Some("baidu"));
    assert!(status.enabled);
    assert_eq!(status.last_result.as_deref(), Some("ok"));
}
