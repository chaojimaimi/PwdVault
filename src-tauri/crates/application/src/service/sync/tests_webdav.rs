//! P3.6 item 5: WebDAV backend against a hand-written tiny_http stub.
//!
//! The stub speaks just enough DAV to pin the wire contract: PROPFIND
//! (207 multistatus / 404), GET, PUT with If-Match (412 on stale etag) and
//! If-None-Match:* (412 on existing, 409 into a missing collection), MKCOL
//! (405 on existing), DELETE. All requests echo the Authorization header
//! into the seen-log so the Basic-Auth wiring is asserted too.

use std::collections::{HashMap, HashSet};
use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

use super::backend::{BackendError, CloudBackend, Precondition, WebDavBackend};

/// What the stub saw for one request (for assertions on the wire format).
#[derive(Debug, Clone)]
struct SeenRequest {
    method: String,
    uri: String,
    if_match: Option<String>,
    if_none_match: Option<String>,
    depth: Option<String>,
    authorization: Option<String>,
}

struct StubState {
    files: FilesMap,
    dirs: Mutex<HashSet<String>>,
    seen: SeenLog,
}

type SeenLog = Arc<Mutex<Vec<SeenRequest>>>;
type FilesMap = Arc<Mutex<HashMap<String, (Vec<u8>, String)>>>;

/// Boot a tiny_http DAV stub on an ephemeral loopback port. Returns
/// (base_url, seen log, files map). The server thread self-terminates on its
/// next poll after this function returns (the shutdown sender is dropped).
fn spawn_stub() -> (String, SeenLog, FilesMap) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let server = tiny_http::Server::from_listener(listener, None).expect("tiny_http server");
    let state = Arc::new(StubState {
        files: Arc::new(Mutex::new(HashMap::new())),
        dirs: Mutex::new(HashSet::new()),
        seen: Arc::new(Mutex::new(Vec::new())),
    });

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    drop(shutdown_tx); // dropping the sender is the shutdown signal
    let seen = state.seen.clone();
    let files = state.files.clone();
    // Detached: the loop self-terminates on its next poll (~25 ms) after
    // this function returns and the shutdown sender is dropped.
    let _handle = thread::spawn(move || loop {
        match server.recv_timeout(Duration::from_millis(25)) {
            Ok(Some(request)) => handle_request(request, &state),
            Ok(None) => {
                // Sender dropped (or explicit signal) ends the loop.
                if shutdown_rx.try_recv() != Err(mpsc::TryRecvError::Empty) {
                    break;
                }
            }
            Err(_) => break,
        }
    });

    (format!("http://127.0.0.1:{port}"), seen, files)
}

fn handle_request(mut request: tiny_http::Request, state: &StubState) {
    let method = request.method().to_string();
    let url = request.url().to_string();
    // Drain the body BEFORE capturing headers: as_reader takes a mutable
    // borrow, the header scan an immutable one.
    let mut body = Vec::new();
    let _ = request.as_reader().read_to_end(&mut body);
    let header = |name: &str| -> Option<String> {
        request
            .headers()
            .iter()
            .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str().to_string())
    };

    let path = url
        .split('?')
        .next()
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    state.seen.lock().unwrap().push(SeenRequest {
        method: method.clone(),
        uri: format!("/{path}"),
        if_match: header("If-Match"),
        if_none_match: header("If-None-Match"),
        depth: header("Depth"),
        authorization: header("Authorization"),
    });

    // Validate the Basic credentials for real (user:password echo of the
    // expected pair) so wrong-password runs surface as 401.
    const EXPECTED_AUTH: &str = "Basic dXNlckBleGFtcGxlLmNvbTpkYXYtcGFzc3dvcmQ=";
    let auth_ok = header("Authorization").as_deref() == Some(EXPECTED_AUTH);

    let (status, etag_header, response_body): (u16, Option<String>, Vec<u8>) = if !auth_ok {
        (401, None, b"unauthorized".to_vec())
    } else {
        match method.as_str() {
            "PROPFIND" => {
                let files = state.files.lock().unwrap();
                match files.get(&path) {
                    None => {
                        // 坚果云-style servers answer 409 (not 404) when an
                        // ANCESTOR collection of the path is missing — the
                        // exact first-connect situation before the remote
                        // directory exists.
                        let parent_missing = path
                            .rsplit_once('/')
                            .map(|(parent, _)| !state.dirs.lock().unwrap().contains(parent))
                            .unwrap_or(false);
                        if parent_missing {
                            (409, None, b"ancestor missing".to_vec())
                        } else {
                            (404, None, b"not found".to_vec())
                        }
                    }
                    Some((file_body, etag)) => {
                        // Namespace-style tag matching real servers (nginx
                        // apache props): prefix differs from the DAV one.
                        let xml = format!(
                            "<?xml version=\"1.0\"?>\
                             <D:multistatus xmlns:D=\"DAV:\" xmlns:lp1=\"http://apache.org/dav/props/\">\
                             <D:response><D:propstat><D:prop>\
                             <lp1:getetag>{etag}</lp1:getetag>\
                             <lp1:getcontentlength>{len}</lp1:getcontentlength>\
                             </D:prop></D:propstat></D:response></D:multistatus>",
                            etag = etag,
                            len = file_body.len()
                        );
                        (207, None, xml.into_bytes())
                    }
                }
            }
            "GET" => {
                let files = state.files.lock().unwrap();
                match files.get(&path) {
                    None => (404, None, b"not found".to_vec()),
                    Some((file_body, _)) => (200, None, file_body.clone()),
                }
            }
            "PUT" => {
                let parent_missing = path
                    .rsplit_once('/')
                    .map(|(parent, _)| !state.dirs.lock().unwrap().contains(parent))
                    .unwrap_or(false);
                if parent_missing {
                    // Most WebDAV servers refuse PUTs into collections
                    // that do not exist.
                    (409, None, b"missing parent collection".to_vec())
                } else {
                    let mut files = state.files.lock().unwrap();
                    if let Some(expected) = header("If-Match") {
                        let current = files.get(&path).map(|(_, e)| e.clone());
                        if current.as_deref() != Some(expected.as_str()) {
                            (412, None, b"precondition failed".to_vec())
                        } else {
                            let next = format!("{expected}-next");
                            files.insert(path, (body, next.clone()));
                            (204, Some(next), b"".to_vec())
                        }
                    } else if header("If-None-Match").as_deref() == Some("*") {
                        use std::collections::hash_map::Entry;
                        match files.entry(path) {
                            Entry::Occupied(_) => (412, None, b"already exists".to_vec()),
                            Entry::Vacant(slot) => {
                                slot.insert((body, "\"created-1\"".to_string()));
                                (201, Some("\"created-1\"".to_string()), b"".to_vec())
                            }
                        }
                    } else {
                        let next = match files.get(&path).map(|(_, e)| e.clone()) {
                            Some(prev) => format!("{prev}-next"),
                            None => "\"created-1\"".to_string(),
                        };
                        files.insert(path, (body, next.clone()));
                        (204, Some(next), b"".to_vec())
                    }
                }
            }
            "MKCOL" => {
                let mut dirs = state.dirs.lock().unwrap();
                if dirs.contains(&path) {
                    (405, None, b"collection exists".to_vec())
                } else {
                    dirs.insert(path);
                    (201, None, b"".to_vec())
                }
            }
            "DELETE" => {
                let mut files = state.files.lock().unwrap();
                match files.remove(&path) {
                    Some(_) => (204, None, b"".to_vec()),
                    None => (404, None, b"not found".to_vec()),
                }
            }
            _ => (405, None, b"method not allowed".to_vec()),
        }
    };

    let mut response = tiny_http::Response::from_data(response_body).with_status_code(status);
    if let Some(etag) = etag_header {
        response.add_header(tiny_http::Header::from_bytes(&b"ETag"[..], etag.as_bytes()).unwrap());
    }
    let _ = request.respond(response);
}

fn make_backend(base_url: &str) -> WebDavBackend {
    WebDavBackend::new(
        base_url,
        "user@example.com",
        Zeroizing::new("dav-password".to_string()),
    )
    .unwrap()
}

/// PROPFIND stat: 207 XML is parsed into etag + size; a missing file is
/// `Ok(None)`; the Depth:0 header and Basic auth went out on the wire.
#[test]
fn webdav_stat_parses_propfind_and_reports_missing() {
    let (base_url, seen, files) = spawn_stub();
    files.lock().unwrap().insert(
        "vault/pwdvault-sync.pwsync".to_string(),
        (b"0123456789".to_vec(), "\"etag-7\"".to_string()),
    );
    let backend = make_backend(&base_url);

    let stat = backend.stat("vault/pwdvault-sync.pwsync").unwrap().unwrap();
    assert_eq!(stat.etag.as_deref(), Some("\"etag-7\""));
    assert_eq!(stat.size, 10);

    let requests = seen.lock().unwrap();
    let propfind = requests
        .iter()
        .find(|r| r.method == "PROPFIND")
        .expect("PROPFIND sent");
    assert_eq!(propfind.uri, "/vault/pwdvault-sync.pwsync");
    assert_eq!(propfind.depth.as_deref(), Some("0"));
    assert_eq!(
        propfind.authorization.as_deref(),
        Some("Basic dXNlckBleGFtcGxlLmNvbTpkYXYtcGFzc3dvcmQ=")
    );
    drop(requests);

    assert!(backend.stat("vault/missing.pwsync").unwrap().is_none());
}

/// GET download roundtrip; 404 surfaces as a Network error.
#[test]
fn webdav_download_roundtrip() {
    let (base_url, _seen, files) = spawn_stub();
    files.lock().unwrap().insert(
        "vault/c.pwsync".to_string(),
        (b"container-bytes".to_vec(), "\"e1\"".to_string()),
    );
    let backend = make_backend(&base_url);

    assert_eq!(
        backend.download("vault/c.pwsync").unwrap(),
        b"container-bytes".to_vec()
    );
    assert!(matches!(
        backend.download("vault/missing.pwsync"),
        Err(BackendError::Network(_))
    ));
}

/// 坚果云-style first connect: PROPFIND answers 409 (ancestor collection
/// missing) instead of 404 — stat must map that to "absent" so the engine
/// proceeds to bootstrap (the upload then MKCOLs the directory).
#[test]
fn webdav_stat_409_on_missing_ancestor_is_absent() {
    let (base_url, _seen, _files) = spawn_stub();
    let backend = make_backend(&base_url);
    assert_eq!(backend.stat("vault/c.pwsync").unwrap(), None);
}

/// PUT If-Match: fresh etag overwrites; stale etag → BackendError::Conflict
/// (the 412 mapping the engine's retry loop depends on); bad credentials →
/// Auth. The wire log must show the If-Match header going out verbatim.
#[test]
fn webdav_put_if_match_maps_412_to_conflict() {
    let (base_url, seen, files) = spawn_stub();
    files.lock().unwrap().insert(
        "vault/c.pwsync".to_string(),
        (b"old".to_vec(), "\"etag-1\"".to_string()),
    );
    let backend = make_backend(&base_url);

    backend
        .upload(
            "vault/c.pwsync",
            b"new",
            Precondition::IfMatch("\"etag-1\"".to_string()),
        )
        .unwrap();
    assert_eq!(
        files.lock().unwrap().get("vault/c.pwsync").unwrap().0,
        b"new".to_vec()
    );

    // The stale etag (what another device already replaced) must Conflict.
    let result = backend.upload(
        "vault/c.pwsync",
        b"loser",
        Precondition::IfMatch("\"etag-1\"".to_string()),
    );
    assert!(matches!(result, Err(BackendError::Conflict)));

    // The wire log must show the PUTs carrying the If-Match precondition
    // verbatim (transport-level retries may duplicate entries — count-agnostic).
    let puts: Vec<Option<String>> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.method == "PUT")
        .map(|r| r.if_match.clone())
        .collect();
    assert!(puts.len() >= 2, "expected at least two PUTs, got {puts:?}");
    assert!(
        puts.iter().all(|h| h.as_deref() == Some("\"etag-1\"")),
        "every PUT must carry If-Match: \"etag-1\", got {puts:?}"
    );

    // Bad credentials map to Auth.
    let bad = WebDavBackend::new(
        &base_url,
        "user@example.com",
        Zeroizing::new("wrong".to_string()),
    )
    .unwrap();
    assert!(matches!(
        bad.upload(
            "vault/c.pwsync",
            b"x",
            Precondition::IfMatch("\"etag-1\"".to_string())
        ),
        Err(BackendError::Auth(_))
    ));
}

/// If-None-Match:* create semantics: first upload creates, second →
/// Conflict (bootstrap race — exactly one device wins, D4).
#[test]
fn webdav_put_if_absent_create_semantics() {
    let (base_url, seen, _files) = spawn_stub();
    let backend = make_backend(&base_url);

    backend
        .upload(
            "vault/pwdvault-sync.pwsync",
            b"first",
            Precondition::IfAbsent,
        )
        .unwrap();
    assert!(matches!(
        backend.upload(
            "vault/pwdvault-sync.pwsync",
            b"second",
            Precondition::IfAbsent
        ),
        Err(BackendError::Conflict)
    ));

    // Wire check: If-None-Match: * (the D4 create semantics) went out.
    let none_matches: Vec<Option<String>> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.method == "PUT")
        .map(|r| r.if_none_match.clone())
        .collect();
    assert!(
        none_matches.len() >= 2,
        "expected at least two PUTs, got {none_matches:?}"
    );
    assert!(
        none_matches.iter().all(|h| h.as_deref() == Some("*")),
        "every PUT must carry If-None-Match: *, got {none_matches:?}"
    );
}

/// PUT into a missing collection gets 409 from the stub; the backend then
/// MKCOLs the ancestors (405 on existing is ignored) and retries.
#[test]
fn webdav_put_creates_missing_collection_via_mkcol() {
    let (base_url, seen, files) = spawn_stub();
    let backend = make_backend(&base_url);

    backend
        .upload_unique("deep/dir/hist.pwsync", b"history")
        .unwrap();
    assert_eq!(
        files.lock().unwrap().get("deep/dir/hist.pwsync").unwrap().0,
        b"history".to_vec()
    );
    let mkcols: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.method == "MKCOL")
        .map(|r| r.uri.clone())
        .collect();
    assert!(
        mkcols.contains(&"/deep".to_string()),
        "expected MKCOL for /deep, got {mkcols:?}"
    );
    assert!(mkcols.contains(&"/deep/dir".to_string()));

    // upload_unique writes unconditionally (unique names cannot conflict).
    backend
        .upload_unique("deep/dir/hist2.pwsync", b"h2")
        .unwrap();
    assert_eq!(
        files
            .lock()
            .unwrap()
            .get("deep/dir/hist2.pwsync")
            .unwrap()
            .0,
        b"h2".to_vec()
    );

    // DELETE removes and is idempotent.
    backend.delete("deep/dir/hist2.pwsync").unwrap();
    backend.delete("deep/dir/hist2.pwsync").unwrap();
    assert!(backend.stat("deep/dir/hist2.pwsync").unwrap().is_none());
}
