//! Baidu backend flow tests (upload slicing, conditional writes, token
//! refresh, end-to-end connect) — harness lives in [`super::tests_baidu`].

use std::sync::atomic::Ordering;
use std::sync::Arc;

use zeroize::Zeroizing;

use super::backend::CloudBackend as _;
use super::backend::{BackendError, MockCloudBackend, Precondition};
use super::baidu::BaiduBackend;
use super::engine::{sync_connect_with_backend, SyncBackendKind, SyncConfig};
use super::tests_baidu::*;
use pwdvault_infrastructure::keychain::{MemorySecretStore, SecretStore, SYNC_BAIDU_TOKEN_ACCOUNT};

/// Bodies larger than 4 MiB are split into ordered slices and reassembled.
#[test]
fn upload_splits_large_bodies_into_ordered_slices() {
    let (base, state, _server) = stub_with_files(vec![]);
    let (backend, _store) = make_backend(&base);
    let body: Vec<u8> = (0..(SLICE_SIZE + 100))
        .map(|index| (index % 251) as u8)
        .collect();

    backend
        .upload(CONTAINER_PATH, &body, Precondition::Unconditional)
        .unwrap();

    let seen = state.seen.lock().unwrap();
    let superfiles: Vec<&SeenRequest> = seen
        .iter()
        .filter(|r| r.url.contains("method=superfile"))
        .collect();
    assert_eq!(
        superfiles.len(),
        2,
        "4 MiB + 100 bytes must split into 2 slices"
    );
    assert!(superfiles[0].url.contains("partseq=0"));
    assert!(superfiles[1].url.contains("partseq=1"));
    assert_eq!(
        state
            .files
            .lock()
            .unwrap()
            .get(&baidu_path(CONTAINER_PATH))
            .unwrap(),
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
    let foreign = backend.upload(
        CONTAINER_PATH,
        b"v3",
        Precondition::IfMatch("not-a-rev".into()),
    );
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
                && r.url.contains(&super::baidu::encode_value(
                    &baidu_path(manifest_rel_path()),
                ))
        })
        .expect("guard must stat the manifest");
    let first_precreate = seen
        .iter()
        .position(|r| r.url.contains("method=precreate"))
        .unwrap();
    assert!(
        manifest_read < first_precreate,
        "guard must run before precreate"
    );
    // The stale-rev attempts never reached precreate (fail-closed guard).
    assert_eq!(
        seen.iter()
            .filter(|r| r.url.contains("method=precreate"))
            .count(),
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
        .upload(
            "apps/testdir/new.pwsync",
            b"created",
            Precondition::IfAbsent,
        )
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

    assert_eq!(
        backend.download(CONTAINER_PATH).unwrap(),
        b"payload".to_vec()
    );

    let seen = state.seen.lock().unwrap();
    let refreshes: Vec<&SeenRequest> = seen
        .iter()
        .filter(|r| r.url.contains("grant_type=refresh_token"))
        .collect();
    assert_eq!(refreshes.len(), 1, "exactly one refresh");
    assert!(
        refreshes[0].url.contains("refresh_token=RT1"),
        "must use the CURRENT refresh token"
    );
    assert!(refreshes[0].url.contains("client_id=test-app-key"));

    let metas: Vec<&SeenRequest> = seen
        .iter()
        .filter(|r| r.url.contains("method=filemetas"))
        .collect();
    assert_eq!(metas.len(), 2);
    assert!(
        metas[0].url.contains("access_token=AT1"),
        "first try used the stale token"
    );
    assert!(
        metas[1].url.contains("access_token=AT2"),
        "retry must use the rotated token"
    );
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
    assert!(matches!(
        backend.stat(CONTAINER_PATH),
        Err(BackendError::Auth(_))
    ));
}

/// delete removes and is idempotent (errno 12 = already gone).
#[test]
fn delete_is_idempotent() {
    let (base, state, _server) = stub_with_files(vec![(CONTAINER_PATH, b"x".as_slice())]);
    let (backend, _store) = make_backend(&base);
    backend.delete(CONTAINER_PATH).unwrap();
    backend.delete(CONTAINER_PATH).unwrap();
    assert!(!state
        .files
        .lock()
        .unwrap()
        .contains_key(&baidu_path(CONTAINER_PATH)));
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
