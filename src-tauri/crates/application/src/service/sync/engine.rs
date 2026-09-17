//! P3.3 sync engine: the user-facing cycle ([`sync_connect`],
//! [`sync_now`], [`sync_disconnect`], [`sync_status`]) and the D8 exclusive
//! merge window.
//!
//! Model (D1/D2): the cloud holds ONE self-contained encrypted container
//! (`pwdvault-sync.pwsync`) plus a rev manifest and rolling history. The
//! container key (cek) is unwrapped once per device at connect (with the
//! container password) and then stored locally wrapped under the session
//! enc subkey (`sync_cek` row, AAD [`WRAP_AAD_SYNC`]) — later syncs need no
//! password and never touch the master key.
//!
//! Local writes follow the P3.1 precise D8 sequence: copy enc/mac out of
//! the session lease → drop the lease → `exclusive_lock_and_clear()` →
//! assert Locked → full read + merge + ONE `VaultStore::write` → republish
//! the COPIED keys (sync never rotates keys). All network I/O happens
//! strictly outside that window, including conflict retries (≤3).
//!
//! Ground I/O lives in [`super::state_io`] (rows + tunables, config/state
//! persistence, local read/write-back, session-key copies, helpers) and
//! [`super::publish`] (container pull/push, manifest, history). This file
//! is the orchestration (M-3 split of the former single-file engine —
//! pure move); the re-exports below keep the pre-split import paths
//! (`service::engine::…` in service/mod.rs, `super::engine::…` for the
//! sync module's adapters and tests) working unchanged.

// Pre-split import paths, preserved verbatim.
pub(crate) use super::state_io::backend_error;
pub use super::state_io::{
    StoredEnvelope, SyncBackendKind, SyncConfig, SyncState, SyncStatusResponse, CONTAINER_FILE,
    HISTORY_DIR, HISTORY_KEEP, MANIFEST_FILE, MAX_UPLOAD_ATTEMPTS, SYNC_CONFIG_BLOB_KEY,
    SYNC_STATE_BLOB_KEY,
};

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::service::security::SYNC_CEK_BLOB_KEY;
use crate::service::sync::backend::CloudBackend;
use crate::service::sync::container::{decrypt_snapshot_with_cek, read_envelope};
use crate::service::sync::merge::{merge_snapshots, MergedSnapshot};
use crate::service::sync::SyncSnapshot;
use crate::service::vault::get_db;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::crypto::{unwrap_secret, KEY_SIZE, WRAP_AAD_SYNC};
use pwdvault_infrastructure::database::vault_store::{self, VaultStore};
use pwdvault_infrastructure::keychain::{SYNC_BAIDU_TOKEN_ACCOUNT, SYNC_WEBDAV_PASSWORD_ACCOUNT};

use super::publish::{
    fetch_manifest, publish_snapshot, pull_or_bootstrap, update_manifest, PublishContext,
};
use super::state_io::{
    container_error, content_hash, load_config, load_sync_state, new_device_id, not_configured,
    now, open_backend, read_local_rows, remote_paths, save_sync_rows, sync_secret_error,
    validate_config, write_merged_back, SessionKeys,
};

// ---------------------------------------------------------------------------
// D8 window (P3.1 precise sequence)
// ---------------------------------------------------------------------------

/// The P3.1 exclusive window: drain leases, assert Locked, full local read +
/// merge + single-transaction write-back, then republish the copied keys.
/// `remote = None` means "no remote content to pull" (push-only cycle) —
/// the merge result is then the local state itself.
fn run_merge_window(
    state: &Arc<AppState>,
    keys: &mut SessionKeys,
    remote: Option<&SyncSnapshot>,
) -> Result<MergedSnapshot, VaultError> {
    // Drain every in-flight lease and refuse new ones.
    state.session.exclusive_lock_and_clear();
    // A concurrent password unlock slipping in between the drain and this
    // check must abort us cleanly — never proceed over a live session.
    if state.session.is_unlocked() {
        return Err(VaultError::VaultLocked);
    }

    let outcome = (|| -> Result<MergedSnapshot, VaultError> {
        let db = get_db(state)?;
        let local = read_local_rows(&db, keys.enc_bytes())?;
        let local_snapshot = SyncSnapshot {
            rev: 0,
            device_id: String::new(),
            generated_at: 0,
            entries: local.sync_entries.clone(),
            groups: local.sync_groups.clone(),
        };
        let merged = match remote {
            Some(remote_snapshot) => merge_snapshots(&local_snapshot, remote_snapshot),
            None => MergedSnapshot {
                entries: local.sync_entries.clone(),
                groups: local.sync_groups.clone(),
                changed: true,
            },
        };
        write_merged_back(&db, keys, &local, &merged)?;
        Ok(merged)
    })();

    // Republish the copied session keys exactly once (success or failure —
    // on failure the transaction rolled back, disk unchanged).
    keys.republish(state);
    state.touch_activity();
    outcome
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Bootstrap this device onto an existing (or new) cloud container (D2).
/// Requires an unlocked session. `webdav_password` is stored in the
/// non-interactive credential store — never persisted with the config.
pub fn sync_connect(
    state: &Arc<AppState>,
    config: SyncConfig,
    container_password: Zeroizing<String>,
    webdav_password: Option<Zeroizing<String>>,
) -> Result<SyncStatusResponse, VaultError> {
    // Credential-store interaction happens FIRST: `open_backend` reads the
    // WebDAV password from the store, and on first-time connect the store is
    // empty — resolving the backend before persisting the password made
    // every initial connect fail with SYNC_CREDENTIALS_MISSING (manual QA).
    if let Some(password) = webdav_password.as_ref() {
        state
            .sync_secret_store
            .set(SYNC_WEBDAV_PASSWORD_ACCOUNT, password.as_bytes())
            .map_err(sync_secret_error)?;
    }
    let backend = open_backend(state, &config)?;
    sync_connect_with_backend(
        state,
        backend.as_ref(),
        config,
        container_password,
        webdav_password,
    )
}

/// [`sync_connect`] with an injected backend (the test seam; production
/// resolves the backend from the config via [`open_backend`]).
pub fn sync_connect_with_backend(
    state: &Arc<AppState>,
    backend: &dyn CloudBackend,
    config: SyncConfig,
    container_password: Zeroizing<String>,
    webdav_password: Option<Zeroizing<String>>,
) -> Result<SyncStatusResponse, VaultError> {
    // D2: bootstrap requires an unlocked session.
    state.lease()?;
    validate_config(&config)?;
    let paths = remote_paths(&config);
    let mut keys = SessionKeys::copy(state)?;

    // ALL credential-store interaction happens before any window (D8 rule 1).
    if let Some(password) = webdav_password {
        state
            .sync_secret_store
            .set(SYNC_WEBDAV_PASSWORD_ACCOUNT, password.as_bytes())
            .map_err(sync_secret_error)?;
    }

    // --- Pull-or-bootstrap (network only; no window yet). ---
    let pull = pull_or_bootstrap(state, backend, &paths, &container_password, &keys)?;

    // --- D8 exclusive window: merge remote into local. ---
    let merged = run_merge_window(state, &mut keys, Some(&pull.snapshot))?;

    // --- Push when the merge added local content; then persist rows. ---
    let device_id = new_device_id();
    let mut history: Vec<String> = Vec::new();
    let (final_entries, final_groups, final_rev) = if merged.changed {
        let mut ctx = PublishContext {
            backend,
            paths: &paths,
            envelope: pull.envelope.clone(),
            cek: &pull.cek,
            etag: pull.etag.clone(),
            base_rev: pull.snapshot.rev,
        };
        let outcome = publish_snapshot(
            &mut ctx,
            &device_id,
            merged.entries.clone(),
            merged.groups.clone(),
            &mut history,
        )?;
        (outcome.entries, outcome.groups, outcome.rev)
    } else {
        // Bootstrap content == remote content: nothing to publish, but the
        // rev manifest must exist for sync_now's fast path to key on.
        let ctx = PublishContext {
            backend,
            paths: &paths,
            envelope: pull.envelope.clone(),
            cek: &pull.cek,
            etag: pull.etag.clone(),
            base_rev: pull.snapshot.rev,
        };
        update_manifest(&ctx, &device_id, pull.snapshot.rev, &pull.container_bytes);
        (merged.entries, merged.groups, pull.snapshot.rev)
    };

    let sync_state = SyncState {
        device_id: Some(device_id),
        last_sync_at: Some(now()),
        last_result: Some("ok".to_string()),
        remote_rev: Some(final_rev),
        last_snapshot_hash: Some(content_hash(&final_entries, &final_groups)),
        envelope: Some(pull.envelope),
        history,
    };
    save_sync_rows(state, &keys, &config, &sync_state, Some(&*pull.cek))?;

    Ok(build_status(&Some(config), &sync_state))
}

/// One pull/push cycle (D5). Requires an unlocked session and a completed
/// bootstrap. The network phase checks the manifest and downloads the
/// container only when the remote rev moved (P3.3 fast path).
pub fn sync_now(state: &Arc<AppState>) -> Result<SyncStatusResponse, VaultError> {
    let lease = state.lease()?;
    let config = load_config(&get_db(state)?)?.ok_or_else(not_configured)?;
    drop(lease);
    let backend = open_backend(state, &config)?;
    sync_now_with_backend(state, backend.as_ref())
}

/// [`sync_now`] with an injected backend (test seam).
pub fn sync_now_with_backend(
    state: &Arc<AppState>,
    backend: &dyn CloudBackend,
) -> Result<SyncStatusResponse, VaultError> {
    let db = get_db(state)?;
    let config = load_config(&db)?.ok_or_else(not_configured)?;
    let mut sync_state = load_sync_state(&db)?;
    let device_id = sync_state.device_id.clone().ok_or_else(not_configured)?;
    let paths = remote_paths(&config);
    let mut keys = SessionKeys::copy(state)?;

    // Unwrap the container key with the session enc subkey (D2: no password).
    let cek: Zeroizing<[u8; KEY_SIZE]> = {
        let blob = vault_store::load_blob(&db, SYNC_CEK_BLOB_KEY)?.ok_or_else(not_configured)?;
        unwrap_secret(keys.enc_bytes(), &blob, WRAP_AAD_SYNC)
            .map_err(|_| VaultError::WrapBlobCorrupt)?
    };

    // --- Network phase 1: what does the remote look like now? ---
    let remote_manifest = fetch_manifest(backend, &paths)?;
    let local_known_rev = sync_state.remote_rev.unwrap_or(0);
    let up_to_date = remote_manifest
        .as_ref()
        .is_some_and(|manifest| manifest.rev == local_known_rev && local_known_rev > 0)
        && sync_state.last_snapshot_hash.is_some()
        && sync_state.envelope.is_some();

    // Fast path: remote rev unchanged since our last cycle — skip the
    // container download; publish later only if local content moved.
    let basis = if up_to_date {
        RemoteBasis::UpToDate {
            etag: backend
                .stat(&paths.container)
                .map_err(backend_error)?
                .and_then(|stat| stat.etag),
            rev: local_known_rev,
        }
    } else {
        match backend.stat(&paths.container).map_err(backend_error)? {
            Some(stat) => {
                let bytes = backend.download(&paths.container).map_err(backend_error)?;
                let (kdf, wrapped_cek) = read_envelope(&bytes).map_err(container_error)?;
                sync_state.envelope = Some(StoredEnvelope {
                    kdf,
                    wrapped_cek: wrapped_cek.to_bytes(),
                });
                let snapshot = decrypt_snapshot_with_cek(&bytes, &cek).map_err(container_error)?;
                RemoteBasis::Fresh {
                    snapshot,
                    etag: stat.etag,
                }
            }
            None => RemoteBasis::Missing,
        }
    };

    // --- D8 exclusive window: pull + merge + write-back + republish. ---
    let (base_rev, etag, merged, need_upload) = match &basis {
        RemoteBasis::Fresh { snapshot, etag } => {
            let merged = run_merge_window(state, &mut keys, Some(snapshot))?;
            {
                let changed = merged.changed;
                (snapshot.rev, etag.clone(), merged, changed)
            }
        }
        RemoteBasis::UpToDate { etag, rev } => {
            let merged = run_merge_window(state, &mut keys, None)?;
            let changed = sync_state
                .last_snapshot_hash
                .as_deref()
                .map(|hash| hash != content_hash(&merged.entries, &merged.groups))
                .unwrap_or(true);
            (*rev, etag.clone(), merged, changed)
        }
        RemoteBasis::Missing => {
            let merged = run_merge_window(state, &mut keys, None)?;
            (0, None, merged, true)
        }
    };

    // --- Network phase 2 (outside the window): push when we have changes. ---
    let (final_entries, final_groups, final_rev) = if need_upload {
        let envelope = sync_state.envelope.clone().ok_or_else(not_configured)?;
        let mut ctx = PublishContext {
            backend,
            paths: &paths,
            envelope,
            cek: &cek,
            etag,
            base_rev,
        };
        let outcome = publish_snapshot(
            &mut ctx,
            &device_id,
            merged.entries.clone(),
            merged.groups.clone(),
            &mut sync_state.history,
        )?;
        (outcome.entries, outcome.groups, outcome.rev)
    } else {
        (merged.entries, merged.groups, base_rev)
    };

    // --- Persist the new bookkeeping (digest-covered rows). ---
    sync_state.last_sync_at = Some(now());
    sync_state.last_result = Some("ok".to_string());
    sync_state.remote_rev = Some(final_rev);
    sync_state.last_snapshot_hash = Some(content_hash(&final_entries, &final_groups));
    save_sync_rows(state, &keys, &config, &sync_state, None)?;

    Ok(build_status(&Some(config), &sync_state))
}

/// Where the remote container stands at the start of a cycle.
enum RemoteBasis {
    /// Manifest rev matches our last processed rev — download skipped.
    UpToDate { etag: Option<String>, rev: u64 },
    /// Fresh container content pulled from the cloud.
    Fresh {
        snapshot: SyncSnapshot,
        etag: Option<String>,
    },
    /// No container on the cloud (recreate from local state).
    Missing,
}

/// Remove this device from cloud sync: the local rows go away, the cloud
/// files stay (other devices are unaffected — documented behavior).
pub fn sync_disconnect(state: &Arc<AppState>) -> Result<(), VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let store = VaultStore::new(&db);
    store.write(lease.mac_key()?, |txn| {
        vault_store::remove_blob_in_txn(txn, SYNC_CEK_BLOB_KEY)?;
        vault_store::remove_blob_in_txn(txn, SYNC_CONFIG_BLOB_KEY)?;
        vault_store::remove_blob_in_txn(txn, SYNC_STATE_BLOB_KEY)?;
        Ok(())
    })?;
    lease.touch_activity();

    // Best effort: drop the stored backend credentials with the connection
    // (WebDAV password P3.2, Baidu token P3.4). The cloud files stay.
    let _ = state.sync_secret_store.delete(SYNC_WEBDAV_PASSWORD_ACCOUNT);
    let _ = state.sync_secret_store.delete(SYNC_BAIDU_TOKEN_ACCOUNT);
    Ok(())
}

/// Current sync status (requires an unlocked session — the config row names
/// the server URL and user name, which are not for locked-vault eyes).
pub fn sync_status(state: &Arc<AppState>) -> Result<SyncStatusResponse, VaultError> {
    let lease = state.lease()?;
    let config = load_config(&get_db(state)?)?;
    let sync_state = load_sync_state(&get_db(state)?)?;
    drop(lease);
    Ok(build_status(&config, &sync_state))
}

fn build_status(config: &Option<SyncConfig>, sync_state: &SyncState) -> SyncStatusResponse {
    SyncStatusResponse {
        enabled: config.as_ref().is_some_and(|config| config.enabled),
        backend: config
            .as_ref()
            .map(|config| config.backend.as_str().to_string()),
        last_sync_at: sync_state.last_sync_at,
        last_result: sync_state.last_result.clone(),
        remote_rev: sync_state.remote_rev,
    }
}
