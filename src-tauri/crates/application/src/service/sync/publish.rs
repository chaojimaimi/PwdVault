//! Sync engine cloud I/O (M-3 split of the former single-file engine —
//! pure move): pulling/bootstrapping the remote container
//! ([`pull_or_bootstrap`]), publishing a new revision with the D4 conflict
//! loop ([`publish_snapshot`]), the rev manifest and history rotation, and
//! the manifest fast-path probe ([`fetch_manifest`]). All of this is network
//! I/O and runs strictly OUTSIDE the D8 exclusive window (the window never
//! stretches over a request, including the ≤3 conflict retries).

use std::sync::Arc;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::service::sync::backend::{BackendError, CloudBackend, Precondition, RemoteStat};
use crate::service::sync::container::{
    create_container_with_cek, decrypt_snapshot_with_cek, read_envelope, reseal_snapshot,
    unlock_container,
};
use crate::service::sync::merge::merge_snapshots;
use crate::service::sync::{SyncEntry, SyncGroup, SyncSnapshot};
use crate::service::vault::get_db;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::crypto::{EncryptedData, KEY_SIZE};

use super::state_io::{
    backend_error, container_error, invalid_sync, new_device_id, now, read_local_rows, to_hex,
    RemotePaths, SessionKeys, StoredEnvelope, HISTORY_KEEP, MAX_UPLOAD_ATTEMPTS,
};

// ---------------------------------------------------------------------------
// Manifest + publishing (outside the D8 window)
// ---------------------------------------------------------------------------

/// Cloud manifest next to the container (D4).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct SyncManifest {
    pub(super) rev: u64,
    device_id: String,
    sha256: String,
    ts: i64,
}

/// What the engine needs to publish a new revision: the current envelope
/// pieces (preserved verbatim), the cek, and the current remote etag/rev.
pub(super) struct PublishContext<'a> {
    pub(super) backend: &'a dyn CloudBackend,
    pub(super) paths: &'a RemotePaths,
    pub(super) envelope: StoredEnvelope,
    pub(super) cek: &'a [u8; KEY_SIZE],
    pub(super) etag: Option<String>,
    pub(super) base_rev: u64,
}

impl PublishContext<'_> {
    fn build_container(&self, snapshot: &SyncSnapshot) -> Result<Vec<u8>, VaultError> {
        let wrapped_cek = EncryptedData::from_bytes(&self.envelope.wrapped_cek).map_err(|_| {
            invalid_sync("SYNC_STATE_CORRUPT", "stored container envelope is corrupt")
        })?;
        reseal_snapshot(self.envelope.kdf.clone(), wrapped_cek, self.cek, snapshot)
            .map_err(container_error)
    }

    /// Precondition for the container PUT given the current etag knowledge.
    /// Without ETag support the manifest-rev guard runs instead (D4/P3.8).
    fn container_precondition(&self) -> Result<Precondition, BackendError> {
        match &self.etag {
            Some(etag) => Ok(Precondition::IfMatch(etag.clone())),
            None => {
                self.check_manifest_rev()?;
                Ok(Precondition::Unconditional)
            }
        }
    }

    /// Manifest-rev guard for servers without ETag support: the manifest rev
    /// must still be `base_rev`, otherwise someone else published.
    fn check_manifest_rev(&self) -> Result<(), BackendError> {
        if self.backend.stat(&self.paths.manifest)?.is_none() {
            // No manifest at all: only an absent container is a consistent
            // reading, and that case is handled by etag/IfAbsent logic.
            return Ok(());
        }
        let bytes = self.backend.download(&self.paths.manifest)?;
        match serde_json::from_slice::<SyncManifest>(&bytes) {
            Ok(manifest) if manifest.rev == self.base_rev => Ok(()),
            Ok(_) => Err(BackendError::Conflict),
            Err(_) => Err(BackendError::Network("manifest is corrupt".to_string())),
        }
    }
}

/// Outcome of a successful publish (or of noticing the remote already has
/// our content): the rev now on the cloud and its exact content.
pub(super) struct PublishOutcome {
    pub(super) rev: u64,
    pub(super) entries: Vec<SyncEntry>,
    pub(super) groups: Vec<SyncGroup>,
}

/// Publish `entries`/`groups` as `base_rev + 1`, with the D4 conflict loop:
/// Conflict → re-stat → re-download → re-merge → retry, at most
/// [`MAX_UPLOAD_ATTEMPTS`] times. Network-only, never inside the D8 window.
pub(super) fn publish_snapshot(
    ctx: &mut PublishContext,
    device_id: &str,
    mut entries: Vec<SyncEntry>,
    mut groups: Vec<SyncGroup>,
    history: &mut Vec<String>,
) -> Result<PublishOutcome, VaultError> {
    for _attempt in 0..MAX_UPLOAD_ATTEMPTS {
        let new_rev = ctx.base_rev + 1;
        let snapshot = SyncSnapshot {
            rev: new_rev,
            device_id: device_id.to_string(),
            generated_at: now(),
            entries: entries.clone(),
            groups: groups.clone(),
        };
        let bytes = ctx.build_container(&snapshot)?;
        let precondition = ctx.container_precondition().map_err(backend_error)?;

        match ctx
            .backend
            .upload(&ctx.paths.container, &bytes, precondition)
        {
            Ok(()) => {
                update_manifest(ctx, device_id, new_rev, &bytes);
                rotate_history(ctx, &bytes, new_rev, device_id, history);
                return Ok(PublishOutcome {
                    rev: new_rev,
                    entries,
                    groups,
                });
            }
            Err(BackendError::Conflict) => {
                // Re-pull, re-merge, retry (D4).
                let stat = ctx
                    .backend
                    .stat(&ctx.paths.container)
                    .map_err(backend_error)?;
                match stat {
                    Some(remote_stat) => {
                        let fresh = ctx
                            .backend
                            .download(&ctx.paths.container)
                            .map_err(backend_error)?;
                        let remote_snapshot =
                            decrypt_snapshot_with_cek(&fresh, ctx.cek).map_err(container_error)?;
                        let our_view = SyncSnapshot {
                            rev: 0,
                            device_id: String::new(),
                            generated_at: 0,
                            entries: entries.clone(),
                            groups: groups.clone(),
                        };
                        let merged = merge_snapshots(&our_view, &remote_snapshot);
                        if !merged.changed {
                            // The remote already carries our content — no
                            // upload needed (anti-echo), just bookkeeping.
                            return Ok(PublishOutcome {
                                rev: remote_snapshot.rev,
                                entries: merged.entries,
                                groups: merged.groups,
                            });
                        }
                        let (kdf, wrapped_cek) = read_envelope(&fresh).map_err(container_error)?;
                        ctx.envelope = StoredEnvelope {
                            kdf,
                            wrapped_cek: wrapped_cek.to_bytes(),
                        };
                        ctx.etag = remote_stat.etag;
                        ctx.base_rev = remote_snapshot.rev;
                        entries = merged.entries;
                        groups = merged.groups;
                    }
                    None => {
                        // Container vanished remotely — recreate it.
                        ctx.etag = None;
                        ctx.base_rev = 0;
                    }
                }
            }
            Err(err) => return Err(backend_error(err)),
        }
    }
    Err(invalid_sync(
        "SYNC_CONFLICT",
        format!(
            "The vault kept changing on another device — {MAX_UPLOAD_ATTEMPTS} retries exhausted"
        ),
    ))
}

/// Best-effort manifest update: WebDAV correctness rests on If-Match, so a
/// manifest failure only degrades the no-ETag fallback (warn, don't fail).
pub(super) fn update_manifest(
    ctx: &PublishContext,
    device_id: &str,
    rev: u64,
    container_bytes: &[u8],
) {
    let manifest = SyncManifest {
        rev,
        device_id: device_id.to_string(),
        sha256: to_hex(&Sha256::digest(container_bytes)),
        ts: now(),
    };
    match serde_json::to_vec(&manifest) {
        Ok(json) => {
            if let Err(err) =
                ctx.backend
                    .upload(&ctx.paths.manifest, &json, Precondition::Unconditional)
            {
                tracing::warn!("sync manifest update failed (degraded): {err}");
            }
        }
        Err(err) => tracing::warn!("sync manifest serialization failed: {err}"),
    }
}

/// D4 history rotation: upload the superseded container under a unique name,
/// keep at most [`HISTORY_KEEP`] files (names tracked in `sync_state`).
/// Failures never fail the sync — history is a recovery convenience.
fn rotate_history(
    ctx: &PublishContext,
    container_bytes: &[u8],
    rev: u64,
    device_id: &str,
    history: &mut Vec<String>,
) {
    let name = format!(
        "{}/pwdvault-sync-r{rev}-{device}-{}.pwsync",
        ctx.paths.history_dir,
        now(),
        device = &device_id[..device_id.len().min(8)]
    );
    if let Err(err) = ctx.backend.upload_unique(&name, container_bytes) {
        tracing::warn!("sync history upload failed: {err}");
        return;
    }
    history.push(name);
    while history.len() > HISTORY_KEEP {
        let oldest = history.remove(0);
        if let Err(err) = ctx.backend.delete(&oldest) {
            // Keep the name on the rotation list; pruned on a later sync.
            tracing::warn!("sync history prune failed for {oldest}: {err}");
            history.insert(0, oldest);
            break;
        }
    }
}

/// Download + parse the manifest; `None` when it does not exist yet.
pub(super) fn fetch_manifest(
    backend: &dyn CloudBackend,
    paths: &RemotePaths,
) -> Result<Option<SyncManifest>, VaultError> {
    if backend
        .stat(&paths.manifest)
        .map_err(backend_error)?
        .is_none()
    {
        return Ok(None);
    }
    let bytes = backend.download(&paths.manifest).map_err(backend_error)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| invalid_sync("SYNC_MANIFEST_CORRUPT", "The sync manifest is corrupt"))
}

// ---------------------------------------------------------------------------
// Pull phase (connect bootstrap)
// ---------------------------------------------------------------------------

/// Result of the connect pull phase: the remote (or freshly created)
/// snapshot plus everything needed to publish and store the cek.
pub(super) struct PullResult {
    pub(super) snapshot: SyncSnapshot,
    pub(super) envelope: StoredEnvelope,
    pub(super) cek: Zeroizing<[u8; KEY_SIZE]>,
    pub(super) etag: Option<String>,
    /// The exact container bytes now on the cloud (manifest sha256 basis).
    pub(super) container_bytes: Vec<u8>,
}

/// Download the remote container, or bootstrap it from local content when
/// the cloud is empty (create semantics: `Precondition::IfAbsent` — the D2
/// connect race resolves to exactly one winner, the loser downloads).
pub(super) fn pull_or_bootstrap(
    state: &Arc<AppState>,
    backend: &dyn CloudBackend,
    paths: &RemotePaths,
    container_password: &Zeroizing<String>,
    keys: &SessionKeys,
) -> Result<PullResult, VaultError> {
    for _attempt in 0..MAX_UPLOAD_ATTEMPTS {
        match backend.stat(&paths.container).map_err(backend_error)? {
            Some(stat) => {
                let bytes = backend.download(&paths.container).map_err(backend_error)?;
                let (snapshot, cek) = unlock_container(container_password.clone(), &bytes)
                    .map_err(container_error)?;
                let (kdf, wrapped_cek) = read_envelope(&bytes).map_err(container_error)?;
                return Ok(PullResult {
                    snapshot,
                    envelope: StoredEnvelope {
                        kdf,
                        wrapped_cek: wrapped_cek.to_bytes(),
                    },
                    cek,
                    etag: stat.etag,
                    container_bytes: bytes,
                });
            }
            None => {
                // Create the initial container from local content (cek fresh
                // from the OS CSPRNG, wrapped inside the container).
                let db = get_db(state)?;
                let local = read_local_rows(&db, keys.enc_bytes())?;
                let initial = SyncSnapshot {
                    rev: 1,
                    device_id: new_device_id(),
                    generated_at: now(),
                    entries: local.sync_entries,
                    groups: local.sync_groups,
                };
                let (bytes, cek) = create_container_with_cek(container_password.clone(), &initial)
                    .map_err(container_error)?;
                let (kdf, wrapped_cek) = read_envelope(&bytes).map_err(container_error)?;
                match backend.upload(&paths.container, &bytes, Precondition::IfAbsent) {
                    Ok(()) => {
                        // Another device may still have raced us — re-stat
                        // settles the etag for later If-Match uploads.
                        let etag = backend
                            .stat(&paths.container)
                            .map_err(backend_error)?
                            .and_then(|stat: RemoteStat| stat.etag);
                        return Ok(PullResult {
                            snapshot: initial,
                            envelope: StoredEnvelope {
                                kdf,
                                wrapped_cek: wrapped_cek.to_bytes(),
                            },
                            cek,
                            etag,
                            container_bytes: bytes,
                        });
                    }
                    // Lost the create race → loop and download the winner.
                    Err(BackendError::Conflict) => continue,
                    Err(err) => return Err(backend_error(err)),
                }
            }
        }
    }
    Err(backend_error(BackendError::Conflict))
}
