//! P3.3 sync engine: config/state rows, bootstrap ([`sync_connect`]), the
//! periodic pull/push cycle ([`sync_now`]), and disconnect/status.
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
//! Cloud layout (D4):
//! ```text
//! <remote_dir>/pwdvault-sync.pwsync            current container
//! <remote_dir>/pwdvault-sync.manifest.json     {rev, device_id, sha256, ts}
//! <remote_dir>/history/pwdvault-sync-r<rev>-<device>-<ts>.pwsync
//! ```
//! History is capped at [`HISTORY_KEEP`] files; the engine tracks the names
//! in its `sync_state` row (no directory listing needed).

use std::collections::HashMap;
use std::sync::Arc;

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::service::security::SYNC_CEK_BLOB_KEY;
use crate::service::sync::backend::{
    BackendError, CloudBackend, Precondition, RemoteStat, WebDavBackend,
};
use crate::service::sync::baidu::BaiduBackend;
use crate::service::sync::baidu_oauth::baidu_configured;
use crate::service::sync::container::{
    create_container_with_cek, decrypt_snapshot_with_cek, read_envelope, reseal_snapshot,
    unlock_container, ContainerError, ContainerKdf,
};
use crate::service::sync::merge::{merge_snapshots, MergedSnapshot};
use crate::service::sync::{
    entries_to_sync, sync_to_entry, SyncEntry, SyncGroup, SyncSecrets, SyncSnapshot,
};
use crate::service::vault::get_db;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::crypto::{
    decrypt, unwrap_secret, wrap_secret, EncryptedData, SecretKey, KEY_SIZE, WRAP_AAD_SYNC,
};
use pwdvault_infrastructure::database::{
    self,
    vault_store::{self, VaultStore},
    Group,
};
use pwdvault_infrastructure::keychain::{
    SecretStoreError, SYNC_BAIDU_TOKEN_ACCOUNT, SYNC_WEBDAV_PASSWORD_ACCOUNT,
};

// ---------------------------------------------------------------------------
// Rows, cloud file names, tunables
// ---------------------------------------------------------------------------

/// VAULT_TABLE row holding the plaintext JSON [`SyncConfig`].
pub const SYNC_CONFIG_BLOB_KEY: &str = "sync_config";
/// VAULT_TABLE row holding the plaintext JSON [`SyncState`].
pub const SYNC_STATE_BLOB_KEY: &str = "sync_state";
/// Cloud file name of the current container (D4).
pub const CONTAINER_FILE: &str = "pwdvault-sync.pwsync";
/// Cloud file name of the rev manifest (D4).
pub const MANIFEST_FILE: &str = "pwdvault-sync.manifest.json";
/// Cloud directory holding rolling history snapshots (D4).
pub const HISTORY_DIR: &str = "history";
/// History snapshots kept per vault (D4).
pub const HISTORY_KEEP: usize = 10;
/// Upload attempts before a Conflict is surfaced (D4: re-pull, re-merge).
pub const MAX_UPLOAD_ATTEMPTS: usize = 3;

/// Which cloud storage the vault syncs through (D6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncBackendKind {
    Webdav,
    Baidu,
}

impl SyncBackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SyncBackendKind::Webdav => "webdav",
            SyncBackendKind::Baidu => "baidu",
        }
    }
}

/// Persisted sync configuration (P3.3): plaintext JSON in the `sync_config`
/// row. Non-sensitive only — the WebDAV password lives in the
/// non-interactive credential store (`sync-webdav-password` account).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncConfig {
    pub enabled: bool,
    pub backend: SyncBackendKind,
    /// WebDAV server root, e.g. `https://dav.jianguoyun.com/dav`.
    pub server_url: String,
    /// Directory on the remote holding the container files.
    pub remote_dir: String,
    /// WebDAV user name (non-sensitive).
    pub username: String,
}

/// Persisted sync bookkeeping (`sync_state` row, plaintext JSON).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncState {
    /// This device's sync identity (stable per connect).
    pub device_id: Option<String>,
    pub last_sync_at: Option<i64>,
    /// `"ok"` after a successful cycle; otherwise a short error code.
    pub last_result: Option<String>,
    /// The container rev this device last processed (pulled or pushed).
    pub remote_rev: Option<u64>,
    /// Content hash (envelope-free) of the snapshot current at
    /// `remote_rev` — the anti-echo basis for the no-download fast path.
    pub last_snapshot_hash: Option<String>,
    /// Envelope pieces (kdf record + wrapped cek) of the current container,
    /// so a new revision can be published without re-downloading it.
    pub envelope: Option<StoredEnvelope>,
    /// History file names currently on the cloud (rotation bookkeeping).
    pub history: Vec<String>,
}

/// The envelope subset kept locally between syncs (see [`SyncState::envelope`]).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredEnvelope {
    pub kdf: ContainerKdf,
    pub wrapped_cek: Vec<u8>,
}

/// Tauri-facing status payload (`sync_status` / return of the sync commands).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncStatusResponse {
    pub enabled: bool,
    pub backend: Option<String>,
    pub last_sync_at: Option<i64>,
    pub last_result: Option<String>,
    pub remote_rev: Option<u64>,
}

/// Cloud manifest next to the container (D4).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SyncManifest {
    rev: u64,
    device_id: String,
    sha256: String,
    ts: i64,
}

// ---------------------------------------------------------------------------
// Errors and small helpers
// ---------------------------------------------------------------------------

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn invalid_sync(code: &'static str, message: impl Into<String>) -> VaultError {
    VaultError::InvalidInput {
        code: code.to_string(),
        message: message.into(),
    }
}

/// Map backend failures onto the user-facing error taxonomy. Shared with
/// the Baidu OAuth commands (P3.4) so `NotConfigured` keeps a single code.
pub(crate) fn backend_error(err: BackendError) -> VaultError {
    match err {
        BackendError::Conflict => invalid_sync(
            "SYNC_CONFLICT",
            "The vault changed on another device — sync again to merge",
        ),
        BackendError::Auth(message) => invalid_sync(
            "SYNC_AUTH_FAILED",
            format!("Cloud authentication failed: {message}"),
        ),
        BackendError::Network(message) => {
            invalid_sync("SYNC_NETWORK_ERROR", format!("Cloud request failed: {message}"))
        }
        BackendError::NotConfigured => invalid_sync(
            "SYNC_BACKEND_NOT_CONFIGURED",
            "This sync backend is not available in this build",
        ),
    }
}

fn container_error(err: ContainerError) -> VaultError {
    match err {
        ContainerError::UnsupportedVersion => invalid_sync(
            "SYNC_CONTAINER_VERSION",
            "The sync container was created by a different app version",
        ),
        ContainerError::InvalidContainer => invalid_sync(
            "SYNC_CONTAINER_INVALID",
            "Sync container is invalid or the container password is incorrect",
        ),
    }
}

fn sync_secret_error(err: SecretStoreError) -> VaultError {
    match err {
        SecretStoreError::NotFound => invalid_sync(
            "SYNC_CREDENTIALS_MISSING",
            "Sync credentials are not stored — reconnect cloud sync",
        ),
        other => VaultError::KeychainError(other.to_string()),
    }
}

fn not_configured() -> VaultError {
    invalid_sync(
        "SYNC_NOT_CONFIGURED",
        "Cloud sync is not set up on this device",
    )
}

/// Fresh device identity: 16 hex chars from the OS CSPRNG.
fn new_device_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Envelope-free, order-insensitive content hash — the anti-echo basis when
/// the manifest rev says the remote did not change (P3.3).
fn content_hash(entries: &[SyncEntry], groups: &[SyncGroup]) -> String {
    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by(|a, b| a.id.cmp(&b.id));
    let mut sorted_groups = groups.to_vec();
    sorted_groups.sort_by(|a, b| a.id.cmp(&b.id));
    let payload = serde_json::json!({ "entries": sorted_entries, "groups": sorted_groups });
    to_hex(&Sha256::digest(serde_json::to_vec(&payload).unwrap_or_default()))
}

/// Validate user-supplied configuration before anything touches the network.
/// The URL/username checks are WebDAV-specific — the Baidu backend gets its
/// endpoints from the build (OAuth pairing, P3.4), so only the remote
/// layout is user input there.
fn validate_config(config: &SyncConfig) -> Result<(), VaultError> {
    if matches!(config.backend, SyncBackendKind::Webdav) {
        let url = config.server_url.trim();
        let scheme_ok = url.starts_with("https://") || url.starts_with("http://");
        if !scheme_ok
            || url.len() <= 8
            || url.len() > 2048
            || url.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(invalid_sync(
                "SYNC_INVALID_CONFIG",
                "Server URL must be an http(s) URL without whitespace",
            ));
        }
        if config.username.len() > 512 {
            return Err(invalid_sync("SYNC_INVALID_CONFIG", "Username is too long"));
        }
    }
    let dir = config.remote_dir.trim().trim_matches('/');
    if dir.len() > 512
        || dir.split('/').any(|segment| segment.is_empty() || segment == "..")
        || dir.chars().any(|c| c.is_control())
    {
        return Err(invalid_sync(
            "SYNC_INVALID_CONFIG",
            "Remote directory contains invalid path segments",
        ));
    }
    Ok(())
}

/// Remote file layout derived from the config (D4).
struct RemotePaths {
    container: String,
    manifest: String,
    history_dir: String,
}

fn remote_paths(config: &SyncConfig) -> RemotePaths {
    let dir = config.remote_dir.trim().trim_matches('/');
    let join = |name: &str| {
        if dir.is_empty() {
            name.to_string()
        } else {
            format!("{dir}/{name}")
        }
    };
    RemotePaths {
        container: join(CONTAINER_FILE),
        manifest: join(MANIFEST_FILE),
        history_dir: join(HISTORY_DIR),
    }
}

/// Build the backend for the configured kind (P3.2 WebDAV, P3.4 Baidu).
fn open_backend(
    state: &Arc<AppState>,
    config: &SyncConfig,
) -> Result<Arc<dyn CloudBackend>, VaultError> {
    match config.backend {
        SyncBackendKind::Webdav => {
            let password = state
                .sync_secret_store
                .get(SYNC_WEBDAV_PASSWORD_ACCOUNT)
                .map_err(sync_secret_error)?;
            let password = Zeroizing::new(String::from_utf8(password).map_err(|_| {
                invalid_sync("SYNC_CREDENTIALS_CORRUPT", "Stored WebDAV password is not valid UTF-8")
            })?);
            Ok(Arc::new(
                WebDavBackend::new(config.server_url.trim(), &config.username, password)
                    .map_err(backend_error)?,
            ))
        }
        SyncBackendKind::Baidu => {
            // P3.8: without compiled-in AppKey/SecretKey the adapter stays
            // NotConfigured — the frontend shows the BAIDU-SETUP guidance.
            if !baidu_configured() {
                return Err(backend_error(BackendError::NotConfigured));
            }
            Ok(Arc::new(BaiduBackend::new(
                pwdvault_domain::constants::BAIDU_APP_KEY,
                pwdvault_domain::constants::BAIDU_SECRET_KEY,
                state.sync_secret_store.clone(),
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Local row reads / merged write-back
// ---------------------------------------------------------------------------

/// Local rows in sync (plaintext-domain) form — the merge input.
struct LocalRows {
    sync_entries: Vec<SyncEntry>,
    sync_groups: Vec<SyncGroup>,
}

/// Decrypt one inner string field (bincode `EncryptedData` first, raw
/// nonce||ciphertext fallback — same resilient path as backup export).
fn decrypt_inner(enc: &[u8; KEY_SIZE], blob: &[u8]) -> Result<String, VaultError> {
    let sealed: EncryptedData = bincode::deserialize(blob)
        .or_else(|_| EncryptedData::from_bytes(blob))
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
    let mut plain = decrypt(enc, &sealed)?;
    let text = String::from_utf8(plain.clone())
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()));
    plain.zeroize();
    text
}

/// Full local read (raw rows including tombstones — the merge input).
fn read_local_rows(db: &Arc<redb::Database>, enc: &[u8; KEY_SIZE]) -> Result<LocalRows, VaultError> {
    let entries = database::list_all_entries_bulk(db, enc, None)?;
    let groups = database::list_all_groups_bulk(db, enc)?;

    let mut secrets: HashMap<String, SyncSecrets> = HashMap::with_capacity(entries.len());
    for entry in &entries {
        secrets.insert(
            entry.id.clone(),
            SyncSecrets {
                password: if entry.encrypted_password.is_empty() {
                    String::new()
                } else {
                    decrypt_inner(enc, &entry.encrypted_password)?
                },
                notes: entry
                    .encrypted_notes
                    .as_deref()
                    .map(|blob| decrypt_inner(enc, blob))
                    .transpose()?,
                totp_secret: entry
                    .encrypted_totp_secret
                    .as_deref()
                    .map(|blob| decrypt_inner(enc, blob))
                    .transpose()?,
            },
        );
    }
    Ok(LocalRows {
        sync_entries: entries_to_sync(&entries, &secrets),
        sync_groups: groups
            .iter()
            .map(|group| SyncGroup {
                id: group.id.clone(),
                name: group.name.clone(),
                created_at: group.created_at,
                updated_at: group.updated_at,
                deleted_at: group.deleted_at,
            })
            .collect(),
    })
}

/// Re-seal merged rows that differ from the local state (single transaction,
/// re-encrypted with the local enc key — plan P3.1).
fn write_merged_back(
    db: &Arc<redb::Database>,
    keys: &SessionKeys,
    local: &LocalRows,
    merged: &MergedSnapshot,
) -> Result<usize, VaultError> {
    let local_entries: HashMap<&str, &SyncEntry> =
        local.sync_entries.iter().map(|e| (e.id.as_str(), e)).collect();
    let local_groups: HashMap<&str, &SyncGroup> =
        local.sync_groups.iter().map(|g| (g.id.as_str(), g)).collect();

    // Convert changed rows BEFORE opening the transaction, so a crypto
    // failure rolls back cleanly without holding the write lock (the same
    // pattern create_entry uses).
    let mut changed_rows = 0usize;
    let mut entry_rows = Vec::new();
    for entry in &merged.entries {
        if local_entries.get(entry.id.as_str()) != Some(&entry) {
            entry_rows.push(sync_to_entry(entry.clone(), keys.enc_bytes())?);
            changed_rows += 1;
        }
    }
    let mut group_rows = Vec::new();
    for group in &merged.groups {
        if local_groups.get(group.id.as_str()) != Some(&group) {
            let mut row = Group::new(group.name.clone());
            row.id = group.id.clone();
            row.created_at = group.created_at;
            row.updated_at = group.updated_at;
            row.deleted_at = group.deleted_at;
            group_rows.push(row);
            changed_rows += 1;
        }
    }

    let store = VaultStore::new(db);
    store.write(keys.mac_bytes(), |txn| {
        for row in &entry_rows {
            vault_store::save_entry_in_txn(txn, keys.enc_bytes(), row)?;
        }
        for row in &group_rows {
            vault_store::save_group_in_txn(txn, keys.enc_bytes(), row)?;
        }
        Ok(())
    })?;
    Ok(changed_rows)
}

// ---------------------------------------------------------------------------
// D8 window (P3.1 precise sequence)
// ---------------------------------------------------------------------------

/// Session key copies taken from a lease, kept alive past the exclusive
/// window and republished afterwards. `SecretKey` zeroizes on drop.
struct SessionKeys {
    enc: SecretKey,
    mac: SecretKey,
}

impl SessionKeys {
    /// Copy enc/mac out of the session and release the lease immediately —
    /// never hold a lease into `exclusive_lock_and_clear` (same-thread
    /// deadlock).
    fn copy(state: &Arc<AppState>) -> Result<Self, VaultError> {
        let lease = state.lease()?;
        let keys = Self {
            enc: SecretKey::new(*lease.enc_key()?),
            mac: SecretKey::new(*lease.mac_key()?),
        };
        drop(lease);
        Ok(keys)
    }

    fn enc_bytes(&self) -> &[u8; KEY_SIZE] {
        self.enc.as_ref()
    }

    fn mac_bytes(&self) -> &[u8; KEY_SIZE] {
        self.mac.as_ref()
    }

    /// Republish the COPIED keys — sync never rotates them (review P3).
    fn republish(&self, state: &Arc<AppState>) {
        state.session.unlock(
            SecretKey::new(*self.enc.as_ref()),
            SecretKey::new(*self.mac.as_ref()),
        );
    }
}

/// The P3.1 exclusive window: drain leases, assert Locked, full local read +
/// merge + single-transaction write-back, then republish the copied keys.
/// `remote = None` means "no remote content to pull" (push-only cycle) —
/// the merge result is then the local state itself.
fn run_merge_window(
    state: &Arc<AppState>,
    keys: &SessionKeys,
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
// Config/state row IO (plaintext JSON blobs — digest-covered)
// ---------------------------------------------------------------------------

fn load_config(db: &Arc<redb::Database>) -> Result<Option<SyncConfig>, VaultError> {
    match vault_store::load_blob(db, SYNC_CONFIG_BLOB_KEY)? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
            invalid_sync("SYNC_CONFIG_CORRUPT", format!("sync config is corrupt: {e}"))
        }),
    }
}

fn load_sync_state(db: &Arc<redb::Database>) -> Result<SyncState, VaultError> {
    match vault_store::load_blob(db, SYNC_STATE_BLOB_KEY)? {
        None => Ok(SyncState::default()),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| invalid_sync("SYNC_STATE_CORRUPT", format!("sync state is corrupt: {e}"))),
    }
}

/// Persist config/state rows (and optionally the wrapped cek) in ONE
/// transaction via `VaultStore::write` so the digest covers them.
fn save_sync_rows(
    state: &Arc<AppState>,
    keys: &SessionKeys,
    config: &SyncConfig,
    sync_state: &SyncState,
    cek: Option<&[u8; KEY_SIZE]>,
) -> Result<(), VaultError> {
    let config_json =
        serde_json::to_vec(config).map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
    let state_json =
        serde_json::to_vec(sync_state).map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
    let cek_blob = match cek {
        Some(cek) => Some(wrap_secret(keys.enc_bytes(), cek, WRAP_AAD_SYNC)?),
        None => None,
    };

    let db = get_db(state)?;
    let store = VaultStore::new(&db);
    store.write(keys.mac_bytes(), |txn| {
        vault_store::save_blob_in_txn(txn, SYNC_CONFIG_BLOB_KEY, &config_json)?;
        vault_store::save_blob_in_txn(txn, SYNC_STATE_BLOB_KEY, &state_json)?;
        if let Some(blob) = &cek_blob {
            vault_store::save_blob_in_txn(txn, SYNC_CEK_BLOB_KEY, blob)?;
        }
        Ok(())
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Publishing (outside the D8 window)
// ---------------------------------------------------------------------------

/// What the engine needs to publish a new revision: the current envelope
/// pieces (preserved verbatim), the cek, and the current remote etag/rev.
struct PublishContext<'a> {
    backend: &'a dyn CloudBackend,
    paths: &'a RemotePaths,
    envelope: StoredEnvelope,
    cek: &'a [u8; KEY_SIZE],
    etag: Option<String>,
    base_rev: u64,
}

impl PublishContext<'_> {
    fn build_container(&self, snapshot: &SyncSnapshot) -> Result<Vec<u8>, VaultError> {
        let wrapped_cek = EncryptedData::from_bytes(&self.envelope.wrapped_cek)
            .map_err(|_| invalid_sync("SYNC_STATE_CORRUPT", "stored container envelope is corrupt"))?;
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
struct PublishOutcome {
    rev: u64,
    entries: Vec<SyncEntry>,
    groups: Vec<SyncGroup>,
}

/// Publish `entries`/`groups` as `base_rev + 1`, with the D4 conflict loop:
/// Conflict → re-stat → re-download → re-merge → retry, at most
/// [`MAX_UPLOAD_ATTEMPTS`] times. Network-only, never inside the D8 window.
fn publish_snapshot(
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

        match ctx.backend.upload(&ctx.paths.container, &bytes, precondition) {
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
                let stat = ctx.backend.stat(&ctx.paths.container).map_err(backend_error)?;
                match stat {
                    Some(remote_stat) => {
                        let fresh =
                            ctx.backend.download(&ctx.paths.container).map_err(backend_error)?;
                        let remote_snapshot = decrypt_snapshot_with_cek(&fresh, ctx.cek)
                            .map_err(container_error)?;
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
        format!("The vault kept changing on another device — {MAX_UPLOAD_ATTEMPTS} retries exhausted"),
    ))
}

/// Best-effort manifest update: WebDAV correctness rests on If-Match, so a
/// manifest failure only degrades the no-ETag fallback (warn, don't fail).
fn update_manifest(ctx: &PublishContext, device_id: &str, rev: u64, container_bytes: &[u8]) {
    let manifest = SyncManifest {
        rev,
        device_id: device_id.to_string(),
        sha256: to_hex(&Sha256::digest(container_bytes)),
        ts: now(),
    };
    match serde_json::to_vec(&manifest) {
        Ok(json) => {
            if let Err(err) =
                ctx.backend.upload(&ctx.paths.manifest, &json, Precondition::Unconditional)
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

// ---------------------------------------------------------------------------
// Pull phase (connect bootstrap)
// ---------------------------------------------------------------------------

/// Result of the connect pull phase: the remote (or freshly created)
/// snapshot plus everything needed to publish and store the cek.
struct PullResult {
    snapshot: SyncSnapshot,
    envelope: StoredEnvelope,
    cek: Zeroizing<[u8; KEY_SIZE]>,
    etag: Option<String>,
    /// The exact container bytes now on the cloud (manifest sha256 basis).
    container_bytes: Vec<u8>,
}

/// Download the remote container, or bootstrap it from local content when
/// the cloud is empty (create semantics: `Precondition::IfAbsent` — the D2
/// connect race resolves to exactly one winner, the loser downloads).
fn pull_or_bootstrap(
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
    let keys = SessionKeys::copy(state)?;

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
    let merged = run_merge_window(state, &keys, Some(&pull.snapshot))?;

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
    let keys = SessionKeys::copy(state)?;

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
                let snapshot =
                    decrypt_snapshot_with_cek(&bytes, &cek).map_err(container_error)?;
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
            let merged = run_merge_window(state, &keys, Some(snapshot))?;
            {
                let changed = merged.changed;
                (snapshot.rev, etag.clone(), merged, changed)
            }
        }
        RemoteBasis::UpToDate { etag, rev } => {
            let merged = run_merge_window(state, &keys, None)?;
            let changed = sync_state
                .last_snapshot_hash
                .as_deref()
                .map(|hash| hash != content_hash(&merged.entries, &merged.groups))
                .unwrap_or(true);
            (*rev, etag.clone(), merged, changed)
        }
        RemoteBasis::Missing => {
            let merged = run_merge_window(state, &keys, None)?;
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

/// Download + parse the manifest; `None` when it does not exist yet.
fn fetch_manifest(
    backend: &dyn CloudBackend,
    paths: &RemotePaths,
) -> Result<Option<SyncManifest>, VaultError> {
    if backend.stat(&paths.manifest).map_err(backend_error)?.is_none() {
        return Ok(None);
    }
    let bytes = backend.download(&paths.manifest).map_err(backend_error)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| invalid_sync("SYNC_MANIFEST_CORRUPT", "The sync manifest is corrupt"))
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
