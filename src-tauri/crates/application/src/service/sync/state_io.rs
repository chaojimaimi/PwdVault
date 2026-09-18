//! Sync engine ground I/O (M-3 split of the former single-file engine —
//! pure move): the config/state rows ([`SyncConfig`], [`SyncState`]), the
//! local vault read/write-back the merge runs on, the session-key copies
//! ([`SessionKeys`]) that survive the D8 exclusive window, and the shared
//! helpers (error mapping, backend opening, validation, cloud file names).
//! Orchestration lives in [`super::engine`], the cloud pull/push paths in
//! [`super::publish`].

use std::sync::atomic::Ordering;
use std::sync::Arc;

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::service::security::SYNC_CEK_BLOB_KEY;
use crate::service::sync::backend::{BackendError, CloudBackend, WebDavBackend};
use crate::service::sync::baidu::BaiduBackend;
use crate::service::sync::baidu_oauth::baidu_configured;
use crate::service::sync::container::{ContainerError, ContainerKdf};
use crate::service::sync::merge::MergedSnapshot;
use crate::service::sync::{entries_to_sync, sync_to_entry, SyncEntry, SyncGroup, SyncSecrets};
use crate::service::vault::get_db;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::crypto::{
    decrypt, wrap_secret, EncryptedData, SecretKey, KEY_SIZE, WRAP_AAD_SYNC,
};
use pwdvault_infrastructure::database::{
    self,
    vault_store::{self, VaultStore},
    Group,
};
use pwdvault_infrastructure::keychain::{SecretStoreError, SYNC_WEBDAV_PASSWORD_ACCOUNT};

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

// ---------------------------------------------------------------------------
// Errors and small helpers
// ---------------------------------------------------------------------------

pub(super) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub(super) fn invalid_sync(code: &'static str, message: impl Into<String>) -> VaultError {
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
        BackendError::Network(message) => invalid_sync(
            "SYNC_NETWORK_ERROR",
            format!("Cloud request failed: {message}"),
        ),
        BackendError::NotConfigured => invalid_sync(
            "SYNC_BACKEND_NOT_CONFIGURED",
            "This sync backend is not available in this build",
        ),
    }
}

pub(super) fn container_error(err: ContainerError) -> VaultError {
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

pub(super) fn sync_secret_error(err: SecretStoreError) -> VaultError {
    match err {
        SecretStoreError::NotFound => invalid_sync(
            "SYNC_CREDENTIALS_MISSING",
            "Sync credentials are not stored — reconnect cloud sync",
        ),
        other => VaultError::KeychainError(other.to_string()),
    }
}

pub(super) fn not_configured() -> VaultError {
    invalid_sync(
        "SYNC_NOT_CONFIGURED",
        "Cloud sync is not set up on this device",
    )
}

/// Fresh device identity: 16 hex chars from the OS CSPRNG.
pub(super) fn new_device_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Envelope-free, order-insensitive content hash — the anti-echo basis when
/// the manifest rev says the remote did not change (P3.3).
pub(super) fn content_hash(entries: &[SyncEntry], groups: &[SyncGroup]) -> String {
    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by(|a, b| a.id.cmp(&b.id));
    let mut sorted_groups = groups.to_vec();
    sorted_groups.sort_by(|a, b| a.id.cmp(&b.id));
    let payload = serde_json::json!({ "entries": sorted_entries, "groups": sorted_groups });
    // A plain JSON document of owned strings serializes infallibly; the old
    // `unwrap_or_default()` silently turned a failure into an empty-payload
    // hash, which would corrupt the anti-echo comparison.
    to_hex(&Sha256::digest(
        serde_json::to_vec(&payload).expect("plain JSON snapshot serializes"),
    ))
}

/// Validate user-supplied configuration before anything touches the network.
/// The URL/username checks are WebDAV-specific — the Baidu backend gets its
/// endpoints from the build (OAuth pairing, P3.4), so only the remote
/// layout is user input there.
///
/// Plan C2 (https-only): plain http is rejected outright — Basic Auth would
/// carry the cloud-drive password in clear text. The check lives here and
/// at [`open_backend`], so BOTH production construction paths
/// (`sync_connect` and the previously-unchecked `sync_now`) enforce it.
pub(super) fn validate_config(config: &SyncConfig) -> Result<(), VaultError> {
    if matches!(config.backend, SyncBackendKind::Webdav) {
        let url = config.server_url.trim();
        let scheme_ok = url.starts_with("https://");
        if !scheme_ok
            || url.len() <= 8
            || url.len() > 2048
            || url.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(invalid_sync(
                "SYNC_INVALID_CONFIG",
                "WebDAV server URL must use https:// — plain http would expose \
                 your cloud-drive password",
            ));
        }
        if config.username.len() > 512 {
            return Err(invalid_sync("SYNC_INVALID_CONFIG", "Username is too long"));
        }
    }
    let dir = config.remote_dir.trim().trim_matches('/');
    if dir.len() > 512
        || dir
            .split('/')
            .any(|segment| segment.is_empty() || segment == "..")
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
pub(super) struct RemotePaths {
    pub(super) container: String,
    pub(super) manifest: String,
    pub(super) history_dir: String,
}

pub(super) fn remote_paths(config: &SyncConfig) -> RemotePaths {
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
///
/// Plan C2: this is the single PRODUCTION construction point (only callers:
/// `sync_connect` and `sync_now`; tests inject backends directly), so the
/// https-only validation runs here first — that seals the `sync_now` path,
/// which previously built its backend straight from the persisted config and
/// never saw `validate_config`. An already-persisted http config therefore
/// fails on the next sync with the guidance message instead of silently
/// continuing in the clear.
pub(super) fn open_backend(
    state: &Arc<AppState>,
    config: &SyncConfig,
) -> Result<Arc<dyn CloudBackend>, VaultError> {
    validate_config(config)?;
    match config.backend {
        SyncBackendKind::Webdav => {
            let password = state
                .sync_secret_store
                .get(SYNC_WEBDAV_PASSWORD_ACCOUNT)
                .map_err(sync_secret_error)?;
            let password = Zeroizing::new(String::from_utf8(password).map_err(|_| {
                invalid_sync(
                    "SYNC_CREDENTIALS_CORRUPT",
                    "Stored WebDAV password is not valid UTF-8",
                )
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
pub(super) struct LocalRows {
    pub(super) sync_entries: Vec<SyncEntry>,
    pub(super) sync_groups: Vec<SyncGroup>,
}

/// Decrypt one inner string field (bincode `EncryptedData` first, raw
/// nonce||ciphertext fallback — same resilient path as backup export).
fn decrypt_inner(enc: &[u8; KEY_SIZE], blob: &[u8]) -> Result<String, VaultError> {
    let sealed: EncryptedData = bincode::deserialize(blob)
        .or_else(|_| EncryptedData::from_bytes(blob))
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
    let mut plain = decrypt(enc, &sealed)?;
    let text =
        String::from_utf8(plain.clone()).map_err(|e| VaultError::DecryptionFailed(e.to_string()));
    plain.zeroize();
    text
}

/// Full local read (raw rows including tombstones — the merge input).
pub(super) fn read_local_rows(
    db: &Arc<redb::Database>,
    enc: &[u8; KEY_SIZE],
) -> Result<LocalRows, VaultError> {
    let entries = database::list_all_entries_bulk(db, enc, None)?;
    let groups = database::list_all_groups_bulk(db, enc)?;

    let mut secrets: std::collections::HashMap<String, SyncSecrets> =
        std::collections::HashMap::with_capacity(entries.len());
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
pub(super) fn write_merged_back(
    db: &Arc<redb::Database>,
    keys: &SessionKeys,
    local: &LocalRows,
    merged: &MergedSnapshot,
) -> Result<usize, VaultError> {
    let local_entries: std::collections::HashMap<&str, &SyncEntry> = local
        .sync_entries
        .iter()
        .map(|e| (e.id.as_str(), e))
        .collect();
    let local_groups: std::collections::HashMap<&str, &SyncGroup> = local
        .sync_groups
        .iter()
        .map(|g| (g.id.as_str(), g))
        .collect();

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
// D8 window key copies
// ---------------------------------------------------------------------------

/// Session key copies taken from a lease, kept alive past the exclusive
/// window and republished afterwards. `SecretKey` zeroizes on drop.
///
/// `generation` snapshots the session generation at copy time (review P1-1).
/// `VaultSession::unlock` bumps the live generation by EXACTLY one per call
/// and locking preserves it, so after the window's single republish
/// `generation` again matches the live session — meaning a LATER lease whose
/// generation differs proves a concurrent key rotation (change_password /
/// recover_vault) re-sealed the vault under NEW keys, and nothing may be
/// written with the copied material anymore.
pub(super) struct SessionKeys {
    enc: SecretKey,
    mac: SecretKey,
    generation: u64,
}

impl SessionKeys {
    /// Copy enc/mac out of the session and release the lease immediately —
    /// never hold a lease into `exclusive_lock_and_clear` (same-thread
    /// deadlock).
    pub(super) fn copy(state: &Arc<AppState>) -> Result<Self, VaultError> {
        let lease = state.lease()?;
        let keys = Self {
            enc: SecretKey::new(*lease.enc_key()?),
            mac: SecretKey::new(*lease.mac_key()?),
            generation: lease.generation(),
        };
        drop(lease);
        Ok(keys)
    }

    pub(super) fn enc_bytes(&self) -> &[u8; KEY_SIZE] {
        self.enc.as_ref()
    }

    pub(super) fn mac_bytes(&self) -> &[u8; KEY_SIZE] {
        self.mac.as_ref()
    }

    /// Republish the COPIED keys — sync never rotates them (review P3) —
    /// but ONLY while the window still owns the session (fix plan A §2.3):
    /// the lock epoch captured before the window's drain must be unchanged
    /// (a manual/auto lock during the window is never silently revoked) and
    /// the live generation must equal our copy's generation (review P1-1:
    /// a moved generation proves a concurrent re-seal published NEW keys —
    /// our stale material must not overwrite them; the digest pre-check in
    /// `VaultStore::write` already rejected our stale writes).
    ///
    /// Returns whether the publish happened. On `false` the copied keys are
    /// dropped (zeroized) and the session is left exactly as it was.
    pub(super) fn republish_if(&mut self, state: &Arc<AppState>, epoch_at_window: u64) -> bool {
        let expected_generation = self.generation;
        let published = state.session.unlock_if(
            SecretKey::new(*self.enc.as_ref()),
            SecretKey::new(*self.mac.as_ref()),
            |live_generation| {
                state.lock_epoch.load(Ordering::Acquire) == epoch_at_window
                    && live_generation == expected_generation
            },
        );
        if published {
            // `unlock_if` bumps the live generation by exactly one; tracking
            // it keeps `generation` equal to the session our keys own after
            // the window.
            self.generation += 1;
        }
        published
    }
}

// ---------------------------------------------------------------------------
// Config/state row IO (plaintext JSON blobs — digest-covered)
// ---------------------------------------------------------------------------

pub(super) fn load_config(db: &Arc<redb::Database>) -> Result<Option<SyncConfig>, VaultError> {
    match vault_store::load_blob(db, SYNC_CONFIG_BLOB_KEY)? {
        None => Ok(None),
        Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
            invalid_sync(
                "SYNC_CONFIG_CORRUPT",
                format!("sync config is corrupt: {e}"),
            )
        }),
    }
}

pub(super) fn load_sync_state(db: &Arc<redb::Database>) -> Result<SyncState, VaultError> {
    match vault_store::load_blob(db, SYNC_STATE_BLOB_KEY)? {
        None => Ok(SyncState::default()),
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| invalid_sync("SYNC_STATE_CORRUPT", format!("sync state is corrupt: {e}"))),
    }
}

/// Persist config/state rows (and optionally the wrapped cek) in ONE
/// transaction via `VaultStore::write` so the digest covers them.
///
/// P1-1 stale-key guard: the copied keys were taken before the D8 window.
/// If the session generation has moved past our own republish, a concurrent
/// change_password / recover_vault re-sealed the vault under NEW keys —
/// refreshing the digest (or the `sync_cek` wrap) with the copied OLD keys
/// here would leave the vault undecryptable under the new password. The
/// save is then abandoned and reported as SUCCESS: only sync bookkeeping is
/// lost, and the next cycle re-reads the remote rev and converges.
pub(super) fn save_sync_rows(
    state: &Arc<AppState>,
    keys: &SessionKeys,
    config: &SyncConfig,
    sync_state: &SyncState,
    cek: Option<&[u8; KEY_SIZE]>,
) -> Result<(), VaultError> {
    // Re-lease OUTSIDE the window (the session was republished, so this
    // succeeds unless the vault was locked again) and require OUR session:
    // exactly our own republish may have moved the generation past the copy.
    let lease = match state.lease() {
        Ok(lease) => lease,
        Err(_) => {
            tracing::warn!("sync bookkeeping save skipped: session no longer unlocked");
            return Ok(());
        }
    };
    if lease.generation() != keys.generation {
        tracing::warn!(
            copied_generation = keys.generation,
            session_generation = lease.generation(),
            "sync bookkeeping save skipped: keys were rotated by a concurrent re-seal"
        );
        return Ok(());
    }

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
    // The lease is HELD across the write: a concurrent re-seal parks at its
    // exclusive drain until this transaction has committed under the
    // verified-current mac, so keys cannot rotate mid-write.
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
