//! Sealed sync-row persistence (SEC-L2) — split out of [`super::state_io`]
//! in v1.6.0 (WP3) when that file hit the 800-line ceiling: the config/state
//! rows ([`super::state_io::SyncConfig`] / [`super::state_io::SyncState`])
//! are sealed AES-GCM blobs with a v1.1.x plaintext dual-read migration, and
//! this module owns their seal / parse / migrate / re-seal / save paths.
//! `state_io` re-exports the moved names so pre-split import paths keep
//! working (the M-3 engine-split precedent).

use std::sync::Arc;

use crate::service::security::SYNC_CEK_BLOB_KEY;
use crate::service::vault::get_db;
use crate::{AppState, VaultError};
use pwdvault_infrastructure::crypto::{
    bc_deserialize, bc_serialize, decrypt_with_aad, encrypt_with_aad, wrap_secret, EncryptedData,
    KEY_SIZE, WRAP_AAD_SYNC,
};
use pwdvault_infrastructure::database::vault_store::{self, VaultStore};

use super::state_io::{
    invalid_sync, SessionKeys, SyncConfig, SyncState, SYNC_CONFIG_BLOB_KEY, SYNC_STATE_BLOB_KEY,
};

// ---------------------------------------------------------------------------
// Config/state row IO (SEC-L2: sealed rows, legacy dual-read migration)
// ---------------------------------------------------------------------------

/// Magic prefix marking a sealed sync row (SEC-L2). Rows written by v1.2.0+
/// are `PREFIX || bincode(EncryptedData)`; rows WITHOUT the prefix are v1.1.x
/// plaintext JSON, still readable and migrated to sealed on first read.
pub(crate) const SYNC_ROW_ENC_PREFIX: &[u8] = b"PVSYNC1";

/// AAD format version for sealed sync rows (§5.1.4 record-format precedent).
const SYNC_ROW_FORMAT_VERSION: u32 = 1;

/// AAD binding a sealed sync row to its row key:
/// `table_name || row_key || format_version` (entry_codec precedent) — a row
/// swapped with its sibling (`sync_config` ↔ `sync_state`) fails GCM auth.
fn sync_row_aad(row_key: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"vault");
    aad.extend_from_slice(row_key.as_bytes());
    aad.extend_from_slice(&SYNC_ROW_FORMAT_VERSION.to_le_bytes());
    aad
}

/// Fail-closed corrupt-row error (both parse formats exhausted).
fn sync_row_corrupt(row_key: &str, detail: impl std::fmt::Display) -> VaultError {
    let code = if row_key == SYNC_CONFIG_BLOB_KEY {
        "SYNC_CONFIG_CORRUPT"
    } else {
        "SYNC_STATE_CORRUPT"
    };
    invalid_sync(code, format!("sync row {row_key} is corrupt: {detail}"))
}

/// Seal one sync row's JSON payload under the session enc subkey, with the
/// row-key AAD (SEC-L2; the sealed-row pattern of `save_entry_in_txn`).
fn seal_sync_row(enc: &[u8; KEY_SIZE], row_key: &str, json: &[u8]) -> Result<Vec<u8>, VaultError> {
    let sealed = encrypt_with_aad(enc, json, &sync_row_aad(row_key))?;
    let encoded = bc_serialize(&sealed).map_err(|e| VaultError::InternalError(e.to_string()))?;
    let mut row = SYNC_ROW_ENC_PREFIX.to_vec();
    row.extend_from_slice(&encoded);
    Ok(row)
}

/// Dual-format parse of one sync row (SEC-L2, LegacySettingsV1 precedent):
///
/// 1. sealed format — magic prefix + AES-GCM under `enc` with row-key AAD.
///    A prefixed row that fails to decrypt is corrupt immediately (a v1.2.0+
///    row must decrypt; falling through to JSON of the same bytes could only
///    fail too — fail-closed either way).
/// 2. legacy v1.1.x plaintext JSON — no prefix.
///
/// Returns the value plus whether the row was legacy (the load paths migrate
/// on read; the re-seal rotation re-seals both formats).
fn parse_sync_row<T: serde::de::DeserializeOwned>(
    enc: &[u8; KEY_SIZE],
    row_key: &str,
    bytes: &[u8],
) -> Result<(T, bool), VaultError> {
    if let Some(encoded) = bytes.strip_prefix(SYNC_ROW_ENC_PREFIX) {
        let sealed: EncryptedData = bc_deserialize(encoded)
            .or_else(|_| EncryptedData::from_bytes(encoded))
            .map_err(|e| sync_row_corrupt(row_key, e))?;
        let plain = decrypt_with_aad(enc, &sealed, &sync_row_aad(row_key))
            .map_err(|e| sync_row_corrupt(row_key, e))?;
        let value = serde_json::from_slice(&plain).map_err(|e| sync_row_corrupt(row_key, e))?;
        return Ok((value, false));
    }
    let value = serde_json::from_slice(bytes).map_err(|e| sync_row_corrupt(row_key, e))?;
    Ok((value, true))
}

/// Read-time migration (SEC-L2): a v1.1.x plaintext row that just parsed
/// through the legacy half of the dual read is immediately re-sealed in one
/// digest-covered transaction, so plaintext sync metadata survives on disk
/// only until its first read.
fn migrate_legacy_row(
    db: &Arc<redb::Database>,
    enc: &[u8; KEY_SIZE],
    mac: &[u8; KEY_SIZE],
    row_key: &str,
    legacy_bytes: &[u8],
) -> Result<(), VaultError> {
    let sealed = seal_sync_row(enc, row_key, legacy_bytes)?;
    VaultStore::new(db).write(mac, |txn| {
        vault_store::save_blob_in_txn(txn, row_key, &sealed)?;
        Ok(())
    })?;
    tracing::info!(
        row = row_key,
        "migrated legacy plaintext sync row to sealed format"
    );
    Ok(())
}

/// Load the sync config (sealed row + legacy dual-read, digest-covered).
pub(super) fn load_config(
    db: &Arc<redb::Database>,
    enc: &[u8; KEY_SIZE],
    mac: &[u8; KEY_SIZE],
) -> Result<Option<SyncConfig>, VaultError> {
    match vault_store::load_blob(db, SYNC_CONFIG_BLOB_KEY)? {
        None => Ok(None),
        Some(bytes) => {
            let (config, legacy) = parse_sync_row::<SyncConfig>(enc, SYNC_CONFIG_BLOB_KEY, &bytes)?;
            if legacy {
                migrate_legacy_row(db, enc, mac, SYNC_CONFIG_BLOB_KEY, &bytes)?;
            }
            Ok(Some(config))
        }
    }
}

/// Load the sync bookkeeping (sealed row + legacy dual-read, digest-covered).
pub(super) fn load_sync_state(
    db: &Arc<redb::Database>,
    enc: &[u8; KEY_SIZE],
    mac: &[u8; KEY_SIZE],
) -> Result<SyncState, VaultError> {
    match vault_store::load_blob(db, SYNC_STATE_BLOB_KEY)? {
        None => Ok(SyncState::default()),
        Some(bytes) => {
            let (state, legacy) = parse_sync_row::<SyncState>(enc, SYNC_STATE_BLOB_KEY, &bytes)?;
            if legacy {
                migrate_legacy_row(db, enc, mac, SYNC_STATE_BLOB_KEY, &bytes)?;
            }
            Ok(state)
        }
    }
}

/// Re-seal one sync row under a NEW enc subkey (SEC-L2 re-seal rotation,
/// called from `reseal_vault`). Dual-read parse covers BOTH formats: sealed
/// rows decrypt under `old_enc`, v1.1.x plaintext JSON rows parse directly —
/// ⛔ a bare ciphertext unwrap (the `sync_cek` pattern) is WRONG here: that
/// row is always ciphertext, while these two rows may still be unmigrated
/// plaintext, and a bare unwrap would abort the whole re-seal and break
/// change_password for users who upgraded without ever triggering the
/// read-time migration. Both formats failing to parse is a corrupt row and
/// aborts (fail-closed).
pub(crate) fn reseal_sync_row(
    old_enc: &[u8; KEY_SIZE],
    new_enc: &[u8; KEY_SIZE],
    row_key: &str,
    bytes: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let (value, _legacy) = parse_sync_row::<serde_json::Value>(old_enc, row_key, bytes)?;
    let json = serde_json::to_vec(&value).map_err(|e| VaultError::InternalError(e.to_string()))?;
    seal_sync_row(new_enc, row_key, &json)
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

    // CQ-P3c: serializing owned strings is infallible in practice — an
    // InternalError, not an EncryptionFailed (the AES-GCM seal below is what
    // can actually fail, and it reports through its own error mapping).
    let config_json =
        serde_json::to_vec(config).map_err(|e| VaultError::InternalError(e.to_string()))?;
    let state_json =
        serde_json::to_vec(sync_state).map_err(|e| VaultError::InternalError(e.to_string()))?;
    // SEC-L2: both rows are sealed under the session enc subkey (row-key AAD
    // binds each blob to its own key).
    let config_row = seal_sync_row(keys.enc_bytes(), SYNC_CONFIG_BLOB_KEY, &config_json)?;
    let state_row = seal_sync_row(keys.enc_bytes(), SYNC_STATE_BLOB_KEY, &state_json)?;
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
        vault_store::save_blob_in_txn(txn, SYNC_CONFIG_BLOB_KEY, &config_row)?;
        vault_store::save_blob_in_txn(txn, SYNC_STATE_BLOB_KEY, &state_row)?;
        if let Some(blob) = &cek_blob {
            vault_store::save_blob_in_txn(txn, SYNC_CEK_BLOB_KEY, blob)?;
        }
        Ok(())
    })?;
    Ok(())
}
