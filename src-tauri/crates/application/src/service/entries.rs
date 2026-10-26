use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::service::vault::get_db;
use crate::{
    validation, AppState, CreateEntryRequest, CustomField, CustomFieldInput, CustomFieldValue,
    EntrySecretResponse, EntrySummary, UpdateEntryRequest, VaultError, VerifyEntryPasswordRequest,
    VerifyEntryPasswordResponse,
};
use pwdvault_domain::constants::LAST_USED_BUMP_THROTTLE_SECS;
use pwdvault_infrastructure::crypto::{
    bc_deserialize, bc_serialize, decrypt, encrypt, EncryptedData,
};
use pwdvault_infrastructure::database;
use pwdvault_infrastructure::database::{
    list_all_entries_bulk, load_entry, vault_store, PasswordEntry,
};

pub fn create_entry(
    state: &Arc<AppState>,
    request: CreateEntryRequest,
) -> Result<EntrySummary, VaultError> {
    let mut request = request;
    request.url = validation::normalize_url(request.url);
    let lease = state.lease()?;
    validation::entry(&request)?;

    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;
    if let Some(group_id) = &request.group_id {
        if database::load_group(&db, key, group_id, false)?.is_none() {
            return Err(VaultError::InvalidInput {
                code: "UNKNOWN_GROUP".into(),
                message: "Group does not exist".into(),
            });
        }
    }

    // Encrypt password and notes BEFORE opening the write transaction,
    // so crypto failures roll back cleanly without holding the write lock.
    let encrypted_password = encrypt(key, request.password.as_bytes())?;
    let encrypted_password_bytes = bc_serialize(&encrypted_password)
        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

    let encrypted_notes = if let Some(notes) = &request.notes {
        let encrypted = encrypt(key, notes.as_bytes())?;
        let bytes =
            bc_serialize(&encrypted).map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        Some(bytes)
    } else {
        None
    };

    let mut entry = PasswordEntry::new(request.title, request.url, request.username);
    entry.encrypted_password = encrypted_password_bytes;
    entry.encrypted_notes = encrypted_notes;
    entry.tags = request.tags;
    entry.group_id = request.group_id;
    // v1.5.0 WP4: per-entry URL match override.
    entry.url_match_mode = request.url_match_mode;
    // v1.6.0: custom fields arrive as plaintext inputs and seal here (the
    // create request is complete — there is no tri-state on create).
    entry.custom_fields = seal_custom_fields(key, &request.custom_fields)?;

    // Single transaction: business write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_entry_in_txn(txn, key, &entry)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(entry.into())
}

pub fn get_entry_meta(state: &Arc<AppState>, id: String) -> Result<EntrySummary, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let entry = load_entry(&db, key, &id, false)?.ok_or(VaultError::EntryNotFound)?;
    // Soft delete (P2.2): a tombstoned entry is invisible to callers.
    if entry.deleted_at.is_some() {
        return Err(VaultError::EntryNotFound);
    }

    lease.touch_remote_activity();

    Ok(entry.into())
}

pub fn get_entry_secret(
    state: &Arc<AppState>,
    id: String,
) -> Result<EntrySecretResponse, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mut entry = load_entry(&db, key, &id, false)?.ok_or(VaultError::EntryNotFound)?;
    // Soft delete (P2.2): a tombstoned entry must not give up its secrets —
    // same filter as get_entry_meta (this is the extension's secret-fetch
    // path; the row survives for merge/reseal, but reads must 404).
    if entry.deleted_at.is_some() {
        return Err(VaultError::EntryNotFound);
    }

    // Decrypt password. Try bincode format first (v1.0.5+ and v1.0.4 both use
    // bc_serialize(EncryptedData)), then fall back to raw bytes
    // (nonce||ciphertext) just in case an older build used to_bytes().
    let encrypted_password: EncryptedData =
        bc_deserialize(&entry.encrypted_password).or_else(|e| {
            EncryptedData::from_bytes(&entry.encrypted_password)
                .map_err(|e2| VaultError::DecryptionFailed(format!("bincode: {} / raw: {}", e, e2)))
        })?;
    let mut password_bytes = decrypt(key, &encrypted_password)?;
    let password = Zeroizing::new(
        String::from_utf8(password_bytes.clone())
            .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?,
    );

    // Decrypt notes if present
    let notes = if let Some(encrypted_notes_bytes) = &entry.encrypted_notes {
        let encrypted: EncryptedData = bc_deserialize(encrypted_notes_bytes).or_else(|e| {
            EncryptedData::from_bytes(encrypted_notes_bytes)
                .map_err(|e2| VaultError::DecryptionFailed(format!("bincode: {} / raw: {}", e, e2)))
        })?;
        let mut notes_bytes = decrypt(key, &encrypted)?;
        let notes_str = Zeroizing::new(
            String::from_utf8(notes_bytes.clone())
                .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?,
        );
        notes_bytes.zeroize();
        Some(notes_str)
    } else {
        None
    };

    // Zeroize intermediate password bytes
    password_bytes.zeroize();

    // v1.6.0: decrypt every custom-field value through the same one-shot
    // channel as password/notes.
    let custom_fields = decrypt_custom_field_values(key, &entry.custom_fields)?;

    // v1.4.0: restored the last_used_at persistence that §5.1.2 removed,
    // behind a 60-second write throttle. §5.1.2's complaint was write
    // amplification (every fetch = entry re-seal + full digest refresh); the
    // throttle reduces that to at most one write per entry per minute, gated
    // by the CURRENT stored value alone (no extra state).
    // SYNC SEMANTICS (deliberate, review-verified): the bump explicitly does
    // NOT touch updated_at. last_used_at is device-local metadata —
    // `SyncEntry` has no such field (sync/mod.rs), so a pure bump never
    // changes the sync payload, never triggers a push, and never moves the
    // LWW fingerprint. When a merge DOES rewrite a row, the winner's payload
    // carries last_used_at=None and the local value resets — accepted
    // best-effort behavior for a device-local field. Pinned by tests:
    // `get_entry_secret_throttles_last_used_at_writes` (service) and the NM
    // contract test.
    let now = chrono::Utc::now().timestamp();
    if entry
        .last_used_at
        .is_none_or(|last| now - last > LAST_USED_BUMP_THROTTLE_SECS)
    {
        entry.last_used_at = Some(now);
        let mac_key = lease.mac_key()?;
        // Single transaction: bump + digest refresh (§5.1.2 pattern).
        vault_store::VaultStore::new(&db).write(mac_key, |txn| {
            vault_store::save_entry_in_txn(txn, key, &entry)?;
            Ok(())
        })?;
    }

    lease.touch_remote_activity();

    Ok(EntrySecretResponse {
        password,
        notes,
        last_used_at: entry.last_used_at,
        custom_fields,
    })
}

/// Seal plaintext custom-field inputs into their stored form (v1.6.0 WP1):
/// label/secret stay plaintext under the outer entry blob, each value is
/// inner-encrypted like `encrypted_notes`. An empty plaintext skips
/// encryption and stores the empty-vec placeholder row.
pub(crate) fn seal_custom_fields(
    key: &[u8; 32],
    fields: &[CustomFieldInput],
) -> Result<Vec<CustomField>, VaultError> {
    fields
        .iter()
        .map(|field| -> Result<CustomField, VaultError> {
            Ok(CustomField {
                label: field.label.clone(),
                value: if field.value.is_empty() {
                    Vec::new()
                } else {
                    let encrypted = encrypt(key, field.value.as_bytes())?;
                    bc_serialize(&encrypted)
                        .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?
                },
                secret: field.secret,
            })
        })
        .collect()
}

/// Decrypt every custom-field value for a secret fetch (v1.6.0 WP1). This is
/// the ONLY disclosure channel for custom-field values — summaries carry
/// label + secret flag exclusively. An empty ciphertext vec is the legal
/// placeholder row and reads back as the empty plaintext. The dual-path
/// (bincode then raw bytes) matches this function's password/notes convention.
fn decrypt_custom_field_values(
    key: &[u8; 32],
    fields: &[CustomField],
) -> Result<Vec<CustomFieldValue>, VaultError> {
    fields
        .iter()
        .map(|field| -> Result<CustomFieldValue, VaultError> {
            let value = if field.value.is_empty() {
                Zeroizing::new(String::new())
            } else {
                let encrypted: EncryptedData = bc_deserialize(&field.value).or_else(|e| {
                    EncryptedData::from_bytes(&field.value).map_err(|e2| {
                        VaultError::DecryptionFailed(format!("bincode: {} / raw: {}", e, e2))
                    })
                })?;
                let mut value_bytes = decrypt(key, &encrypted)?;
                let result = String::from_utf8(value_bytes.clone())
                    .map_err(|e| VaultError::DecryptionFailed(e.to_string()));
                value_bytes.zeroize();
                result.map(Zeroizing::new)?
            };
            Ok(CustomFieldValue {
                label: field.label.clone(),
                value,
                secret: field.secret,
            })
        })
        .collect()
}

/// Verify a candidate password against a stored entry WITHOUT disclosing it
/// (v1.6.0 WP3 / D7 — the extension save/update prompt's desktop pivot).
/// The caller supplies the SHA-256 of the candidate (hashed client-side, in
/// the page context where the user typed it); this decrypts the stored
/// password, hashes the raw bytes, and answers with a bare boolean under a
/// constant-time comparison.
///
/// Disclosure posture: the stored plaintext stays inside this function
/// (zeroized immediately after hashing), is never converted to a `String`
/// (the raw decrypted bytes hash directly — no UTF-8 round-trip), and
/// NOTHING but the boolean leaves. Deliberately NOT bumping `last_used_at`
/// (same reasoning as the security report bypassing it): verification runs
/// once per form-submit candidate, and the resulting write amplification
/// would dwarf the value of the signal.
pub fn verify_entry_password(
    state: &Arc<AppState>,
    request: VerifyEntryPasswordRequest,
) -> Result<VerifyEntryPasswordResponse, VaultError> {
    validation::id(&request.id)?;
    let candidate = parse_sha256_digest(&request.password_sha256)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let entry = load_entry(&db, key, &request.id, false)?.ok_or(VaultError::EntryNotFound)?;
    // Soft delete (P2.2): tombstoned entries answer EntryNotFound, exactly
    // like get_entry_meta/get_entry_secret — no secret material from trash.
    if entry.deleted_at.is_some() {
        return Err(VaultError::EntryNotFound);
    }

    // Dual-path parse (bincode first, raw nonce||ciphertext fallback) — the
    // same convention as get_entry_secret's password path.
    let encrypted: EncryptedData = bc_deserialize(&entry.encrypted_password).or_else(|e| {
        EncryptedData::from_bytes(&entry.encrypted_password)
            .map_err(|e2| VaultError::DecryptionFailed(format!("bincode: {} / raw: {}", e, e2)))
    })?;
    let mut stored_bytes = decrypt(key, &encrypted)?;
    let stored_digest = Sha256::digest(&stored_bytes);
    // Constant-time comparison (subtle::ConstantTimeEq): the digest never
    // branches on a byte difference, so response timing cannot be used to
    // reconstruct a matching prefix of the candidate hash.
    let matches = bool::from(stored_digest.as_slice().ct_eq(candidate.as_slice()));
    stored_bytes.zeroize();

    // Explicit vault op (may arrive over the extension bridge): the short
    // remote grace applies (v1.2.0 SEC-L5 touch policy).
    lease.touch_remote_activity();

    Ok(VerifyEntryPasswordResponse { matches })
}

/// Decode a SHA-256 hex digest to its 32 bytes. Case-insensitive (both hex
/// registers accepted — the normalization the service tests pin); wrong
/// length or non-hex characters are rejected as invalid input.
fn parse_sha256_digest(hex: &str) -> Result<[u8; 32], VaultError> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(invalid_digest());
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let high = hex_char_value(bytes[index * 2])?;
        let low = hex_char_value(bytes[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(digest)
}

fn hex_char_value(byte: u8) -> Result<u8, VaultError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(invalid_digest()),
    }
}

fn invalid_digest() -> VaultError {
    VaultError::InvalidInput {
        code: "INVALID_PASSWORD_DIGEST".into(),
        message: "Password digest must be 64 hex characters (SHA-256)".into(),
    }
}

pub fn list_all_entries(state: &Arc<AppState>) -> Result<Vec<EntrySummary>, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;

    // §5.6.2: single read transaction bulk scan instead of 1+N.
    // Soft delete (P2.2): the infra bulk scan is raw (reseal_vault depends on
    // it); the service layer filters tombstones out here. The filter is
    // tombstone-only and deliberately ignores the purge ledger — a LIVE row
    // is served no matter what the ledger says.
    let entries = list_all_entries_bulk(&db, key, None)?
        .into_iter()
        .filter(|entry| entry.deleted_at.is_none())
        .collect::<Vec<_>>();

    // Purge-ledger reconciliation (v1.4.0): a LIVE row whose id is recorded
    // proves a merge revival / import resurrected the entry after a purge.
    // The row was served above (no live-row filtering); here the stale
    // ledger records are dropped so a LATER tombstone shows up in the trash
    // again — otherwise every sync would re-suppress it (= silent data
    // loss). Best-effort: a failed reconciliation only delays the cleanup to
    // the next successful list.
    reconcile_purged_ledger(&db, &lease, &entries)?;

    let summaries: Vec<EntrySummary> = entries.into_iter().map(Into::into).collect();

    lease.touch_remote_activity();

    Ok(summaries)
}

/// Drop ledger records for ids that now exist as LIVE rows (see
/// [`list_all_entries`]). Errors are logged and swallowed: the ledger is
/// local bookkeeping, the caller's read result stays valid either way.
fn reconcile_purged_ledger(
    db: &Arc<redb::Database>,
    lease: &crate::session::SessionLease<'_>,
    live_entries: &[PasswordEntry],
) -> Result<(), VaultError> {
    let purged = vault_store::purged_entry_ids(db)?;
    let stale_ids: Vec<String> = live_entries
        .iter()
        .filter(|entry| purged.contains(&entry.id))
        .map(|entry| entry.id.clone())
        .collect();
    if stale_ids.is_empty() {
        return Ok(());
    }
    let mac_key = lease.mac_key()?;
    let outcome = vault_store::VaultStore::new(db).write(mac_key, |txn| {
        for id in &stale_ids {
            vault_store::remove_purged_entry_in_txn(txn, id)?;
        }
        Ok(())
    });
    if let Err(error) = outcome {
        tracing::warn!("purge-ledger reconciliation failed: {error}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Trash (v1.4.0): soft-deleted entries. Tauri IPC only — the browser
// extension never sees the trash (D6, touch_activity precedent).
// ---------------------------------------------------------------------------

/// Tombstoned entries still visible in the trash: `deleted_at` set AND the id
/// not recorded in the purge ledger (ledger entries are rows a sync cycle
/// re-inserted after a physical delete — invisible by design).
pub fn list_deleted_entries(state: &Arc<AppState>) -> Result<Vec<EntrySummary>, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;

    let purged = vault_store::purged_entry_ids(&db)?;
    let entries = list_all_entries_bulk(&db, key, None)?
        .into_iter()
        .filter(|entry| entry.deleted_at.is_some())
        .filter(|entry| !purged.contains(&entry.id))
        .collect::<Vec<_>>();
    let summaries: Vec<EntrySummary> = entries.into_iter().map(Into::into).collect();

    lease.touch_remote_activity();

    Ok(summaries)
}

/// Restore a tombstoned entry. The `updated_at` bump is REQUIRED, not
/// cosmetic: LWW arbitration (merge.rs `merge_entry_pair`) lets a tombstone
/// win only when `deleted_at >= loser.updated_at` — the restore must present
/// itself as the newest change so a remote tombstone loses and the revival
/// sticks through the next sync.
pub fn restore_entry(state: &Arc<AppState>, id: String) -> Result<EntrySummary, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    let mut entry = load_entry(&db, key, &id, false)?.ok_or(VaultError::EntryNotFound)?;
    // Restoring a live entry is a caller bug, not a no-op.
    if entry.deleted_at.is_none() {
        return Err(VaultError::InvalidInput {
            code: "ENTRY_NOT_DELETED".into(),
            message: "Entry is not in the trash".into(),
        });
    }

    entry.deleted_at = None;
    entry.updated_at = chrono::Utc::now().timestamp();

    // Single transaction: revival + digest refresh + ledger cleanup (the row
    // is live again, so any stale purge record must go with it).
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_entry_in_txn(txn, key, &entry)?;
        vault_store::remove_purged_entry_in_txn(txn, &entry.id)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(entry.into())
}

/// Physically delete one tombstoned row and record the id in the purge
/// ledger (same transaction — a crash must never leave a deleted row without
/// its ledger record, or the next sync refills the trash). Purging a LIVE
/// entry is refused: the trash flow only ever offers tombstones.
pub fn purge_entry(state: &Arc<AppState>, id: String) -> Result<bool, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    let entry = load_entry(&db, key, &id, false)?;
    match entry {
        None => {
            // Row already gone: idempotent success only if this exact id was
            // purged before; a never-seen id is a caller bug.
            if vault_store::purged_entry_ids(&db)?.contains(&id) {
                Ok(false)
            } else {
                Err(VaultError::EntryNotFound)
            }
        }
        Some(entry) => {
            if entry.deleted_at.is_none() {
                return Err(VaultError::InvalidInput {
                    code: "ENTRY_NOT_DELETED".into(),
                    message: "Only deleted entries can be purged".into(),
                });
            }
            let now = chrono::Utc::now().timestamp();
            let entry_id = entry.id.clone();
            let store = vault_store::VaultStore::new(&db);
            store.write(mac_key, |txn| {
                vault_store::remove_entry_in_txn(txn, &entry_id)?;
                vault_store::record_purged_entries_in_txn(
                    txn,
                    std::slice::from_ref(&entry_id),
                    now,
                )?;
                Ok(())
            })?;
            lease.touch_remote_activity();
            Ok(true)
        }
    }
}

/// Physically delete EVERY tombstoned row (including ledger-suppressed ones
/// — their rows are sync refills that would otherwise linger forever) and
/// record all ids. Returns the number of rows removed.
pub fn empty_trash(state: &Arc<AppState>) -> Result<usize, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    let tombstone_ids: Vec<String> = list_all_entries_bulk(&db, key, None)?
        .into_iter()
        .filter(|entry| entry.deleted_at.is_some())
        .map(|entry| entry.id)
        .collect();
    if tombstone_ids.is_empty() {
        return Ok(0);
    }

    let now = chrono::Utc::now().timestamp();
    let count = tombstone_ids.len();
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        for id in &tombstone_ids {
            vault_store::remove_entry_in_txn(txn, id)?;
        }
        vault_store::record_purged_entries_in_txn(txn, &tombstone_ids, now)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(count)
}

pub fn update_entry<R: Into<UpdateEntryRequest>>(
    state: &Arc<AppState>,
    id: String,
    request: R,
) -> Result<EntrySummary, VaultError> {
    let mut request = request.into();
    request.url = validation::normalize_url(request.url);
    let lease = state.lease()?;
    validation::id(&id)?;
    validation::entry_update(&request)?;

    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;
    if let Some(group_id) = &request.group_id {
        if database::load_group(&db, key, group_id, false)?.is_none() {
            return Err(VaultError::InvalidInput {
                code: "UNKNOWN_GROUP".into(),
                message: "Group does not exist".into(),
            });
        }
    }

    let mut entry = load_entry(&db, key, &id, false)?.ok_or(VaultError::EntryNotFound)?;
    // Soft delete (P2.2): editing a tombstoned entry must not resurrect it.
    if entry.deleted_at.is_some() {
        return Err(VaultError::EntryNotFound);
    }

    // Update fields
    entry.title = request.title;
    entry.url = request.url;
    entry.username = request.username;
    entry.tags = request.tags;
    entry.group_id = request.group_id;
    // v1.5.0 WP4: the match override is replaced wholesale (metadata
    // semantics, same as title/url/tags).
    entry.url_match_mode = request.url_match_mode;
    entry.updated_at = chrono::Utc::now().timestamp();

    // Only replace sensitive fields explicitly included in the patch.
    if let Some(password) = &request.password {
        let encrypted_password = encrypt(key, password.as_bytes())?;
        entry.encrypted_password = bc_serialize(&encrypted_password)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
    }

    // Encrypt and update notes
    if request.update_notes {
        entry.encrypted_notes = if let Some(notes) = &request.notes {
            let encrypted = encrypt(key, notes.as_bytes())?;
            Some(
                bc_serialize(&encrypted)
                    .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?,
            )
        } else {
            None
        };
    }

    // TOTP tri-state (P2.4): None = leave unchanged, Some("") = clear,
    // Some(x) = encrypt and set (plain base32 or a whole otpauth:// URI —
    // the code generator parses either at read time).
    if let Some(totp_secret) = &request.totp_secret {
        entry.encrypted_totp_secret = if totp_secret.is_empty() {
            None
        } else {
            let encrypted = encrypt(key, totp_secret.as_bytes())?;
            Some(
                bc_serialize(&encrypted)
                    .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?,
            )
        };
    }

    // Custom fields tri-state batch (v1.6.0): None = leave unchanged, so a
    // metadata-only edit never needs the plaintext values it does not hold;
    // Some(list) = seal and replace wholesale (same metadata semantics as
    // tags).
    if let Some(custom_fields) = &request.custom_fields {
        entry.custom_fields = seal_custom_fields(key, custom_fields)?;
    }

    // Single transaction: business write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_entry_in_txn(txn, key, &entry)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(entry.into())
}

pub fn remove_entry(state: &Arc<AppState>, id: String) -> Result<bool, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    // Soft delete (P2.2): stamp a tombstone and keep the row. The row must
    // survive so multi-device merge (P3.1) can arbitrate the deletion against
    // concurrent edits, and reseal_vault keeps seeing a consistent table.
    let mut entry = match load_entry(&db, key, &id, false)? {
        Some(entry) => entry,
        None => return Ok(false),
    };
    let now = chrono::Utc::now().timestamp();
    entry.deleted_at = Some(now);
    // Bump updated_at so LWW merge arbitration sees the delete as the newest
    // change ("deleted_at >= remote.updated_at → delete wins").
    entry.updated_at = now;

    // Single transaction: tombstone write + digest refresh (§5.1.2)
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        vault_store::save_entry_in_txn(txn, key, &entry)?;
        Ok(())
    })?;

    lease.touch_remote_activity();

    Ok(true)
}

pub fn get_entry_count(state: &Arc<AppState>) -> Result<usize, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;

    // Soft delete (P2.2): count live entries only, decrypting each row (the
    // raw table length would report tombstones the user can no longer see —
    // review P2 fix for the extension count).
    let count = list_all_entries_bulk(&db, key, None)?
        .iter()
        .filter(|entry| entry.deleted_at.is_none())
        .count();

    lease.touch_remote_activity();

    Ok(count)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
#[path = "entries/tests_custom_fields.rs"]
mod tests_custom_fields;
#[cfg(test)]
#[path = "entries/tests_verify_password.rs"]
mod tests_verify_password;
