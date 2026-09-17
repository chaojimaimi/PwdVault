//! Encrypted sync container (D2) — the self-contained cloud object.
//!
//! One container file (`pwdvault-sync.pwsync`) carries the whole sync
//! snapshot under two independent credentials:
//!
//! - the **container password** derives `kdf_key` (Argon2id, adaptive
//!   params — the X6-clamped starting point keeps them at/above the import
//!   floor), which wraps the **container key (cek)**;
//! - the **cek** (32 random bytes, fixed for the container's lifetime)
//!   encrypts the snapshot.
//!
//! Serialization is JSON (deliberate, for container diagnosability — D2
//! decision; bincode was the alternative, one form is pinned by the
//! `version` field). Envelope shape:
//!
//! ```text
//! { version: 1, kdf: { salt, params }, wrapped_cek: EncryptedData,
//!   snapshot: EncryptedData }
//! ```
//!
//! Wrong password, corrupted bytes and tampering all collapse into a single
//! [`ContainerError::InvalidContainer`] (GCM cannot distinguish them and
//! merging the cases avoids a decryption oracle); only an unknown `version`
//! is reported separately as [`ContainerError::UnsupportedVersion`], and the
//! version gate runs before any key derivation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use pwdvault_infrastructure::crypto::{
    decrypt_with_aad, derive_key, derive_key_with_params, encrypt_with_aad, generate_salt,
    generate_wrap_key, unwrap_secret, wrap_secret, AdaptiveParams, EncryptedData, KEY_SIZE,
    SALT_SIZE, WRAP_AAD_CONTAINER,
};

use super::{SyncEntry, SyncGroup, SyncSnapshot};

/// Container format version (D2). v1 only interoperates with v1 — cross
/// app-version sync is gated here (see the dual-read notes in P2.1).
pub const CONTAINER_FORMAT_VERSION: u32 = 1;

/// AAD binding the snapshot blob to container-v1 semantics: a snapshot can
/// never be replayed under a different purpose or format version.
const SNAPSHOT_AAD: &[u8] = b"pwdvault-sync-container-snapshot-v1";

#[derive(Error, Debug)]
pub enum ContainerError {
    /// The bytes are not a readable container, the password is wrong, or the
    /// payload failed authentication — one variant by design (see module doc).
    #[error("Sync container is invalid or the password is incorrect")]
    InvalidContainer,

    /// The file declares a container format version this build does not
    /// understand (checked before any key derivation).
    #[error("Sync container version is not supported by this build")]
    UnsupportedVersion,
}

/// Container KDF record: salt + Argon2id parameters used for the container
/// password (written at creation, required verbatim to open).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerKdf {
    pub salt: [u8; SALT_SIZE],
    pub params: AdaptiveParams,
}

/// The v1 container envelope (serialized as JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncContainerV1 {
    pub version: u32,
    pub kdf: ContainerKdf,
    /// The container key (cek), wrapped under the container-password KDF key.
    pub wrapped_cek: EncryptedData,
    /// The full sync snapshot, encrypted under the cek.
    pub snapshot: EncryptedData,
}

/// Minimal envelope peek so the version gate runs before any crypto work.
#[derive(Deserialize)]
struct ContainerPeek {
    version: u32,
}

/// Create a container: derive the KDF key from the container password, wrap a
/// fresh random cek with it, and encrypt the snapshot under the cek.
pub fn create_container(
    container_password: Zeroizing<String>,
    snapshot: &SyncSnapshot,
) -> Result<Vec<u8>, ContainerError> {
    create_container_with_cek(container_password, snapshot).map(|(bytes, _cek)| bytes)
}

/// Like [`create_container`], but also returns the generated cek — the sync
/// engine needs it to store the key wrapped under the session enc subkey
/// (D2 `sync_cek` row) and to publish later revisions without the password.
pub fn create_container_with_cek(
    container_password: Zeroizing<String>,
    snapshot: &SyncSnapshot,
) -> Result<(Vec<u8>, Zeroizing<[u8; KEY_SIZE]>), ContainerError> {
    // derive_key benchmarks the adaptive params (~500 ms) — creation is a
    // rare, user-driven event; opening later reuses the stored params.
    let salt = generate_salt();
    let (mut kdf_key, params) = derive_key(container_password.as_str(), &salt)
        .map_err(|_| ContainerError::InvalidContainer)?;
    let result = seal_container(ContainerKdf { salt, params }, &kdf_key, snapshot);
    kdf_key.zeroize();
    result
}

/// Open a container: gate on the version, re-derive the KDF key from the
/// stored params + password, unwrap the cek, decrypt the snapshot.
pub fn open_container(
    container_password: Zeroizing<String>,
    bytes: &[u8],
) -> Result<SyncSnapshot, ContainerError> {
    unlock_container(container_password, bytes).map(|(snapshot, _cek)| snapshot)
}

/// Like [`open_container`], but also returns the unwrapped cek (sync engine
/// bootstrap — D2). The cek is `Zeroizing`; it never leaves memory in
/// plaintext outside this tuple.
pub fn unlock_container(
    container_password: Zeroizing<String>,
    bytes: &[u8],
) -> Result<(SyncSnapshot, Zeroizing<[u8; KEY_SIZE]>), ContainerError> {
    let container = parse_envelope(bytes)?;

    let (mut kdf_key, _) = derive_key_with_params(
        container_password.as_str(),
        &container.kdf.salt,
        &container.kdf.params,
    )
    .map_err(|_| ContainerError::InvalidContainer)?;
    let unwrapped = unwrap_secret(
        &kdf_key,
        &container.wrapped_cek.to_bytes(),
        WRAP_AAD_CONTAINER,
    );
    kdf_key.zeroize();
    let cek = unwrapped.map_err(|_| ContainerError::InvalidContainer)?;

    let snapshot = decrypt_snapshot(&container, &cek)?;
    Ok((snapshot, cek))
}

/// Version-gate + parse the envelope (shared by every entry point).
fn parse_envelope(bytes: &[u8]) -> Result<SyncContainerV1, ContainerError> {
    // Version gate FIRST, envelope only: an unknown version is a distinct,
    // user-facing "upgrade needed" condition and must be decided before any
    // key material is touched (also keeps it password-independent).
    let peek: ContainerPeek =
        serde_json::from_slice(bytes).map_err(|_| ContainerError::InvalidContainer)?;
    if peek.version != CONTAINER_FORMAT_VERSION {
        return Err(ContainerError::UnsupportedVersion);
    }
    serde_json::from_slice(bytes).map_err(|_| ContainerError::InvalidContainer)
}

/// Decrypt + parse the snapshot field with a known cek.
fn decrypt_snapshot(
    container: &SyncContainerV1,
    cek: &[u8; KEY_SIZE],
) -> Result<SyncSnapshot, ContainerError> {
    // Everything below fails identically: wrong cek, tampered snapshot, or a
    // corrupted inner structure.
    let mut snapshot_json = decrypt_with_aad(cek, &container.snapshot, SNAPSHOT_AAD)
        .map_err(|_| ContainerError::InvalidContainer)?;
    let parsed = serde_json::from_slice::<SyncSnapshot>(&snapshot_json)
        .map_err(|_| ContainerError::InvalidContainer);
    snapshot_json.zeroize();
    parsed
}

/// Decrypt the snapshot with a known cek, NO container password (the
/// `sync_now` path — the engine holds the cek unwrapped from the `sync_cek`
/// row and must stay password-free, D2).
pub fn decrypt_snapshot_with_cek(
    container_bytes: &[u8],
    cek: &[u8; KEY_SIZE],
) -> Result<SyncSnapshot, ContainerError> {
    let container = parse_envelope(container_bytes)?;
    decrypt_snapshot(&container, cek)
}

/// Re-encrypt the snapshot under the given cek, preserving the rest of the
/// envelope (version + kdf record + wrapped_cek). The sync engine publishes
/// a new revision this way: same container password/KDF, same cek, only the
/// snapshot ciphertext rotates.
pub fn update_container_snapshot(
    container_bytes: &[u8],
    cek: &[u8; KEY_SIZE],
    snapshot: &SyncSnapshot,
) -> Result<Vec<u8>, ContainerError> {
    let (kdf, wrapped_cek) = read_envelope(container_bytes)?;
    reseal_snapshot(kdf, wrapped_cek, cek, snapshot)
}

/// The envelope pieces the engine stores in its `sync_state` row so a
/// later revision can be published without re-downloading the container
/// (`sync_now`'s "remote rev unchanged" fast path).
pub fn read_envelope(
    container_bytes: &[u8],
) -> Result<(ContainerKdf, EncryptedData), ContainerError> {
    let container = parse_envelope(container_bytes)?;
    Ok((container.kdf, container.wrapped_cek))
}

/// Build container bytes from stored envelope pieces plus a freshly
/// encrypted snapshot (the inverse view of [`read_envelope`]).
pub fn reseal_snapshot(
    kdf: ContainerKdf,
    wrapped_cek: EncryptedData,
    cek: &[u8; KEY_SIZE],
    snapshot: &SyncSnapshot,
) -> Result<Vec<u8>, ContainerError> {
    let mut snapshot_json =
        serde_json::to_vec(snapshot).map_err(|_| ContainerError::InvalidContainer)?;
    let encrypted = encrypt_with_aad(cek, &snapshot_json, SNAPSHOT_AAD)
        .map_err(|_| ContainerError::InvalidContainer)?;
    snapshot_json.zeroize();
    let updated = SyncContainerV1 {
        version: CONTAINER_FORMAT_VERSION,
        kdf,
        wrapped_cek,
        snapshot: encrypted,
    };
    serde_json::to_vec(&updated).map_err(|_| ContainerError::InvalidContainer)
}

/// D3 tiebreak fingerprint: SHA-256 over the bincode serialization of a
/// [`SyncEntry`]. The byte form is pinned by this struct's field order — both
/// devices must run the same container format version (the container
/// `version` field gates cross-version sync, P3.8).
pub fn entry_fingerprint(entry: &SyncEntry) -> [u8; 32] {
    let encoded = bincode::serialize(entry)
        .expect("SyncEntry bincode encoding is infallible (no maps, no non-string keys)");
    Sha256::digest(&encoded).into()
}

/// Same fingerprint rule for groups (LWW tiebreak in [`super::merge`]).
pub(super) fn group_fingerprint(group: &SyncGroup) -> [u8; 32] {
    let encoded = bincode::serialize(group)
        .expect("SyncGroup bincode encoding is infallible (no maps, no non-string keys)");
    Sha256::digest(&encoded).into()
}

/// Seal with an already-derived KDF key record. The cek is generated here and
/// never leaves memory in plaintext (wrap output only) — it is returned to
/// the caller alongside the sealed bytes (bootstrap needs it for the
/// `sync_cek` row; `create_container` drops it).
fn seal_container(
    kdf: ContainerKdf,
    kdf_key: &[u8; 32],
    snapshot: &SyncSnapshot,
) -> Result<(Vec<u8>, Zeroizing<[u8; KEY_SIZE]>), ContainerError> {
    let cek = Zeroizing::new(generate_wrap_key());
    let mut snapshot_json =
        serde_json::to_vec(snapshot).map_err(|_| ContainerError::InvalidContainer)?;
    let encrypted_snapshot = encrypt_with_aad(&cek, &snapshot_json, SNAPSHOT_AAD)
        .map_err(|_| ContainerError::InvalidContainer)?;
    snapshot_json.zeroize();
    let wrapped_cek = wrap_secret(kdf_key, &cek, WRAP_AAD_CONTAINER)
        .map_err(|_| ContainerError::InvalidContainer)?;
    let container = SyncContainerV1 {
        version: CONTAINER_FORMAT_VERSION,
        kdf,
        wrapped_cek: EncryptedData::from_bytes(&wrapped_cek)
            .map_err(|_| ContainerError::InvalidContainer)?,
        snapshot: encrypted_snapshot,
    };
    let bytes = serde_json::to_vec(&container).map_err(|_| ContainerError::InvalidContainer)?;
    Ok((bytes, cek))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use pwdvault_infrastructure::crypto::WRAP_AAD_BIO;

    const PASSWORD: &str = "container-passphrase";
    const WRONG_PASSWORD: &str = "not-the-password";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(PASSWORD.to_string())
    }

    fn wrong_password() -> Zeroizing<String> {
        Zeroizing::new(WRONG_PASSWORD.to_string())
    }

    /// Backup-fixture pattern: weak explicit KDF params keep the rejection
    /// tests off the ~500 ms adaptive benchmark (the full production path is
    /// exercised once by the roundtrip test below).
    fn seal_with_weak_params(snapshot: &SyncSnapshot) -> Vec<u8> {
        seal_with_weak_params_and_cek(snapshot).0
    }

    /// Same fixture, but hands back the cek for the engine-facing helpers.
    fn seal_with_weak_params_and_cek(
        snapshot: &SyncSnapshot,
    ) -> (Vec<u8>, Zeroizing<[u8; KEY_SIZE]>) {
        let salt = [0x5A; SALT_SIZE];
        let params = AdaptiveParams {
            m_cost: 16384,
            t_cost: 1,
            p_cost: 1,
        };
        let (kdf_key, params) = derive_key_with_params(PASSWORD, &salt, &params).unwrap();
        seal_container(ContainerKdf { salt, params }, &kdf_key, snapshot).unwrap()
    }

    fn sample_snapshot() -> SyncSnapshot {
        SyncSnapshot {
            rev: 3,
            device_id: "device-a".to_string(),
            generated_at: 1_700_000_000,
            entries: vec![SyncEntry {
                id: "e1".to_string(),
                title: "Example".to_string(),
                url: Some("https://example.com".to_string()),
                username: "user".to_string(),
                password: Some("s3cret".to_string()),
                notes: Some("note".to_string()),
                totp_secret: None,
                tags: vec![],
                group_id: None,
                created_at: 1_700_000_000,
                updated_at: 1_700_000_050,
                deleted_at: None,
            }],
            groups: vec![],
        }
    }

    /// Flip one bit inside a nested byte-array field of the container JSON.
    fn mutate_byte(bytes: &[u8], path: &[&str], index: usize) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let mut target = &mut value;
        for key in path {
            target = &mut target[*key];
        }
        let old = target[index].as_u64().unwrap();
        target[index] = json!(old ^ 0x01);
        serde_json::to_vec(&value).unwrap()
    }

    /// P3.6 item 3: production roundtrip (the one test that pays the adaptive
    /// KDF benchmark) + envelope sanity.
    #[test]
    fn create_open_roundtrip_preserves_snapshot() {
        let snapshot = sample_snapshot();
        let bytes = create_container(password(), &snapshot).unwrap();
        let opened = open_container(password(), &bytes).unwrap();
        assert_eq!(opened, snapshot);

        let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(envelope["version"], json!(CONTAINER_FORMAT_VERSION));
        assert!(envelope["kdf"]["params"].is_object());
        assert!(envelope["wrapped_cek"]["nonce"].is_array());
        assert!(envelope["snapshot"]["ciphertext"].is_array());
    }

    /// P3.6 item 3: a wrong container password is rejected with the unified
    /// InvalidContainer error.
    #[test]
    fn wrong_container_password_is_rejected_as_invalid() {
        let bytes = seal_with_weak_params(&sample_snapshot());
        assert!(matches!(
            open_container(wrong_password(), &bytes),
            Err(ContainerError::InvalidContainer)
        ));
    }

    /// P3.6 item 3: GCM tampering anywhere in the trust chain (snapshot, cek
    /// wrap, KDF salt) is rejected — and indistinguishable from a wrong
    /// password (no oracle).
    #[test]
    fn tampered_container_is_rejected_as_invalid() {
        let bytes = seal_with_weak_params(&sample_snapshot());
        for path in [
            &["snapshot", "ciphertext"][..],
            &["snapshot", "nonce"][..],
            &["wrapped_cek", "ciphertext"][..],
            &["wrapped_cek", "nonce"][..],
            &["kdf", "salt"][..],
        ] {
            let mutated = mutate_byte(&bytes, path, 0);
            assert!(
                matches!(
                    open_container(password(), &mutated),
                    Err(ContainerError::InvalidContainer)
                ),
                "tampering {path:?} was not rejected"
            );
        }
        assert!(matches!(
            open_container(wrong_password(), &bytes),
            Err(ContainerError::InvalidContainer)
        ));
    }

    /// P3.6 item 3: an unknown version is a distinct error, decided before
    /// any crypto, regardless of the password.
    #[test]
    fn unknown_container_version_is_reported_before_crypto() {
        let bytes = seal_with_weak_params(&sample_snapshot());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["version"] = json!(CONTAINER_FORMAT_VERSION + 1);
        let future = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            open_container(password(), &future),
            Err(ContainerError::UnsupportedVersion)
        ));
        assert!(matches!(
            open_container(wrong_password(), &future),
            Err(ContainerError::UnsupportedVersion)
        ));
    }

    /// P3.6 item 3: garbage, versionless JSON, truncated envelopes and
    /// hostile KDF parameters all fail closed (the hostile-params case before
    /// Argon2 allocates anything).
    #[test]
    fn malformed_containers_are_rejected_as_invalid() {
        let password = password();
        assert!(matches!(
            open_container(password.clone(), b"garbage"),
            Err(ContainerError::InvalidContainer)
        ));
        assert!(matches!(
            open_container(password.clone(), b""),
            Err(ContainerError::InvalidContainer)
        ));
        assert!(matches!(
            open_container(password.clone(), br#"{"kdf":{}}"#),
            Err(ContainerError::InvalidContainer)
        ));
        assert!(matches!(
            open_container(password.clone(), br#"{"version":1}"#),
            Err(ContainerError::InvalidContainer)
        ));

        let bytes = seal_with_weak_params(&sample_snapshot());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["kdf"]["params"]["m_cost"] = json!(u32::MAX);
        value["kdf"]["params"]["t_cost"] = json!(u32::MAX);
        let hostile = serde_json::to_vec(&value).unwrap();
        let start = std::time::Instant::now();
        assert!(matches!(
            open_container(password, &hostile),
            Err(ContainerError::InvalidContainer)
        ));
        assert!(start.elapsed().as_millis() < 50);
    }

    /// P3.6 item 3 ("cek 引导 unwrap"): the cek unwraps with the wrap
    /// primitive under WRAP_AAD_CONTAINER — and under no other AAD — then
    /// decrypts the snapshot back to the exact JSON.
    #[test]
    fn cek_unwraps_via_wrap_primitive_with_aad_binding() {
        let snapshot = sample_snapshot();
        let bytes = seal_with_weak_params(&snapshot);
        let container: SyncContainerV1 = serde_json::from_slice(&bytes).unwrap();
        let (kdf_key, _) =
            derive_key_with_params(PASSWORD, &container.kdf.salt, &container.kdf.params).unwrap();

        let cek = unwrap_secret(
            &kdf_key,
            &container.wrapped_cek.to_bytes(),
            WRAP_AAD_CONTAINER,
        )
        .unwrap();
        assert!(unwrap_secret(&kdf_key, &container.wrapped_cek.to_bytes(), WRAP_AAD_BIO).is_err());

        let snapshot_json = decrypt_with_aad(&cek, &container.snapshot, SNAPSHOT_AAD).unwrap();
        assert_eq!(snapshot_json, serde_json::to_vec(&snapshot).unwrap());
    }

    /// The tiebreak fingerprint is deterministic and content-sensitive (the
    /// tiebreak symmetry itself is asserted in the merge tests).
    #[test]
    fn entry_fingerprint_is_deterministic_and_content_sensitive() {
        let a = sample_snapshot().entries.remove(0);
        let b = a.clone();
        assert_eq!(entry_fingerprint(&a), entry_fingerprint(&b));
        let mut c = a.clone();
        c.title = "Different".to_string();
        assert_ne!(entry_fingerprint(&a), entry_fingerprint(&c));
    }

    /// P3.3 engine support: `unlock_container` hands back the cek, which then
    /// re-seals a NEW snapshot revision without the password — and the
    /// cek-only path decrypts both the original and the updated container.
    #[test]
    fn cek_aware_helpers_reseal_and_decrypt_without_password() {
        let original = sample_snapshot();
        let (bytes, cek) = seal_with_weak_params_and_cek(&original);

        // unlock_container == open_container + cek.
        let (opened, unlocked_cek) = unlock_container(password(), &bytes).unwrap();
        assert_eq!(opened, original);
        assert_eq!(*unlocked_cek, *cek);

        // Password-free decrypt of the original container.
        assert_eq!(decrypt_snapshot_with_cek(&bytes, &cek).unwrap(), original);

        // Publish revision +1 under the same cek, keeping the KDF record.
        let mut next = original.clone();
        next.rev += 1;
        next.device_id = "device-b".to_string();
        let updated = update_container_snapshot(&bytes, &cek, &next).unwrap();

        // Envelope (version/kdf/wrapped_cek) preserved, snapshot replaced.
        let before: SyncContainerV1 = serde_json::from_slice(&bytes).unwrap();
        let after: SyncContainerV1 = serde_json::from_slice(&updated).unwrap();
        assert_eq!(after.version, before.version);
        assert_eq!(after.wrapped_cek.to_bytes(), before.wrapped_cek.to_bytes());
        assert_ne!(after.snapshot.to_bytes(), before.snapshot.to_bytes());
        // Old password still opens the updated container (same kdf).
        assert_eq!(open_container(password(), &updated).unwrap(), next);
        // And the cek-only path decrypts it too.
        assert_eq!(decrypt_snapshot_with_cek(&updated, &cek).unwrap(), next);

        // A wrong cek fails closed.
        let wrong = Zeroizing::new([0u8; KEY_SIZE]);
        assert!(matches!(
            decrypt_snapshot_with_cek(&updated, &wrong),
            Err(ContainerError::InvalidContainer)
        ));
        // Malformed bytes never panic the cek-only path.
        assert!(matches!(
            decrypt_snapshot_with_cek(b"junk", &cek),
            Err(ContainerError::InvalidContainer)
        ));
    }
}
