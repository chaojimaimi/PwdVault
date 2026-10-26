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
//! { version: 3, kdf: { salt, params }, wrapped_cek: EncryptedData,
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
    bc_serialize, decrypt_with_aad, derive_key, derive_key_with_params, encrypt_with_aad,
    generate_salt, generate_wrap_key, unwrap_secret, wrap_secret, AdaptiveParams, EncryptedData,
    KEY_SIZE, SALT_SIZE, WRAP_AAD_CONTAINER,
};

use super::{SyncEntry, SyncGroup, SyncSnapshot};

/// Container format version (D2). Written exclusively since v1.5.0 (WP4:
/// `SyncEntry` gained `url_match_mode`, which changes the bincode LWW
/// fingerprint input — two devices must agree on the fingerprint bytes, so a
/// v1.4.x peer opening a v2 container must fail cleanly at the version gate
/// instead of silently stripping the new field on republish). Bumped again in
/// v1.6.0 (WP1): `SyncEntry` gained `custom_fields`, changing the fingerprint
/// input once more — a v1.5.x peer opening a v3 container must fail cleanly
/// at the version gate for the same reason (the v1.5.0 precedent, extended to
/// three generations). Read side accepts v1 and v2 as well: see
/// `SUPPORTED_READ_VERSIONS`.
pub const CONTAINER_FORMAT_VERSION: u32 = 3;

/// Versions this build can READ. v1 = containers written by pre-v1.5.0
/// builds (their serde_json snapshots lack `url_match_mode`; the serde
/// default lands those entries on Auto — no legacy struct needed). v2 =
/// v1.5.0–v1.5.1 containers (their snapshots lack `custom_fields`; the serde
/// default lands those entries on an empty vec — pinned by the permanent
/// V2_CONTAINER_HEX fixture in `tests_container_v2_fixture`). v3 = the
/// current format. The AAD constants are deliberately NOT versioned for the
/// bumps: same SNAPSHOT_AAD/WRAP_AAD_CONTAINER keeps v1 bytes decryptable.
const SUPPORTED_READ_VERSIONS: [u32; 3] = [1, 2, CONTAINER_FORMAT_VERSION];

/// AAD binding the snapshot blob to container semantics: a snapshot can
/// never be replayed under a different purpose. Kept at the v1 value across
/// the format bump so v1 containers stay readable (see
/// `SUPPORTED_READ_VERSIONS`).
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
    // key material is touched (also keeps it password-independent). Both
    // readable generations pass (see SUPPORTED_READ_VERSIONS); anything
    // else — including containers written by a NEWER build — fails here.
    let peek: ContainerPeek =
        serde_json::from_slice(bytes).map_err(|_| ContainerError::InvalidContainer)?;
    if !SUPPORTED_READ_VERSIONS.contains(&peek.version) {
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
#[cfg(test)]
pub(crate) fn update_container_snapshot(
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
    let encoded = bc_serialize(entry)
        .expect("SyncEntry bincode encoding is infallible (no maps, no non-string keys)");
    Sha256::digest(&encoded).into()
}

/// Same fingerprint rule for groups (LWW tiebreak in [`super::merge`]).
pub(super) fn group_fingerprint(group: &SyncGroup) -> [u8; 32] {
    let encoded = bc_serialize(group)
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
    use pwdvault_domain::UrlMatchMode;
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
                url_match_mode: UrlMatchMode::Auto,
                custom_fields: vec![],
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
        // A version NEITHER readable generation accepts (4 = newer than this
        // build). Version 1 readability is pinned by the permanent fixture
        // below, version 2 by `tests_container_v2_fixture`.
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

    /// PERMANENT FIXTURE — NEVER RECAPTURE (v1.5.0 WP4).
    ///
    /// Real bytes of a container written by the v1 format path (pre-v1.5.0:
    /// `version: 1`, snapshot JSON WITHOUT `url_match_mode`), captured with
    /// `create_container` immediately before the 1→2 version bump for the
    /// sample snapshot asserted below. Recapturing this constant against any
    /// newer writer would launder a v1-readability regression — the exact P0
    /// class the v1.5.0 plan review exists to prevent. If this test goes
    /// red, the reader for pre-v1.5.0 containers broke: fix the reader,
    /// never the fixture.
    #[test]
    fn v1_container_real_bytes_still_open() {
        const V1_CONTAINER_HEX: &str = "7b2276657273696f6e223a312c226b6466223a7b2273616c74223a5b35362c3232392c3131342c3139342c3137332c3234362c3137362c3132372c37372c3135362c3137352c38332c34362c392c34372c38335d2c22706172616d73223a7b226d5f636f7374223a33383931322c22745f636f7374223a322c22705f636f7374223a347d7d2c22777261707065645f63656b223a7b226e6f6e6365223a5b3234352c3234322c3231372c3139362c3231392c3134332c37312c3130392c3139332c3131322c3135372c39355d2c2263697068657274657874223a5b38372c3131322c322c3139362c3139332c34342c3138372c3230352c3130342c3133392c32302c3230302c33372c31382c32302c3137342c3231382c3232362c3138312c3235322c34362c31382c3133342c3235352c33302c3136392c36382c38382c31352c37382c35302c33342c34362c322c3133322c3133362c3231352c37372c36382c3231352c33392c35302c31342c38312c3138322c3138382c3233372c3136305d7d2c22736e617073686f74223a7b226e6f6e6365223a5b37352c3130322c3139392c37352c36372c3230322c31372c3137332c3135392c3230312c34342c32305d2c2263697068657274657874223a5b34342c36372c3231342c3232342c3133372c37392c3133352c3131362c3230352c3138322c3139362c3138392c3132362c31332c39302c3134372c3133382c3132382c3233392c33382c38322c3132342c37372c3233342c3133382c3130372c3232352c3133352c3230352c382c31332c3136332c35342c3234312c35312c3130392c322c37312c31322c3131302c39372c33342c38342c3136392c31322c3139322c39342c3136392c36322c33372c3137362c3233322c3231392c39352c3138302c3138332c3135392c35302c3230302c33352c3130392c3131312c3138362c3234392c39362c3232362c3232382c3139382c38382c37352c3130372c3139362c3139392c3135382c3232372c31332c33382c3232362c34312c35332c3137312c36362c3139322c3234362c3139392c3139332c3132312c37382c3233382c33312c33342c31322c3137382c3234382c32382c35322c31322c322c35322c3231392c3231372c3139322c36352c3232322c36302c35392c37312c35302c39382c3235332c3133322c3232362c3135342c3134332c3232332c33342c31392c3138392c322c32382c33332c3132372c38322c3136302c3136302c39312c38372c3230302c3135372c3132352c34392c3131312c3230352c3131332c3133312c3130382c3235322c3136342c31372c3132322c3234312c37392c3136302c3137362c3138342c33342c3230382c3136382c3139332c3234362c3132392c36352c38362c35322c31372c3133392c38322c3232342c36302c3136322c3138382c3130342c3137302c3133342c3137362c3132332c35312c39342c3132352c36362c3132372c31382c3137362c3130362c3235322c35372c37312c3136352c3234372c3138312c34332c3139362c3137312c33342c3233332c3138362c3132322c3139302c3232352c38382c3130312c3235352c3137342c3235352c3139332c392c3133342c39312c39372c3137352c3139332c3139342c3130332c36362c37372c34332c39362c3131382c36302c3139322c37352c3134352c392c3231322c3133312c3130322c35382c39372c3136382c3135352c36382c3231312c3233342c3233312c3135322c38342c3132352c3134352c38302c3232342c3134302c36392c3135322c36322c302c3234392c3234342c3139302c3131362c3231382c3134392c37392c3230342c37312c3133362c3136302c3234302c3138362c3131392c37362c3133322c3231392c31382c39312c3134342c3131322c3234322c31362c3134322c3234342c3132332c32322c3137342c3233332c3231392c3139312c3230392c3139382c31302c31382c3135372c3233342c3136322c3131372c3138362c33392c3232382c392c39342c38342c3137392c3132312c3131352c36392c3231352c3230352c3139382c3139392c3133322c3130392c31392c34362c3132302c3136382c32392c3132342c3233392c302c3130382c3132392c37302c3233382c352c37342c3138372c35342c3233332c3231312c3136342c34382c35332c3132302c3233342c3137392c39342c36342c3137302c3131312c35332c3231312c3233362c3136352c3232382c3133362c3233312c3134372c38352c33302c3139302c3138352c36302c3138352c3138372c3134302c3230302c33302c37362c3130322c3233302c37372c302c3137322c3132332c3234322c36312c3135342c32322c3231342c3134362c34362c3134302c32392c3231302c3137382c3138302c37352c3138342c35352c3235342c36352c36382c3131372c3138312c3230302c34342c3134302c31322c3139332c34392c3232312c31342c3233382c3134322c3138362c34302c3138352c3235322c3136362c3134302c34342c32302c36312c3137362c33332c3132392c332c34342c31392c39352c3133312c3136382c37312c35352c3130382c32332c36322c3230352c3138372c3136332c36352c3136382c3138302c3132342c36352c3231342c3135342c3234312c3130322c3133302c3130392c3133302c3138302c34392c32362c39332c39342c3135332c3132372c3133372c36362c3137382c38372c39302c372c3130352c37372c3134312c35322c38312c3234372c3134312c33382c3132392c3132382c34312c31372c33372c3235312c3135322c3131322c3135392c36392c3132342c37362c35312c3235352c38312c35312c3133332c3130312c39382c36332c39392c3132332c39352c3137362c3233302c3230392c34382c37362c38382c3230382c3135352c35372c3132392c3231382c3233332c34332c35342c3232382c3130382c35342c33372c3134352c3135362c3132342c3136342c3130332c37372c3138382c3136312c3234342c34392c3234362c38382c3137352c372c3232302c3233362c3133352c3137312c3231322c3231352c3233312c31372c3138322c3135342c3133332c3130362c3233382c3232302c3134382c3130372c31362c3232302c3130382c3132322c31332c3139382c3137332c3230332c3135362c3134392c39312c3138372c3139362c3234342c32322c33325d7d7d";
        let bytes = decode_hex(V1_CONTAINER_HEX);
        let opened = open_container(password(), &bytes).unwrap();
        // The v1 snapshot payload carries no `url_match_mode` key; the
        // serde default landing every entry on Auto is the load-bearing
        // read-side compatibility measure (asserted by exact equality).
        assert_eq!(
            opened,
            SyncSnapshot {
                rev: 7,
                device_id: "device-capture-v1".to_string(),
                generated_at: 1_760_000_000,
                entries: vec![SyncEntry {
                    id: "capture-entry-1".to_string(),
                    title: "Capture Title".to_string(),
                    url: Some("https://capture.example.com/login".to_string()),
                    username: "capture-user".to_string(),
                    password: Some("capture-pass".to_string()),
                    notes: Some("capture note".to_string()),
                    totp_secret: None,
                    tags: vec!["capture".to_string()],
                    group_id: Some("capture-group-1".to_string()),
                    created_at: 1_759_000_000,
                    updated_at: 1_759_500_000,
                    deleted_at: None,
                    url_match_mode: UrlMatchMode::Auto,
                    custom_fields: vec![],
                }],
                groups: vec![SyncGroup {
                    id: "capture-group-1".to_string(),
                    name: "Capture Group".to_string(),
                    created_at: 1_759_000_000,
                    updated_at: 1_759_000_000,
                    deleted_at: None,
                }],
            }
        );
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("fixture hex is well-formed"))
            .collect()
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

/// Golden byte fixtures pinning the LWW tiebreak fingerprint inputs.
///
/// **Provenance**: the `*_HEX` constants were produced by **bincode 1.3.3**
/// on `main @ b9185a2` (v1.2.4) via `bincode::serialize`, captured BEFORE
/// the v1.3.0 bincode 1 → 2 dependency swap. [`entry_fingerprint`] /
/// [`group_fingerprint`] are SHA-256 over exactly these bytes, so a device
/// running bincode 2 and a device still running bincode 1 must agree on them
/// or the D3 LWW tiebreak becomes inconsistent across a sync pair.
///
/// **Cross-VERSION consistency (v1.6.0 restatement)**: the fingerprint input
/// layout follows the `SyncEntry` shape, which has now changed twice
/// (`url_match_mode` in v1.5.0, `custom_fields` in v1.6.0). The fingerprint
/// of the same logical entry therefore differs between container generations
/// — that is exactly why cross-version sync is cut off at the container
/// version gate (`SUPPORTED_READ_VERSIONS` gates reads, and old peers fail
/// cleanly on v3 containers instead of silently stripping fields). Within
/// ONE generation the bytes must never drift: the re-captures below pin the
/// current 14-field layout, and the version gate keeps devices on
/// mismatched layouts from ever comparing fingerprints.
///
/// **These tests are the cross-version fingerprint tripwire.** If upgrading
/// bincode 2.x (or the `bc_serialize`/`bc_deserialize` config) makes any of
/// them red, the legacy byte semantics have drifted and the fingerprint of
/// the same logical entry would change across app versions — any such change
/// MUST be evaluated for tiebreak compatibility in the same commit.
#[cfg(test)]
mod bincode_golden {
    use pwdvault_infrastructure::crypto::{bc_deserialize, bc_serialize};

    use super::{SyncEntry, SyncGroup};
    use pwdvault_domain::UrlMatchMode;

    /// All-empty / all-`None` `SyncEntry`.
    ///
    /// v1.5.0 DELIBERATE UPDATE (WP4): `SyncEntry` gained `url_match_mode`
    /// (`#[serde(default)]`), which changes the fingerprint input layout —
    /// this fixture was re-captured for the then-current 13-field shape.
    /// v1.6.0 DELIBERATE UPDATE (WP1): the struct gained `custom_fields`
    /// (`#[serde(default)]`) — re-captured for the CURRENT 14-field shape
    /// (trailing empty-`Vec` length). Cross-version sync is cut off at the
    /// container version gate; see the CONTAINER_FORMAT_VERSION docs.
    const SYNC_ENTRY_MINIMAL_HEX: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    /// Fully populated `SyncEntry`: UTF-8 fields, password/notes/totp/group
    /// set, tombstone, `updated_at = i64::MAX`, `url_match_mode = Exact`
    /// (non-zero sentinel so the trailing field's bytes carry data), and one
    /// custom field (`"API Key"` / `"key-value-1"` / `secret = true`) so the
    /// 14th field's bytes carry data too.
    ///
    /// v1.6.0 DELIBERATE UPDATE (WP1): re-captured for the 14-field layout
    /// (same rule as SYNC_ENTRY_MINIMAL_HEX above).
    const SYNC_ENTRY_FULL_UTF8_HEX: &str = "140000000000000073796e632d656e7472792d757569642df09f94901200000000000000e5908ce6ada5e69da1e79bae2d456e74727901240000000000000068747470733a2f2f73796e632e6578616d706c652e6a702fe383ade382b0e382a4e383b3150000000000000073796e632d75736572406578616d706c652e636f6d010f0000000000000070407373773072642de5af86e7a0810119000000000000006e6f74652d776974682de5a49ae5ad97e88a822d6368617273012b000000000000006f7470617574683a2f2f746f74702f746573743f7365637265743d4a425357593344504548504b335058500200000000000000040000000000000073796e630600000000000000e5908ce6ada5010c0000000000000073796e632d67726f75702d3100f1536500000000ffffffffffffff7f0110185465000000000100000001000000000000000700000000000000415049204b65790b000000000000006b65792d76616c75652d3101";

    /// All-empty / all-`None` `SyncGroup`.
    const SYNC_GROUP_MINIMAL_HEX: &str =
        "000000000000000000000000000000000000000000000000000000000000000000";

    /// `SyncGroup` with UTF-8 id/name, `created_at = i64::MIN`, tombstone
    /// `i64::MAX`.
    const SYNC_GROUP_FULL_EXTREMES_HEX: &str = "140000000000000073796e632d67726f75702d757569642df09f8f861200000000000000e5908ce6ada5e58886e7bb842f47726f7570000000000000008000f153650000000001ffffffffffffff7f";

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("fixture hex is well-formed"))
            .collect()
    }

    /// Byte-exact reproduction + round-trip equality (these types derive
    /// `PartialEq`, so direct comparison works).
    fn assert_golden<
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    >(
        hex_fixture: &str,
        value: &T,
    ) {
        let bytes = decode_hex(hex_fixture);
        assert_eq!(
            bc_serialize(value).expect("bc_serialize is infallible for these shapes"),
            bytes,
            "serialized bytes diverge from the bincode 1.3.3 golden fixture — \
             LWW tiebreak fingerprint drift, see bincode_golden module docs"
        );
        let decoded: T =
            bc_deserialize(&bytes).expect("golden fixture must deserialize via bc_deserialize");
        assert_eq!(
            decoded, *value,
            "fixture did not round-trip to an equal value"
        );
    }

    #[test]
    fn sync_entry_minimal() {
        let entry = SyncEntry {
            id: String::new(),
            title: String::new(),
            url: None,
            username: String::new(),
            password: None,
            notes: None,
            totp_secret: None,
            tags: vec![],
            group_id: None,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
            url_match_mode: UrlMatchMode::Auto,
            custom_fields: vec![],
        };
        assert_golden(SYNC_ENTRY_MINIMAL_HEX, &entry);
    }

    #[test]
    fn sync_entry_full_utf8() {
        let entry = SyncEntry {
            id: "sync-entry-uuid-🔐".to_string(),
            title: "同步条目-Entry".to_string(),
            url: Some("https://sync.example.jp/ログイン".to_string()),
            username: "sync-user@example.com".to_string(),
            password: Some("p@ssw0rd-密码".to_string()),
            notes: Some("note-with-多字节-chars".to_string()),
            totp_secret: Some("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP".to_string()),
            tags: vec!["sync".to_string(), "同步".to_string()],
            group_id: Some("sync-group-1".to_string()),
            created_at: 1700000000,
            updated_at: i64::MAX,
            deleted_at: Some(1700010000),
            url_match_mode: UrlMatchMode::Exact,
            custom_fields: vec![super::super::SyncCustomField {
                label: "API Key".to_string(),
                value: "key-value-1".to_string(),
                secret: true,
            }],
        };
        assert_golden(SYNC_ENTRY_FULL_UTF8_HEX, &entry);
    }

    #[test]
    fn sync_group_minimal() {
        let group = SyncGroup {
            id: String::new(),
            name: String::new(),
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        };
        assert_golden(SYNC_GROUP_MINIMAL_HEX, &group);
    }

    #[test]
    fn sync_group_full_extremes() {
        let group = SyncGroup {
            id: "sync-group-uuid-🏆".to_string(),
            name: "同步分组/Group".to_string(),
            created_at: i64::MIN,
            updated_at: 1700000000,
            deleted_at: Some(i64::MAX),
        };
        assert_golden(SYNC_GROUP_FULL_EXTREMES_HEX, &group);
    }
}
