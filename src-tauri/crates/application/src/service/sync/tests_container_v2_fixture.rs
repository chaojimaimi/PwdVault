//! PERMANENT FIXTURE (v1.6.0 WP3 / D4) — NEVER RECAPTURE.
//!
//! Real bytes of a container written by the **v2** format path
//! (v1.5.0–v1.5.1: `version: 2`, snapshot JSON WITHOUT `custom_fields`),
//! frozen in `V2_CONTAINER_HEX`. The capture mechanism is kept alive in this
//! file as [`seal_v2_era_container`]: a test-only 13-field mirror of the
//! pre-`custom_fields` `SyncEntry` layout produces the snapshot JSON (the
//! serde output therefore carries no `custom_fields` key) and the v2-era LWW
//! fingerprint (an inline replica of the then-current
//! `Sha256(bc_serialize(entry))` — `entry_fingerprint` itself is typed on
//! the modern `SyncEntry` and cannot run against the mirror), and the
//! envelope is hand-sealed with the version field pinned to 2 from the same
//! internal primitives the production sealer uses (the weak-params pattern
//! of the sibling container tests). The frozen constant was captured from
//! exactly that function immediately before `CONTAINER_FORMAT_VERSION`
//! bumped 2 → 3.
//!
//! Recapturing this constant against any newer writer would launder a
//! v2-readability regression — the same P0 class the v1.5.0 plan review
//! exists to prevent. If `v2_container_real_bytes_still_open` goes red, the
//! reader for v1.5.x containers broke: **fix the reader, never the
//! fixture.**

use sha2::{Digest, Sha256};
use zeroize::Zeroize;
use zeroize::Zeroizing;

use pwdvault_infrastructure::crypto::{
    bc_serialize, derive_key_with_params, encrypt_with_aad, generate_wrap_key, wrap_secret,
    AdaptiveParams, EncryptedData, SALT_SIZE, WRAP_AAD_CONTAINER,
};

use super::container::{open_container, ContainerKdf, SyncContainerV1};
use super::{SyncEntry, SyncGroup, SyncSnapshot};
use pwdvault_domain::UrlMatchMode;

const PASSWORD: &str = "container-passphrase";

fn password() -> Zeroizing<String> {
    Zeroizing::new(PASSWORD.to_string())
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("fixture hex is well-formed"))
        .collect()
}

// Verbatim copy of the private `SNAPSHOT_AAD` in container.rs (the const is
// deliberately not exported). A drift on either side turns these tests red —
// the tripwire, not an accident.
const SNAPSHOT_AAD: &[u8] = b"pwdvault-sync-container-snapshot-v1";

/// The capture entry in its v2-era 13-field shape (NO `custom_fields`).
/// Field order mirrors the pre-v1.6.0 `SyncEntry` declaration exactly, so
/// `bc_serialize` reproduces the historical fingerprint input bytes.
#[derive(serde::Serialize, serde::Deserialize)]
struct SyncEntryV2Mirror {
    id: String,
    title: String,
    url: Option<String>,
    username: String,
    password: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
    tags: Vec<String>,
    group_id: Option<String>,
    created_at: i64,
    updated_at: i64,
    deleted_at: Option<i64>,
    url_match_mode: UrlMatchMode,
}

/// The full v2-era snapshot payload shape (envelope fields + 13-field
/// entries). Serializes to the exact JSON a v1.5.x writer produced.
#[derive(serde::Serialize)]
struct SyncSnapshotV2Mirror {
    rev: u64,
    device_id: String,
    generated_at: i64,
    entries: Vec<SyncEntryV2Mirror>,
    groups: Vec<SyncGroupV2Mirror>,
}

#[derive(serde::Serialize)]
struct SyncGroupV2Mirror {
    id: String,
    name: String,
    created_at: i64,
    updated_at: i64,
    deleted_at: Option<i64>,
}

fn mirror_entry() -> SyncEntryV2Mirror {
    SyncEntryV2Mirror {
        id: "capture-entry-2".to_string(),
        title: "Capture Title v2".to_string(),
        url: Some("https://capture.example.com/login".to_string()),
        username: "capture-user".to_string(),
        password: Some("capture-pass".to_string()),
        notes: Some("capture note".to_string()),
        totp_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
        tags: vec!["capture".to_string(), "v2".to_string()],
        group_id: Some("capture-group-2".to_string()),
        created_at: 1_759_000_000,
        updated_at: 1_759_500_000,
        deleted_at: None,
        url_match_mode: UrlMatchMode::Exact,
    }
}

fn mirror_group() -> SyncGroupV2Mirror {
    SyncGroupV2Mirror {
        id: "capture-group-2".to_string(),
        name: "Capture Group v2".to_string(),
        created_at: 1_759_000_000,
        updated_at: 1_759_000_000,
        deleted_at: None,
    }
}

/// The D5/LWW fingerprint a v2-era device computed for the capture entry:
/// SHA-256 over the bincode bytes of the 13-field layout. Inlined here
/// because `entry_fingerprint` is typed on the modern `SyncEntry`.
fn v2_era_entry_fingerprint(entry: &SyncEntryV2Mirror) -> [u8; 32] {
    let encoded = bc_serialize(entry).expect("mirror bincode encoding is infallible (no maps)");
    Sha256::digest(&encoded).into()
}

/// Hand-replicated v2 seal: same primitives as the production
/// `seal_container`, but with the envelope version pinned to 2 and the
/// snapshot built from the 13-field mirror (no `custom_fields` keys in the
/// payload JSON). Weak KDF params keep opens fast (fixture pattern).
fn seal_v2_era_container() -> (Vec<u8>, [u8; 32]) {
    let entry = mirror_entry();
    let fingerprint = v2_era_entry_fingerprint(&entry);
    let snapshot = SyncSnapshotV2Mirror {
        rev: 9,
        device_id: "device-capture-v2".to_string(),
        generated_at: 1_760_000_000,
        entries: vec![entry],
        groups: vec![mirror_group()],
    };
    let mut snapshot_json = serde_json::to_vec(&snapshot).expect("mirror snapshot serializes");

    let salt = [0x5A; SALT_SIZE];
    let weak = AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (kdf_key, params) = derive_key_with_params(PASSWORD, &salt, &weak).unwrap();
    let cek = Zeroizing::new(generate_wrap_key());
    let encrypted_snapshot = encrypt_with_aad(&cek, &snapshot_json, SNAPSHOT_AAD)
        .expect("snapshot encryption is infallible for these shapes");
    snapshot_json.zeroize();
    let wrapped_cek = wrap_secret(&kdf_key, &cek, WRAP_AAD_CONTAINER)
        .expect("cek wrap is infallible for these shapes");

    // The envelope, with the era's version pinned (the production sealer now
    // writes CONTAINER_FORMAT_VERSION = 3).
    let container = SyncContainerV1 {
        version: 2,
        kdf: ContainerKdf { salt, params },
        wrapped_cek: EncryptedData::from_bytes(&wrapped_cek)
            .expect("wrap output is a valid EncryptedData"),
        snapshot: encrypted_snapshot,
    };
    (
        serde_json::to_vec(&container).expect("envelope serializes"),
        fingerprint,
    )
}

/// The modern reader's view of the capture snapshot: identical content, with
/// `custom_fields` landed on the serde default (empty) — the load-bearing
/// read-side compatibility measure for v2 payloads, asserted by exact
/// equality.
fn expected_snapshot() -> SyncSnapshot {
    SyncSnapshot {
        rev: 9,
        device_id: "device-capture-v2".to_string(),
        generated_at: 1_760_000_000,
        entries: vec![SyncEntry {
            id: "capture-entry-2".to_string(),
            title: "Capture Title v2".to_string(),
            url: Some("https://capture.example.com/login".to_string()),
            username: "capture-user".to_string(),
            password: Some("capture-pass".to_string()),
            notes: Some("capture note".to_string()),
            totp_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
            tags: vec!["capture".to_string(), "v2".to_string()],
            group_id: Some("capture-group-2".to_string()),
            created_at: 1_759_000_000,
            updated_at: 1_759_500_000,
            deleted_at: None,
            url_match_mode: UrlMatchMode::Exact,
            custom_fields: vec![],
        }],
        groups: vec![SyncGroup {
            id: "capture-group-2".to_string(),
            name: "Capture Group v2".to_string(),
            created_at: 1_759_000_000,
            updated_at: 1_759_000_000,
            deleted_at: None,
        }],
    }
}

/// PERMANENT FIXTURE — NEVER RECAPTURE. Real v2-format bytes (captured from
/// [`seal_v2_era_container`] immediately before the 2 → 3 bump) must keep
/// opening under the v3 reader, with `custom_fields` landing on the serde
/// default. See the module docs before touching the constant.
#[test]
fn v2_container_real_bytes_still_open() {
    const V2_CONTAINER_HEX: &str = "7b2276657273696f6e223a322c226b6466223a7b2273616c74223a5b39302c39302c39302c39302c39302c39302c39302c39302c39302c39302c39302c39302c39302c39302c39302c39305d2c22706172616d73223a7b226d5f636f7374223a31363338342c22745f636f7374223a312c22705f636f7374223a317d7d2c22777261707065645f63656b223a7b226e6f6e6365223a5b3231392c3235322c36342c37302c3134332c36312c3133382c3137352c3233352c3137382c37342c32395d2c2263697068657274657874223a5b3138392c3133302c3134332c3137352c3135312c35342c3233332c3130352c35332c3132392c3139392c34312c3235342c3132392c3139312c3234332c3234322c3134362c3137362c34352c3234332c31362c32312c3134372c3135342c3232312c3134342c3132382c3231352c3230332c37302c39302c3234362c3230362c3233382c3234322c3231312c3131342c362c36342c36382c322c3131352c32302c3232312c38332c3134302c3231305d7d2c22736e617073686f74223a7b226e6f6e6365223a5b39392c3133372c3133332c332c38332c312c34392c3131392c302c3230392c31322c35315d2c2263697068657274657874223a5b3138382c34342c372c3139332c35352c3135362c32312c39322c35312c3230312c332c3138372c32312c36392c3134322c332c3235342c3136362c35312c3232312c3138392c3232312c372c3233382c3235312c3131372c3138352c3130352c32352c3234302c3232392c3135352c39392c3131392c3138342c39322c3137362c38392c3231312c31392c37302c3134322c3231392c3132342c3135372c3232382c3232392c3131372c31302c3131392c31352c34322c39342c3132352c3235322c31302c3134362c3230352c35392c3230362c35342c3130322c3235322c3138322c3233382c32342c3135312c3232332c31392c3130382c35312c3231362c3137382c3231312c332c3234342c3131372c3233332c3137302c3233322c37392c31362c3138342c3232372c3134362c3130342c31392c33372c3230302c3135322c3234342c3135392c3232342c3137362c36302c3232372c352c32382c32362c3139332c3234362c322c31332c3135352c3136332c3131302c34332c3134302c36382c3233362c33302c39352c3131322c3130322c3133312c37302c3136332c36372c3136322c36342c32322c3134382c332c38322c34342c32312c3135312c3131372c33372c3133362c32372c36332c34332c37372c3133352c38322c3130372c31382c37312c3130312c3139352c3230382c3136352c34342c3133302c3232312c3235322c34372c3231312c33362c31312c3131392c35312c3232382c312c3133382c3138382c3138322c3231392c3139322c32382c34332c3139382c38302c33352c32362c3134332c3130312c35362c3138392c3232362c3234322c38312c31392c3138332c32312c3233362c35372c3230362c3233362c35382c3234392c3131332c3135312c39312c37362c3231332c38392c332c3132372c3232372c342c34322c3234382c3139342c38372c3137352c3132362c3136312c3133342c3230312c3131322c3139312c3133332c3130352c35302c3139322c35302c3136312c3135352c37332c3231392c3234322c3136352c3234392c3135322c372c3234392c3235332c37382c3230372c3139322c3133342c3235342c32312c3136372c3230312c3137312c3132372c32322c36322c38362c36332c37342c3137312c37322c35352c3139362c3234392c36302c3136322c3139302c382c3230322c3233372c3232312c35372c3233322c33392c3130372c36352c382c38382c3232372c3139312c3130382c3137342c31372c3130302c36372c3235322c3139392c34322c32302c3135372c3234322c3131352c37372c3136302c3133332c3137332c3134372c3137332c3233332c3135352c3135382c3136372c3231312c31382c3138372c32322c3232382c3132352c37312c3233362c31372c38312c3231342c3232382c3135332c3132342c3139362c35312c37352c3132342c3137312c34302c352c35372c34302c33372c3132322c3133302c322c31302c3233352c34312c3233332c3131372c3133302c3138372c3131332c3234362c3230312c3134352c3232392c3231392c3230392c3139302c3134352c3234342c3131342c3133352c3232382c3130382c34382c3233302c31342c32342c3135382c3137392c3135322c33322c3130382c34332c38322c33312c3232312c3232382c35342c3234362c3139382c36322c3234322c3131322c3235322c3132382c37302c3138342c35382c3233342c3235322c33312c35312c3136322c32342c3135322c3232392c33362c3138322c38372c34382c32392c34392c3234302c37352c36382c3136312c34342c302c3137382c3135342c3135392c39312c3139312c35392c32342c3137382c3139352c3232342c3232372c31322c3134392c3131352c3130342c3139302c3137352c3139362c3130322c3134352c3135362c3138392c3133322c3138352c3138382c3139312c3133312c3135312c3235312c31322c32332c34352c3135352c3230342c38322c32342c3233372c33352c3231352c3138352c3134342c3233372c3139352c3230342c3233322c3230372c39352c3136312c36312c3131302c3132392c3232362c3132302c3234332c31322c3234322c3235312c32382c36342c3234382c3131302c3232332c34332c31302c3133322c37312c3132342c3231322c38302c3234302c32302c3134312c33342c3235322c32312c35362c3130342c34362c3138382c34302c3131342c3232372c3135332c3234302c31322c32322c32332c39382c3134312c3135382c37372c32302c39352c39392c34332c3130312c3235302c33362c3137382c35382c3232362c3138352c32372c3235322c3137392c3139332c32362c3132372c3230322c35392c3232332c34372c39322c3130302c33332c3135352c31392c3230382c3131352c39352c31372c3135352c3135302c3131392c3232392c3232342c3134362c37302c382c3133362c3234392c3132322c3234372c3137362c38312c3231372c3132352c3132362c3133382c3134362c3137312c39372c3139332c3235342c31392c3233312c3232312c33392c3130392c3137332c3131382c3138322c3137332c3137312c34302c35342c3232372c36362c3136362c3133302c3139392c3133372c3137382c3234362c3234382c39352c37392c34302c3136352c3138342c3136312c3134352c3133332c35382c35352c3131372c3138372c3234342c3231392c37362c3230342c33312c3232312c3133352c36332c33322c3130302c3137312c38322c38302c3232302c37332c39352c37372c39352c39382c35312c31392c33325d7d7d";
    let bytes = decode_hex(V2_CONTAINER_HEX);
    let opened = open_container(password(), &bytes).unwrap();
    assert_eq!(opened, expected_snapshot());
}

/// The capture mechanism stays alive and honest: a freshly hand-sealed v2
/// envelope (same primitives, version pinned to 2, snapshot without the
/// `custom_fields` keys) must open under the v3 reader exactly like the
/// frozen bytes — and its envelope really declares version 2.
#[test]
fn v2_shaped_envelope_from_replicated_seal_still_opens() {
    let (bytes, _fingerprint) = seal_v2_era_container();
    let envelope: SyncContainerV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope.version, 2);

    let opened = open_container(password(), &bytes).unwrap();
    assert_eq!(opened, expected_snapshot());
}

/// The v2-era LWW fingerprint input is pinned for forensics: the same
/// logical entry hashed over the 13-field layout produced exactly these
/// bytes on v1.5.x devices. (The modern 14-field fingerprint necessarily
/// differs — that divergence is why cross-version sync is cut off at the
/// container version gate.)
#[test]
fn v2_era_fingerprint_matches_the_frozen_input() {
    const V2_ERA_FINGERPRINT_HEX: &str =
        "141e14ef63e269e4cb7eea94ba4d06706f39ffe3f13a2820b9f0282bf462da25";
    let fingerprint = v2_era_entry_fingerprint(&mirror_entry());
    assert_eq!(to_hex(&fingerprint), V2_ERA_FINGERPRINT_HEX);
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
