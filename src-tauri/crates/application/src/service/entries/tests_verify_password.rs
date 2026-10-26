//! v1.6.0 WP3 (D7): `verify_entry_password` — the extension save/update
//! prompt's desktop pivot. Pins the boolean-only disclosure contract, the
//! hit/miss verdicts, the hex normalization, and the lock/tombstone/unknown
//! rejections.

use super::*;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
use pwdvault_infrastructure::database::Settings;

const TEST_PASSWORD: &str = "verify-password-test-password";
const STORED_PASSWORD: &str = "correct-horse-battery";

fn digest_hex(plaintext: &[u8]) -> String {
    let hash = Sha256::digest(plaintext);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn verify_request(id: &str, hex: &str) -> VerifyEntryPasswordRequest {
    VerifyEntryPasswordRequest {
        id: id.to_string(),
        password_sha256: hex.to_string(),
    }
}

/// Same scaffold shape as the sibling `tests` module: unlocked in-memory
/// AppState.
fn unlocked_state() -> (Arc<AppState>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(database::init_database(dir.path().join("verify.db")).unwrap());
    let salt = [0x75; 16];
    let params = AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        pwdvault_infrastructure::crypto::kdf::derive_key_with_params(TEST_PASSWORD, &salt, &params)
            .unwrap();
    let verification =
        pwdvault_infrastructure::crypto::create_verification_header(&master_key, salt, params)
            .unwrap();
    let (enc_key, mac_key) =
        pwdvault_infrastructure::crypto::kdf::derive_subkeys(&master_key, &salt);

    database::vault_store::VaultStore::new(&db)
        .write(&mac_key, |txn| {
            database::vault_store::save_verification_data_in_txn(txn, &verification)?;
            pwdvault_infrastructure::vault_header::save_header_in_txn(
                txn,
                &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
                &enc_key,
            )?;
            database::vault_store::save_settings_in_txn(txn, &Settings::default())?;
            Ok(())
        })
        .unwrap();

    let state = Arc::new(AppState::default());
    *state.database.lock().unwrap() = Some(db);
    *state.verification_data.lock().unwrap() = Some(verification);
    state.session.unlock(enc_key, mac_key);
    (state, dir)
}

fn create_entry_with_password(state: &Arc<AppState>, password: &str) -> EntrySummary {
    create_entry(
        state,
        CreateEntryRequest {
            url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
            title: "Verify Target".to_string(),
            url: None,
            username: "user".to_string(),
            password: Zeroizing::new(password.to_string()),
            notes: None,
            tags: vec![],
            group_id: None,
            custom_fields: Vec::new(),
        },
    )
    .unwrap()
}

/// The stored password hashes to the candidate digest → matches = true.
#[test]
fn matching_password_verifies_true() {
    let (state, _dir) = unlocked_state();
    let entry = create_entry_with_password(&state, STORED_PASSWORD);

    let response = verify_entry_password(
        &state,
        verify_request(&entry.id, &digest_hex(STORED_PASSWORD.as_bytes())),
    )
    .unwrap();
    assert!(response.matches);
}

/// A wrong candidate hashes to a different digest → matches = false (a
/// boolean verdict, not an error).
#[test]
fn wrong_password_verifies_false() {
    let (state, _dir) = unlocked_state();
    let entry = create_entry_with_password(&state, STORED_PASSWORD);

    let response = verify_entry_password(
        &state,
        verify_request(&entry.id, &digest_hex(b"wrong-password")),
    )
    .unwrap();
    assert!(!response.matches);
}

/// Uppercase hex is normalized before comparison (the wire contract the
/// dispatcher relies on — WebCrypto emits lowercase, but the request format
/// accepts both registers).
#[test]
fn uppercase_hex_is_normalized() {
    let (state, _dir) = unlocked_state();
    let entry = create_entry_with_password(&state, STORED_PASSWORD);

    let upper = digest_hex(STORED_PASSWORD.as_bytes()).to_uppercase();
    let response = verify_entry_password(&state, verify_request(&entry.id, &upper)).unwrap();
    assert!(response.matches);
}

/// Malformed digests are rejected as invalid input — never coerced into a
/// false verdict (a caller could not distinguish "wrong password" from
/// "garbage request").
#[test]
fn malformed_digests_are_rejected() {
    let (state, _dir) = unlocked_state();
    let entry = create_entry_with_password(&state, STORED_PASSWORD);

    for bad in ["", "abc", &"0".repeat(63), &"0".repeat(65), &"z".repeat(64)] {
        let err = verify_entry_password(&state, verify_request(&entry.id, bad))
            .expect_err("malformed digest must be rejected");
        assert!(
            matches!(err, VaultError::InvalidInput { ref code, .. } if code == "INVALID_PASSWORD_DIGEST"),
            "expected INVALID_PASSWORD_DIGEST for {bad:?}, got {err:?}"
        );
    }
}

/// A locked vault refuses before any lookup (the extension treats this as
/// "no prompt" — D7's locked-vault boundary).
#[test]
fn locked_vault_is_rejected() {
    let (state, _dir) = unlocked_state();
    let entry = create_entry_with_password(&state, STORED_PASSWORD);
    state.lock_vault();

    let err = verify_entry_password(
        &state,
        verify_request(&entry.id, &digest_hex(STORED_PASSWORD.as_bytes())),
    )
    .expect_err("locked vault must refuse verification");
    assert!(matches!(err, VaultError::VaultLocked));
}

/// Unknown ids (and tombstoned entries) answer EntryNotFound — trash never
/// verifies secrets (P2.2, same filter as get_entry_secret).
#[test]
fn unknown_and_tombstoned_entries_answer_not_found() {
    let (state, _dir) = unlocked_state();
    let entry = create_entry_with_password(&state, STORED_PASSWORD);
    let digest = digest_hex(STORED_PASSWORD.as_bytes());

    let err = verify_entry_password(&state, verify_request("no-such-entry", &digest))
        .expect_err("unknown id must 404");
    assert!(matches!(err, VaultError::EntryNotFound));

    remove_entry(&state, entry.id.clone()).unwrap();
    let err = verify_entry_password(&state, verify_request(&entry.id, &digest))
        .expect_err("tombstoned entry must 404");
    assert!(matches!(err, VaultError::EntryNotFound));
}

/// The response shape is EXACTLY one boolean field — serialization must not
/// carry any plaintext or metadata (the D7 no-disclosure contract, pinned at
/// the wire-format level).
#[test]
fn response_serializes_to_matches_only() {
    let (state, _dir) = unlocked_state();
    let entry = create_entry_with_password(&state, STORED_PASSWORD);

    let response = verify_entry_password(
        &state,
        verify_request(&entry.id, &digest_hex(STORED_PASSWORD.as_bytes())),
    )
    .unwrap();
    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "matches": true }),
        "the response must carry the boolean and nothing else"
    );
}

/// DECLARED DECISION pin (v1.6.0 review follow-up): `verify_entry_password`
/// deliberately does NOT bump `last_used_at` — unlike `get_entry_secret`,
/// which stamps on every fetch (60s-throttled). Verification runs once per
/// form-submit candidate and the resulting re-seal/write amplification would
/// dwarf the value of the signal; the save prompt is a preview, not a usage.
/// This pins the no-write side of that decision on both verdicts (the
/// positive bump contract lives in
/// `get_entry_secret_throttles_last_used_at_writes`).
#[test]
fn verify_does_not_bump_last_used_at() {
    let (state, _dir) = unlocked_state();
    let entry = create_entry_with_password(&state, STORED_PASSWORD);

    // Establish the baseline via the channel that DOES bump.
    let stamped = get_entry_secret(&state, entry.id.clone())
        .unwrap()
        .last_used_at
        .expect("secret fetch stamps last_used_at");

    // Cross a full second so a (buggy) verify-side bump at second
    // granularity could not coincide with the stamped value.
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let hit = verify_entry_password(
        &state,
        verify_request(&entry.id, &digest_hex(STORED_PASSWORD.as_bytes())),
    )
    .unwrap();
    assert!(hit.matches);
    let miss = verify_entry_password(
        &state,
        verify_request(&entry.id, &digest_hex(b"wrong-password")),
    )
    .unwrap();
    assert!(!miss.matches);

    let after = get_entry_meta(&state, entry.id)
        .unwrap()
        .last_used_at
        .expect("the stamped value must survive verify");
    assert_eq!(
        after, stamped,
        "verify must not rewrite the row's last_used_at"
    );
}
