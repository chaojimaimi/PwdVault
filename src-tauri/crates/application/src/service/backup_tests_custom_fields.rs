//! v1.6.0 WP1 (D8): backup payload fidelity for the three newer fields —
//! `url_match_mode`, TOTP secrets and custom fields ride the plaintext
//! payload (export decrypts, import re-seals), with the empty-value
//! symmetry and pre-v1.6.0 backup compatibility pinned here.

use super::*;
use zeroize::Zeroizing;

use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
use pwdvault_infrastructure::database::Settings;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "backup-fidelity-password";

fn unlocked_state_with_entries<F>(build_entries: F) -> (Arc<AppState>, TempDir, Vec<String>)
where
    F: FnOnce(&[u8; 32]) -> Vec<PasswordEntry>,
{
    let dir = TempDir::new().unwrap();
    let db = Arc::new(database::init_database(dir.path().join("fidelity.db")).unwrap());
    let salt = [0x74; 16];
    let params = AdaptiveParams {
        m_cost: 16384,
        t_cost: 1,
        p_cost: 1,
    };
    let (master_key, _) =
        crypto::kdf::derive_key_with_params(TEST_PASSWORD, &salt, &params).unwrap();
    let verification = crypto::create_verification_header(&master_key, salt, params).unwrap();
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);
    let entries = build_entries(&enc_key);
    let entry_ids = entries.iter().map(|entry| entry.id.clone()).collect();

    database::vault_store::VaultStore::new(&db)
        .write(&mac_key, |txn| {
            database::vault_store::save_verification_data_in_txn(txn, &verification)?;
            pwdvault_infrastructure::vault_header::save_header_in_txn(
                txn,
                &pwdvault_infrastructure::vault_header::VaultHeader::new_initial(),
                &enc_key,
            )?;
            database::vault_store::save_settings_in_txn(txn, &Settings::default())?;
            for entry in &entries {
                database::vault_store::save_entry_in_txn(txn, &enc_key, entry)?;
            }
            Ok(())
        })
        .unwrap();

    let state = Arc::new(AppState::default());
    *state.database.lock().unwrap() = Some(db);
    *state.verification_data.lock().unwrap() = Some(verification);
    state.session.unlock(enc_key, mac_key);
    (state, dir, entry_ids)
}

fn seal_inner(key: &[u8; 32], plain: &str) -> Vec<u8> {
    bc_serialize(&crypto::encrypt(key, plain.as_bytes()).unwrap()).unwrap()
}

/// The D8 round trip: TOTP + custom fields (secret true/false, empty
/// placeholder) survive export → import losslessly, and the exported payload
/// shows the empty-value symmetry (empty ciphertext → empty plaintext, kept
/// as a placeholder row).
#[test]
fn export_import_roundtrip_preserves_totp_and_custom_fields() {
    let (state, _dir, _) = unlocked_state_with_entries(|enc_key| {
        let mut entry = PasswordEntry::new("Fidelity entry".into(), None, "fidelity-user".into());
        entry.encrypted_password = seal_inner(enc_key, "fidelity-pw");
        entry.encrypted_totp_secret = Some(seal_inner(enc_key, "JBSWY3DPEHPK3PXP"));
        entry.url_match_mode = pwdvault_domain::UrlMatchMode::Exact;
        entry.custom_fields = vec![
            pwdvault_domain::CustomField {
                label: "API Key".to_string(),
                value: seal_inner(enc_key, "key-value-1"),
                secret: true,
            },
            pwdvault_domain::CustomField {
                label: "Visible".to_string(),
                value: seal_inner(enc_key, "plain-value"),
                secret: false,
            },
            pwdvault_domain::CustomField {
                label: "Placeholder".to_string(),
                value: Vec::new(),
                secret: true,
            },
        ];
        vec![entry]
    });

    let backup = export_vault(&state, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();

    // Export side: decrypt the payload and pin the plaintext-load model,
    // including the empty-value symmetry (empty ciphertext exported as the
    // empty plaintext, row kept).
    {
        let b64 = base64::engine::general_purpose::STANDARD;
        let salt: [u8; 16] = b64.decode(&backup.salt).unwrap().try_into().unwrap();
        let (key, _) = crypto::kdf::derive_key_with_params(
            TEST_PASSWORD,
            &salt,
            &crypto::kdf::AdaptiveParams {
                m_cost: backup.kdf_memory,
                t_cost: backup.kdf_iterations,
                p_cost: backup.kdf_parallelism,
            },
        )
        .unwrap();
        let encrypted = crypto::EncryptedData {
            nonce: b64.decode(&backup.nonce).unwrap(),
            ciphertext: b64.decode(&backup.data).unwrap(),
        };
        let mut payload_bytes =
            crypto::decrypt_with_aad(&key, &encrypted, &backup_v2_aad(&backup).unwrap()).unwrap();
        let payload: BackupPayload = serde_json::from_slice(&payload_bytes).unwrap();
        payload_bytes.zeroize();
        assert_eq!(payload.entries.len(), 1);
        let exported = &payload.entries[0];
        assert_eq!(
            exported.url_match_mode,
            pwdvault_domain::UrlMatchMode::Exact
        );
        assert_eq!(
            exported.totp_secret.as_deref().map(String::as_str),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert_eq!(exported.custom_fields.len(), 3);
        assert_eq!(exported.custom_fields[0].label, "API Key");
        assert_eq!(exported.custom_fields[0].value.as_str(), "key-value-1");
        assert!(exported.custom_fields[0].secret);
        assert_eq!(exported.custom_fields[2].value.as_str(), "");
    }

    // Import side: re-sealed under the (same) master key and fully readable.
    let result = import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    assert_eq!(result.entries_imported, 1);

    let listed = crate::service::list_all_entries(&state).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].url_match_mode,
        pwdvault_domain::UrlMatchMode::Exact
    );
    assert_eq!(listed[0].custom_fields.len(), 3);

    let secret = crate::service::get_entry_secret(&state, listed[0].id.clone()).unwrap();
    assert_eq!(secret.password.as_str(), "fidelity-pw");
    assert_eq!(secret.custom_fields[0].value.as_str(), "key-value-1");
    assert_eq!(secret.custom_fields[1].value.as_str(), "plain-value");
    assert!(!secret.custom_fields[1].secret);
    assert_eq!(secret.custom_fields[2].value.as_str(), "");
}

/// Old backups (the v1.5.1 shape: payload entries WITHOUT the three newer
/// keys) import smoothly — serde defaults land the entry on Auto / no TOTP /
/// no custom fields. Built as a v1 envelope so the payload bytes are freely
/// chosen (v1 has no AAD binding).
#[test]
fn import_accepts_v1_5_1_backup_without_new_fields() {
    let (state, _dir, _) = unlocked_state_with_entries(|_| vec![]);

    let legacy_entry = serde_json::json!({
        // Deliberately NO url_match_mode / totp_secret / custom_fields keys —
        // exactly what a v1.5.1 export wrote.
        "id": "legacy-entry-1",
        "title": "Legacy Backup Entry",
        "url": "https://legacy.example.test",
        "username": "legacy-user",
        "password": "legacy-password",
        "notes": null,
        "tags": ["legacy"],
        "group_id": null,
        "created_at": 1_700_000_000,
        "updated_at": 1_700_000_100
    });
    let payload = serde_json::json!({
        "entries": [legacy_entry],
        "groups": [],
        "settings": serde_json::to_value(Settings::default()).unwrap(),
    });
    let payload_json = serde_json::to_vec(&payload).unwrap();

    let salt = [0x42u8; 16];
    let params = AdaptiveParams {
        m_cost: crypto::kdf::KdfPolicy::IMPORT_MIN_MEMORY_KIB,
        t_cost: crypto::kdf::KdfPolicy::IMPORT_MIN_ITERATIONS,
        p_cost: 1,
    };
    let (key, _) = crypto::kdf::derive_key_with_params(TEST_PASSWORD, &salt, &params).unwrap();
    let encrypted = crypto::encrypt(&key, &payload_json).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    let backup = VaultBackup {
        version: BACKUP_VERSION_V1,
        created_at: 0,
        magic: None,
        kdf_name: None,
        cipher_name: None,
        salt: b64.encode(salt),
        kdf_memory: params.m_cost,
        kdf_iterations: params.t_cost,
        kdf_parallelism: params.p_cost,
        nonce: b64.encode(&encrypted.nonce),
        data: b64.encode(&encrypted.ciphertext),
    };

    let result = import_vault(&state, backup, Zeroizing::new(TEST_PASSWORD.to_string())).unwrap();
    assert_eq!(result.entries_imported, 1);

    let listed = crate::service::list_all_entries(&state).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].title, "Legacy Backup Entry");
    // Defaults, not garbage: the three keys were absent from the payload.
    assert_eq!(
        listed[0].url_match_mode,
        pwdvault_domain::UrlMatchMode::Auto
    );
    assert!(listed[0].custom_fields.is_empty());
    let secret = crate::service::get_entry_secret(&state, listed[0].id.clone()).unwrap();
    assert_eq!(secret.password.as_str(), "legacy-password");
    // No TOTP key in the payload = no TOTP secret; likewise no custom fields.
    assert!(secret.custom_fields.is_empty());
}
