//! Tests for the third-party CSV importer (WP2).
//!
//! Coverage mapped from the plan: four-preset header detection (incl. BOM
//! prefix / wrong column order / extra columns / CRLF / quoted embedded
//! newlines), size and row caps, staging zeroization, lock-discards-staging,
//! commit counts with group dedup, single-transaction digest discipline,
//! duplicate statistics, and locked-vault rejection.

use std::sync::Arc;

use super::*;
use crate::service::{create_entry, create_group, list_all_entries, list_all_groups};
use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
use pwdvault_infrastructure::database::{self, Settings};
use tempfile::TempDir;
use zeroize::{Zeroize, Zeroizing};

const TEST_PASSWORD: &str = "csv-import-test-password";

fn unlocked_state() -> (Arc<AppState>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(database::init_database(dir.path().join("csv_import.db")).unwrap());
    let salt = [0x61; 16];
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

// ---------------------------------------------------------------------------
// Parser + preset detection
// ---------------------------------------------------------------------------

#[test]
fn parse_csv_handles_quotes_escapes_and_blank_lines() {
    let parsed = parse_csv("a,\"b,c\",d\n\"line1\nline2\",\"he said \"\"hi\"\"\",\"\"\n\nx,y,z");
    assert_eq!(parsed.len(), 4);
    assert_eq!(parsed[0], vec!["a", "b,c", "d"]);
    assert_eq!(parsed[1], vec!["line1\nline2", "he said \"hi\"", ""]);
    // A blank line parses as a single empty-field row — counted as a skip.
    assert_eq!(parsed[2], vec![""]);
    assert_eq!(parsed[3], vec!["x", "y", "z"]);

    // Trailing newline does not produce a phantom row.
    assert_eq!(parse_csv("a,b\n").len(), 1);
    // Unquoted content is untouched.
    assert_eq!(parse_csv("plain"), vec![vec!["plain"]]);
}

#[test]
fn bom_is_stripped_before_header_detection() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"name,url,username,password\nX,https://x.test,u,pw-x");
    let text = decode_csv_text(&bytes).unwrap();
    let grid = parse_csv(&text);
    let map = header_index_map(&grid[0]);
    assert_eq!(detect_preset(&map), Some(CsvPreset::Chrome));
}

#[test]
fn all_four_preset_signatures_are_recognized() {
    let detect = |header: &str| {
        let grid = parse_csv(header);
        detect_preset(&header_index_map(&grid[0]))
    };
    assert_eq!(
        detect("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp"),
        Some(CsvPreset::Bitwarden)
    );
    assert_eq!(
        detect("Title,Url,Username,Password,Notes,OTPAuth"),
        Some(CsvPreset::OnePassword)
    );
    assert_eq!(
        detect("Group,Title,Username,Password,URL,Notes,TOTP"),
        Some(CsvPreset::KeePassXC)
    );
    assert_eq!(
        detect("name,url,username,password,note"),
        Some(CsvPreset::Chrome)
    );
    assert_eq!(detect("col_a,col_b"), None);
    // Bitwarden wins the overlap: KeePassXC's signature (group+title+password)
    // is also present when login_* columns exist.
    assert_eq!(
        detect("group,title,username,password,url,login_uri,login_username,login_password"),
        Some(CsvPreset::Bitwarden)
    );
}

#[test]
fn staging_zeroizes_on_drop_discipline() {
    let mut row = CsvStagedRow {
        title: "Site".to_string(),
        url: Some("https://x.test".to_string()),
        username: "user".to_string(),
        password: "secret-password".to_string(),
        notes: Some("secret notes".to_string()),
        totp_secret: Some("JBSWY3DPEHPK3PXP".to_string()),
        group: Some("Web".to_string()),
    };
    row.zeroize();
    assert!(row.title.is_empty());
    assert!(row.password.is_empty());
    assert!(row.username.is_empty());
    // zeroize's Option impl TAKES the value (leaves None) after wiping it.
    assert!(row.url.is_none());
    assert!(row.notes.is_none());
    assert!(row.totp_secret.is_none());
    assert!(row.group.is_none());

    let mut staged = CsvStagedImport {
        preset: "Chrome".to_string(),
        skipped_rows: 1,
        rows: vec![CsvStagedRow {
            title: "T".to_string(),
            url: None,
            username: "u".to_string(),
            password: "p".to_string(),
            notes: None,
            totp_secret: None,
            group: None,
        }],
    };
    staged.zeroize();
    assert!(staged.rows.is_empty());
    assert_eq!(staged.skipped_rows, 0);
}

// ---------------------------------------------------------------------------
// Caps, staging lifecycle, locked-vault rejection
// ---------------------------------------------------------------------------

#[test]
fn oversized_files_are_rejected() {
    let (state, _dir) = unlocked_state();
    let bytes = vec![b'a'; MAX_CSV_FILE_BYTES + 1];
    let error = import_csv_open(&state, bytes).unwrap_err();
    match error {
        VaultError::InvalidInput { code, .. } => assert_eq!(code, "CSV_FILE_TOO_LARGE"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn row_overflow_is_rejected() {
    let (state, _dir) = unlocked_state();
    let mut csv = String::from("name,url,username,password\n");
    for i in 0..=MAX_CSV_ROWS {
        csv.push_str(&format!("Site {i},https://{i}.test,u{i},pw{i}\n"));
    }
    let error = import_csv_open(&state, csv.into_bytes()).unwrap_err();
    match error {
        VaultError::InvalidInput { code, .. } => assert_eq!(code, "CSV_TOO_MANY_ROWS"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn locking_discards_the_staging() {
    let state = Arc::new(AppState::default());
    *state.csv_import_staging.lock().unwrap() = Some(CsvStagedImport {
        preset: "Chrome".to_string(),
        skipped_rows: 0,
        rows: vec![CsvStagedRow {
            title: "T".to_string(),
            url: None,
            username: "u".to_string(),
            password: "p".to_string(),
            notes: None,
            totp_secret: None,
            group: None,
        }],
    });
    // All lock paths funnel through AppState::lock_vault (manual, tray,
    // auto-lock) — one drop point covers them all.
    state.lock_vault();
    assert!(state.csv_import_staging.lock().unwrap().is_none());
}

#[test]
fn failed_open_invalidates_a_previous_staging() {
    let (state, _dir) = unlocked_state();
    import_csv_open(&state, chrome_csv(&[("A", "https://a.test", "a", "pw-a")])).unwrap();
    assert!(state.csv_import_staging.lock().unwrap().is_some());

    // An unrecognized layout clears the previous staging: commit must only
    // ever run on rows the LAST successful preview showed.
    let error = import_csv_open(&state, b"col_a,col_b\n1,2".to_vec()).unwrap_err();
    match error {
        VaultError::InvalidInput { code, message } => {
            assert_eq!(code, "CSV_FORMAT_UNKNOWN");
            // The failure message lists every preset's expected headers.
            for preset in ["Bitwarden", "1Password", "Chrome", "KeePassXC"] {
                assert!(
                    message.contains(preset),
                    "message missing {preset}: {message}"
                );
            }
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(state.csv_import_staging.lock().unwrap().is_none());
}

#[test]
fn locked_vault_rejects_open_and_commit() {
    let state = Arc::new(AppState::default());
    // NOTE: locked by default — no session unlock.
    assert!(matches!(
        import_csv_open(&state, b"name,url,username,password".to_vec()),
        Err(VaultError::VaultLocked)
    ));
    assert!(matches!(
        import_csv_commit(&state),
        Err(VaultError::VaultLocked)
    ));
}

// ---------------------------------------------------------------------------
// Full open → commit flow against a real database
// ---------------------------------------------------------------------------

fn chrome_csv(rows: &[(&str, &str, &str, &str)]) -> Vec<u8> {
    let mut csv = String::from("name,url,username,password\n");
    for (name, url, username, password) in rows {
        csv.push_str(&format!("{name},{url},{username},{password}\n"));
    }
    csv.into_bytes()
}

#[test]
fn commit_reports_that_nothing_is_staged_without_an_open() {
    let (state, _dir) = unlocked_state();
    let error = import_csv_commit(&state).unwrap_err();
    match error {
        VaultError::InvalidInput { code, .. } => assert_eq!(code, "CSV_NO_STAGED_IMPORT"),
        other => panic!("unexpected error: {other:?}"),
    }
}

/// The plan's centerpiece flow: Bitwarden export (CRLF + BOM + quoted
/// embedded newline + shuffled/extra columns) into a vault that already has
/// a matching entry and a matching group.
#[test]
fn open_then_commit_imports_entries_and_dedups_groups() {
    let (state, _dir) = unlocked_state();

    // Pre-existing vault state: "Web" group + an entry that duplicates row 1.
    let web = create_group(&state, "Web".to_string()).unwrap();
    let _existing = create_entry(
        &state,
        crate::CreateEntryRequest {
            url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
            title: "Site A".to_string(),
            url: Some("https://a.example.com".to_string()),
            username: "a@x.com".to_string(),
            password: Zeroizing::new("pw-a-long".to_string()),
            notes: None,
            tags: vec![],
            group_id: Some(web.id.clone()),
            custom_fields: Vec::new(),
        },
    )
    .unwrap();

    // Bitwarden export with EVERY parser hazard: BOM, CRLF endings, quoted
    // embedded newline in notes, shuffled columns, an extra column, a blank
    // line, and an invalid row (empty username).
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(
        b"login_uri,extra,login_username,name,login_password,notes,login_totp,folder\r\n\
          https://a.example.com,x,a@x.com,Site A,pw-a-long,,,Web\r\n\
          https://b.example.com,x,b@x.com,Site B,pw-b,\"line1\nline2\",JBSWY3DPEHPK3PXP,\r\n\
          ,x,c@x.com,Site C,pw-c,,JBSWY3DPEHPK3PXP,Mail\r\n\
          \r\n\
          https://d.example.com,x,,Site D,pw-d,,,Web\r\n",
    );

    let preview = import_csv_open(&state, bytes).unwrap();
    assert_eq!(preview.preset, "Bitwarden");
    // 5 data rows: 3 valid + 1 blank skip + 1 invalid skip.
    assert_eq!(preview.total_rows, 5);
    assert_eq!(preview.rows.len(), 3);
    assert_eq!(preview.skipped_rows, 2);
    assert_eq!(preview.duplicate_candidates, 1);
    // Preview carries no password values — presence flags only.
    assert!(preview.rows.iter().all(|row| row.has_password));
    // Column mapping is by NAME: Site A's folder lands even though the
    // columns are shuffled, Site B's empty folder imports ungrouped.
    assert_eq!(preview.rows[0].group.as_deref(), Some("Web"));
    assert_eq!(preview.rows[1].group, None);
    assert_eq!(preview.rows[2].group.as_deref(), Some("Mail"));
    // The quoted newline stayed inside one field (notes presence flag).
    assert!(preview.rows[1].has_notes);
    assert!(preview.rows[1].has_totp);

    let result = import_csv_commit(&state).unwrap();
    assert_eq!(result.created_entries, 3);
    // "Web" matched the existing group; "Mail" is the only new one.
    assert_eq!(result.created_groups, 1);
    assert_eq!(result.skipped_rows, 2);

    // Staging is consumed (zeroized on drop) after a successful commit.
    assert!(state.csv_import_staging.lock().unwrap().is_none());

    // Rows landed with the right groups, and the vault stays digest-consistent.
    let entries = list_all_entries(&state).unwrap();
    assert_eq!(entries.len(), 4);
    let grouped: std::collections::HashMap<String, Option<String>> = entries
        .into_iter()
        .map(|entry| (entry.title, entry.group_id))
        .collect();
    assert_eq!(grouped["Site A"].as_deref(), Some(web.id.as_str()));
    assert_eq!(grouped["Site B"], None);
    let groups = list_all_groups(&state).unwrap();
    assert_eq!(groups.len(), 2);

    // Single-transaction discipline (structural): commit went through exactly
    // ONE VaultStore::write, so the digest was pre-verified and refreshed once
    // — a second full verification passes here.
    let db = crate::service::vault::get_db(&state).unwrap();
    let mac_key = state.session.get_mac_key().unwrap();
    assert!(database::integrity::verify_integrity(&db, &mac_key).unwrap());
}

#[test]
fn rows_without_a_group_column_create_no_groups() {
    let (state, _dir) = unlocked_state();
    import_csv_open(
        &state,
        chrome_csv(&[
            ("A", "https://a.test", "a", "pw-a"),
            ("B", "https://b.test", "b", "pw-b"),
        ]),
    )
    .unwrap();
    let result = import_csv_commit(&state).unwrap();
    assert_eq!(result.created_entries, 2);
    assert_eq!(result.created_groups, 0);
    let entries = list_all_entries(&state).unwrap();
    assert!(entries.iter().all(|entry| entry.group_id.is_none()));
    assert!(list_all_groups(&state).unwrap().is_empty());
}

#[test]
fn duplicate_candidates_count_staged_rows_matching_the_vault() {
    let (state, _dir) = unlocked_state();
    let _existing = create_entry(
        &state,
        crate::CreateEntryRequest {
            url_match_mode: pwdvault_domain::UrlMatchMode::Auto,
            title: "Existing".to_string(),
            url: Some("https://dup.test".to_string()),
            username: "dup@x.com".to_string(),
            password: Zeroizing::new("pw-existing".to_string()),
            notes: None,
            tags: vec![],
            group_id: None,
            custom_fields: Vec::new(),
        },
    )
    .unwrap();

    let preview = import_csv_open(
        &state,
        chrome_csv(&[
            ("Dup", "https://dup.test", "dup@x.com", "pw-1"),
            ("Other", "https://other.test", "dup@x.com", "pw-2"),
            ("Dup2", "https://dup.test", "someoneelse@x.com", "pw-3"),
        ]),
    )
    .unwrap();
    // Only username AND url matching together counts.
    assert_eq!(preview.duplicate_candidates, 1);
}
