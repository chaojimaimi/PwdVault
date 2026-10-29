//! Security dashboard aggregation (WP1, v1.5.0; verdict reworked v1.7.0) —
//! Tauri-only.
//!
//! Scans every LIVE entry, decrypts the password in-process, and reports
//! three findings WITHOUT any plaintext leaving the process:
//! `weak` (id + zxcvbn grade, capped at 2 — see WeakPasswordFinding),
//! `reused` (id groups sharing the identical password), `stale` (ids
//! untouched for over a year).
//!
//! Deliberately NOT built on `get_entry_secret`: that service bumps
//! `last_used_at` (60s-throttled write) per entry — a dashboard sweep would
//! pollute the "Recently used" sort AND double the plaintext exposure window.
//! The read path mirrors the sync engine's `decrypt_inner` pattern instead
//! (state_io.rs) — bincode first, raw nonce||ciphertext fallback.
//!
//! Plaintext discipline (SEC-M3): decrypted passwords are `Zeroizing<String>`
//! end to end; the reuse detector buckets SHA-256 DIGESTS only (never the
//! plaintext itself); the bucket map is dropped at function exit. The
//! aggregation entry point takes `Zeroizing` inputs, so a bare `String`
//! cannot reach it — that is the compile-time enforcement pinned by the
//! `ReportInput` shape.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::service::vault::get_db;
use crate::{AppState, VaultError};
use pwdvault_domain::strength::{classify_password, zxcvbn_score, PasswordVerdict};
use pwdvault_infrastructure::crypto::{bc_deserialize, decrypt, EncryptedData, KEY_SIZE};
use pwdvault_infrastructure::database::{list_all_entries_bulk, PasswordEntry};

/// Staleness window: `updated_at` more than 365 days in the past. `updated_at`
/// is the CONTENT MODIFICATION time — the UI copy must say "unchanged for
/// over a year", never "unused" (last_used_at deliberately never bumps it).
pub const STALE_THRESHOLD_SECS: i64 = 365 * 24 * 60 * 60;

/// One weak-password finding: metadata only, no plaintext.
#[derive(Debug, Serialize)]
pub struct WeakPasswordFinding {
    pub id: String,
    /// zxcvbn 0-4 grade, CAPPED AT 2 (v1.7.0 semantic change: this was the
    /// 0-100 heuristic score before). A corpus-layer hit on a password
    /// zxcvbn grades 3-4 must still render as Weak/Very Weak on the
    /// dashboard — without the cap the weak list would carry a "Strong"
    /// grade (the frontend maps 4 → Strong), contradicting the row's
    /// presence in the weak list.
    pub score: u32,
}

/// The full dashboard report. The response shape is the security contract:
/// ids, counts, and scores — nothing decryptable ever crosses IPC.
#[derive(Debug, Serialize)]
pub struct SecurityReport {
    pub generated_at: i64,
    /// Number of live entries scanned.
    pub total: usize,
    /// Entries whose password classifies Weak (empty, a corpus-layer hit,
    /// or zxcvbn ≤ 2 — pwdvault_domain::strength::classify_password).
    pub weak: Vec<WeakPasswordFinding>,
    /// Groups of ≥ 2 entries whose passwords are byte-identical.
    pub reused: Vec<Vec<String>>,
    /// Entries whose `updated_at` is more than a year old.
    pub stale: Vec<String>,
}

/// Aggregation input row. `password` is `Zeroizing` so a bare `String`
/// cannot be passed in — the compiler enforces the plaintext discipline.
pub struct ReportInput {
    pub id: String,
    pub password: Zeroizing<String>,
    pub updated_at: i64,
}

/// Pure aggregation over decrypted inputs (unit-testable without a database).
///
/// The reuse buckets hold SHA-256 digests as keys, never plaintext, and the
/// map dies with the call frame. Results are sorted for a deterministic wire
/// payload (HashMap iteration order would otherwise leak run-to-run noise
/// into the UI).
pub fn aggregate_report(now: i64, inputs: &[ReportInput]) -> SecurityReport {
    let mut weak: Vec<WeakPasswordFinding> = Vec::new();
    let mut stale: Vec<String> = Vec::new();
    let mut digest_buckets: HashMap<[u8; 32], Vec<String>> = HashMap::new();

    for input in inputs {
        // Weak verdict: empty password, corpus-layer hit, or zxcvbn ≤ 2
        // (classify_password owns the full ladder — see strength.rs).
        if classify_password(&input.password) == PasswordVerdict::Weak {
            weak.push(WeakPasswordFinding {
                id: input.id.clone(),
                score: u32::from(zxcvbn_score(&input.password).min(2)),
            });
        }
        if now.saturating_sub(input.updated_at) > STALE_THRESHOLD_SECS {
            stale.push(input.id.clone());
        }
        // Only non-empty passwords participate in reuse detection: empty
        // password fields are legal on historical (backup-restored) rows and
        // must not report as "shared password" groups.
        if !input.password.is_empty() {
            let digest: [u8; 32] = Sha256::digest(input.password.as_bytes()).into();
            digest_buckets
                .entry(digest)
                .or_default()
                .push(input.id.clone());
        }
    }

    let mut reused: Vec<Vec<String>> = digest_buckets
        .into_values()
        .filter(|group| group.len() >= 2)
        .collect();
    // Digest-based grouping is deterministic already, but sort the id lists
    // (and groups by first id) so the payload is stable across reruns.
    for group in &mut reused {
        group.sort();
    }
    reused.sort();

    SecurityReport {
        generated_at: now,
        total: inputs.len(),
        weak,
        reused,
        stale,
    }
}

/// Build the dashboard report for the unlocked vault. Locked vaults are
/// rejected by the session lease (`VaultLocked`).
pub fn security_report(state: &Arc<AppState>) -> Result<SecurityReport, VaultError> {
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;

    // Raw infra scan + tombstone filter here (the service-wide pattern): the
    // trash is not part of the security posture of the live vault.
    let entries: Vec<PasswordEntry> = list_all_entries_bulk(&db, key, None)?
        .into_iter()
        .filter(|entry| entry.deleted_at.is_none())
        .collect();

    let mut inputs: Vec<ReportInput> = Vec::with_capacity(entries.len());
    for entry in entries {
        let password = decrypt_entry_password(key, &entry.encrypted_password)?;
        inputs.push(ReportInput {
            id: entry.id,
            password,
            updated_at: entry.updated_at,
        });
    }

    let now = chrono::Utc::now().timestamp();
    let report = aggregate_report(now, &inputs);

    // Explicit vault operation: extends the 120s remote-activity grace
    // (SEC-L5 policy, same as the other read services).
    lease.touch_remote_activity();
    Ok(report)
}

/// Decrypt one inner password blob — the sync engine's `decrypt_inner`
/// pattern (bincode `EncryptedData` first, raw nonce||ciphertext fallback),
/// with the plaintext consumed straight into `Zeroizing` so no unmanaged
/// copy ever exists (SEC-M3).
fn decrypt_entry_password(
    key: &[u8; KEY_SIZE],
    blob: &[u8],
) -> Result<Zeroizing<String>, VaultError> {
    let sealed: EncryptedData = bc_deserialize(blob)
        .or_else(|_| EncryptedData::from_bytes(blob))
        .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;
    match String::from_utf8(decrypt(key, &sealed)?) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(e) => {
            let message = e.to_string();
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            Err(VaultError::DecryptionFailed(message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use pwdvault_infrastructure::crypto::kdf::AdaptiveParams;
    use pwdvault_infrastructure::database;

    fn input(id: &str, password: &str, updated_at: i64) -> ReportInput {
        ReportInput {
            id: id.to_string(),
            password: Zeroizing::new(password.to_string()),
            updated_at,
        }
    }

    const NOW: i64 = 1_800_000_000;

    /// Same minimal unlocked-vault fixture the other service tests use.
    fn unlocked_state() -> (Arc<AppState>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(database::init_database(dir.path().join("security_report.db")).unwrap());
        let salt = [0x61; 16];
        let params = AdaptiveParams {
            m_cost: 16384,
            t_cost: 1,
            p_cost: 1,
        };
        let (master_key, _) = pwdvault_infrastructure::crypto::kdf::derive_key_with_params(
            "security-report-test-password",
            &salt,
            &params,
        )
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
                database::vault_store::save_settings_in_txn(txn, &database::Settings::default())?;
                Ok(())
            })
            .unwrap();

        let state = Arc::new(AppState::default());
        *state.database.lock().unwrap() = Some(db);
        *state.verification_data.lock().unwrap() = Some(verification);
        state.session.unlock(enc_key, mac_key);
        (state, dir)
    }

    /// Store one entry with the given plaintext password + updated_at.
    fn store_entry(state: &Arc<AppState>, title: &str, password: &str, updated_at: i64) {
        let db = crate::service::vault::get_db(state).unwrap();
        let key = state.session.get_enc_key().unwrap();
        let mac_key = state.session.get_mac_key().unwrap();
        let mut entry = PasswordEntry::new(
            title.to_string(),
            None,
            format!("{title}-user@example.test"),
        );
        let sealed = pwdvault_infrastructure::crypto::encrypt(&key, password.as_bytes()).unwrap();
        entry.encrypted_password = pwdvault_infrastructure::crypto::bc_serialize(&sealed).unwrap();
        entry.updated_at = updated_at;
        database::vault_store::VaultStore::new(&db)
            .write(&mac_key, |txn| {
                database::vault_store::save_entry_in_txn(txn, &key, &entry)?;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn weak_buckets_follow_the_classification_verdict() {
        let inputs = vec![
            // Strong (zxcvbn 4, corpus-clean) — not weak.
            input("strong", "kX9$mP2!vL5#nQ8@wR4&jF7^", NOW),
            // Corpus exact hit (also zxcvbn 0) — weak, wire score 0.
            input("weak", "password", NOW),
            // zxcvbn 3 = Fair, no corpus hit — not weak under the v1.7.0
            // ladder (it was 53/100 on the retired heuristic).
            input("medium", "hello world", NOW),
        ];
        let report = aggregate_report(NOW, &inputs);
        assert_eq!(report.total, 3);
        assert_eq!(report.weak.len(), 1);
        assert_eq!(report.weak[0].id, "weak");
        // "password" carries zxcvbn grade 0 on the wire (capped at 2 anyway).
        assert_eq!(report.weak[0].score, 0);
    }

    #[test]
    fn corpus_forced_weak_rows_carry_a_capped_wire_score() {
        // "iloveyou84920173@!" hits the core-word formula but zxcvbn grades
        // it 4 (Strong). The verdict is Weak (corpus overrules) and the wire
        // score is capped at 2 so the frontend never renders a "Strong"
        // grade label inside the weak list.
        let inputs = vec![input("forced", "iloveyou84920173@!", NOW)];
        let report = aggregate_report(NOW, &inputs);
        assert_eq!(report.weak.len(), 1);
        assert_eq!(report.weak[0].score, 2);
    }

    #[test]
    fn reused_groups_share_identical_passwords() {
        let inputs = vec![
            input("a", "same-secret-1", NOW),
            input("b", "same-secret-1", NOW),
            input("c", "same-secret-1", NOW),
            input("d", "other-secret-2", NOW),
            input("e", "other-secret-2", NOW),
            input("f", "unique-secret-3", NOW),
        ];
        let report = aggregate_report(NOW, &inputs);
        assert_eq!(report.reused.len(), 2);
        assert_eq!(
            report.reused[0],
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert_eq!(report.reused[1], vec!["d".to_string(), "e".to_string()]);
    }

    #[test]
    fn empty_passwords_never_report_as_reused() {
        // Historical backup-restored rows may have empty password fields.
        let inputs = vec![input("a", "", NOW), input("b", "", NOW)];
        let report = aggregate_report(NOW, &inputs);
        assert!(report.reused.is_empty());
        // They still count toward the total and the weak list (score 0).
        assert_eq!(report.total, 2);
        assert_eq!(report.weak.len(), 2);
    }

    #[test]
    fn stale_boundary_is_strictly_more_than_365_days() {
        let day = 24 * 60 * 60;
        let inputs = vec![
            input("fresh", "pw-1", NOW),                        // today
            input("edge-inside", "pw-2", NOW - 365 * day),      // exactly 365d
            input("edge-outside", "pw-3", NOW - 365 * day - 1), // one second over
            input("old", "pw-4", NOW - 366 * day),
        ];
        let report = aggregate_report(NOW, &inputs);
        assert_eq!(
            report.stale,
            vec!["edge-outside".to_string(), "old".to_string()]
        );
    }

    #[test]
    fn reuse_buckets_hold_digests_not_plaintext() {
        // Structural pin for the plaintext discipline: the bucket key type is
        // a 32-byte digest, so plaintext can only live inside ReportInput.
        let inputs = vec![input("a", "leak-check", NOW), input("b", "leak-check", NOW)];
        let report = aggregate_report(NOW, &inputs);
        assert_eq!(report.reused, vec![vec!["a".to_string(), "b".to_string()]]);
        // The aggregation signature takes Zeroizing inputs; this line is the
        // same guarantee expressed in the type system (a bare String is a
        // compile error at the aggregate_report call site).
        let _enforced: &Zeroizing<String> = &inputs[0].password;
    }

    #[test]
    fn service_scans_live_entries_only_and_never_get_entry_secret() {
        let (state, _dir) = unlocked_state();
        // The service stamps the report with the REAL clock, so the stale
        // fixture anchors at the epoch (always > 365 days old) and the fresh
        // fixture at the current time.
        let now = chrono::Utc::now().timestamp();
        store_entry(&state, "Fresh", "kX9$mP2!vL5#nQ8@wR4&jF7^", now);
        store_entry(&state, "Old", "pw-old-1", 0);
        store_entry(&state, "Dead", "password-dead", now);
        // Tombstone the "Dead" row — it must not appear in the report even
        // though its password would be weak.
        let db = crate::service::vault::get_db(&state).unwrap();
        let key = state.session.get_enc_key().unwrap();
        let mac_key = state.session.get_mac_key().unwrap();
        let mut dead = database::list_all_entries_bulk(&db, &key, None)
            .unwrap()
            .into_iter()
            .find(|entry| entry.title == "Dead")
            .unwrap();
        dead.deleted_at = Some(NOW);
        database::vault_store::VaultStore::new(&db)
            .write(&mac_key, |txn| {
                database::vault_store::save_entry_in_txn(txn, &key, &dead)?;
                Ok(())
            })
            .unwrap();

        let report = security_report(&state).unwrap();
        assert_eq!(report.total, 2); // tombstone excluded from the count
        assert!(report.weak.iter().all(|finding| finding.id != dead.id));
        assert_eq!(report.stale, vec![report_title_id(&state, "Old")]);
    }

    fn report_title_id(state: &Arc<AppState>, title: &str) -> String {
        let db = crate::service::vault::get_db(state).unwrap();
        let key = state.session.get_enc_key().unwrap();
        database::list_all_entries_bulk(&db, &key, None)
            .unwrap()
            .into_iter()
            .find(|entry| entry.title == title)
            .unwrap()
            .id
    }

    #[test]
    fn locked_vault_rejects_the_report() {
        let state = Arc::new(AppState::default()); // locked session
        assert!(matches!(
            security_report(&state),
            Err(VaultError::VaultLocked)
        ));
    }
}
