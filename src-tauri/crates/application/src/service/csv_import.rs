//! Third-party CSV importer (WP2, v1.5.0) — Tauri-only.
//!
//! Two-command flow (SEC-M2 discipline: plaintext never crosses the webview
//! on the desktop path):
//!
//! 1. [`import_csv_open`] — native open dialog happens in the tauri-app
//!    adapter; this service receives the raw bytes, parses + validates them,
//!    stages the plaintext rows in `AppState` (locked vaults drop the
//!    staging), and returns a PREVIEW without any password column.
//! 2. [`import_csv_commit`] — pre-seals every staged row and writes groups +
//!    entries in ONE `VaultStore` transaction (single digest refresh; the
//!    backup-import path at backup.rs Stage 5-6 is the precedent — per-row
//!    commits would trigger one whole-database digest refresh per row).
//!
//! Supported presets: Bitwarden / 1Password / Chrome / KeePassXC, recognized
//! by header signature. Parsing rules (all four exporters need them): UTF-8
//! BOM stripping (BEFORE the header match), CRLF/CR/LF normalization, and
//! RFC4180 quoted fields incl. embedded newlines.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::service::vault::get_db;
use crate::{AppState, CreateEntryRequest, VaultError};
use pwdvault_domain::constants::MAX_TOTP_SECRET_LENGTH;
use pwdvault_infrastructure::crypto::{bc_serialize, encrypt};
use pwdvault_infrastructure::database::{
    list_all_entries_bulk, list_all_groups_bulk, vault_store, Group, PasswordEntry,
};

/// Hard cap on the picked file (defense against a mis-selected huge blob).
pub const MAX_CSV_FILE_BYTES: usize = 10 * 1024 * 1024;
/// Hard cap on data rows (excludes the header row).
pub const MAX_CSV_ROWS: usize = 5000;

fn invalid_csv(code: &'static str, message: impl Into<String>) -> VaultError {
    VaultError::InvalidInput {
        code: code.to_string(),
        message: message.into(),
    }
}

// ---------------------------------------------------------------------------
// CSV parsing (RFC4180 subset the four exporters actually emit)
// ---------------------------------------------------------------------------

/// Strip a UTF-8 BOM. 1Password and Chrome exports carry one; the header
/// signature match must run AFTER the strip or the first column name keeps
/// an invisible prefix and every signature misses.
fn strip_bom(bytes: &[u8]) -> &[u8] {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    }
}

/// Normalize CRLF and lone CR to LF so the field parser only has to know
/// about `\n` (quoted embedded newlines end up normalized too — documented).
fn normalize_newlines(text: &str) -> String {
    if !text.contains('\r') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    out
}

/// Decode picked bytes into normalized CSV text. Non-UTF-8 input is rejected
/// (never mangled lossy — silent byte corruption of passwords is worse than
/// a clear error).
fn decode_csv_text(bytes: &[u8]) -> Result<String, VaultError> {
    let stripped = strip_bom(bytes);
    let text = std::str::from_utf8(stripped)
        .map_err(|_| invalid_csv("CSV_NOT_UTF8", "The selected file is not valid UTF-8 text"))?
        .to_string();
    Ok(normalize_newlines(&text))
}

/// Parse RFC4180 CSV: comma-separated, double-quoted fields with `""`
/// escapes and embedded newlines. A quote only opens quoted mode at field
/// start; quotes elsewhere are literal (the lenient reading — none of the
/// four exporters emit mid-field bare quotes).
pub fn parse_csv(input: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                // `""` inside a quoted field is an escaped literal quote.
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                // Embedded newlines and commas are field content here.
                field.push(c);
            }
        } else {
            match c {
                '"' if field.is_empty() => in_quotes = true,
                ',' => row.push(std::mem::take(&mut field)),
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                _ => field.push(c),
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

// ---------------------------------------------------------------------------
// Presets: header signatures + column mapping
// ---------------------------------------------------------------------------

/// Recognized exporter layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsvPreset {
    Bitwarden,
    OnePassword,
    Chrome,
    KeePassXC,
}

impl CsvPreset {
    pub fn name(self) -> &'static str {
        match self {
            CsvPreset::Bitwarden => "Bitwarden",
            CsvPreset::OnePassword => "1Password",
            CsvPreset::Chrome => "Chrome",
            CsvPreset::KeePassXC => "KeePassXC",
        }
    }

    /// Human-readable header expectation for the recognition-failure error.
    fn expected_headers(self) -> &'static str {
        match self {
            CsvPreset::Bitwarden => {
                "folder, favorite, type, name, notes, fields, reprompt, \
                 login_uri, login_username, login_password, login_totp"
            }
            CsvPreset::OnePassword => "Title, Url, Username, Password, Notes, OTPAuth",
            CsvPreset::Chrome => "name, url, username, password, note",
            CsvPreset::KeePassXC => "Group, Title, Username, Password, URL, Notes, TOTP",
        }
    }
}

/// Header-name → column index for one file (names lowercased + trimmed;
/// column ORDER is irrelevant — mapping is by name).
fn header_index_map(headers: &[String]) -> HashMap<String, usize> {
    headers
        .iter()
        .enumerate()
        .map(|(index, header)| (header.trim().to_ascii_lowercase(), index))
        .collect()
}

/// Header-signature detection. Order matters: earlier presets claim their
/// distinctive columns first so ambiguous overlaps resolve deterministically
/// (`login_*` → Bitwarden; `otpauth` → 1Password; `group` → KeePassXC; the
/// plain `name/url/username/password` quartet → Chrome).
fn detect_preset(headers: &HashMap<String, usize>) -> Option<CsvPreset> {
    let has = |name: &str| headers.contains_key(name);
    if has("login_uri") && has("login_username") {
        Some(CsvPreset::Bitwarden)
    } else if has("otpauth") && has("title") {
        Some(CsvPreset::OnePassword)
    } else if has("group") && has("title") && has("password") {
        Some(CsvPreset::KeePassXC)
    } else if has("name") && has("url") && has("username") && has("password") {
        Some(CsvPreset::Chrome)
    } else {
        None
    }
}

/// Column mapping per preset: canonical field → source header name. `None`
/// means the preset has no such column (e.g. Chrome has no group/TOTP).
struct ColumnSpec {
    title: &'static str,
    username: &'static str,
    url: &'static str,
    password: &'static str,
    notes: Option<&'static str>,
    totp: Option<&'static str>,
    group: Option<&'static str>,
}

fn columns(preset: CsvPreset) -> ColumnSpec {
    match preset {
        CsvPreset::Bitwarden => ColumnSpec {
            title: "name",
            username: "login_username",
            url: "login_uri",
            password: "login_password",
            notes: Some("notes"),
            totp: Some("login_totp"),
            group: Some("folder"),
        },
        CsvPreset::OnePassword => ColumnSpec {
            title: "title",
            username: "username",
            url: "url",
            password: "password",
            notes: Some("notes"),
            totp: Some("otpauth"),
            group: None,
        },
        CsvPreset::Chrome => ColumnSpec {
            title: "name",
            username: "username",
            url: "url",
            password: "password",
            notes: Some("note"),
            totp: None,
            group: None,
        },
        CsvPreset::KeePassXC => ColumnSpec {
            title: "title",
            username: "username",
            url: "url",
            password: "password",
            notes: Some("notes"),
            totp: Some("totp"),
            group: Some("group"),
        },
    }
}

fn unrecognized_message() -> String {
    let presets = [
        CsvPreset::Bitwarden,
        CsvPreset::OnePassword,
        CsvPreset::Chrome,
        CsvPreset::KeePassXC,
    ];
    let mut message = String::from(
        "Could not recognize the CSV layout. Supported exports and their \
         expected headers:\n",
    );
    for preset in presets {
        message.push_str(&format!(
            "  {}: {}\n",
            preset.name(),
            preset.expected_headers()
        ));
    }
    message
}

// ---------------------------------------------------------------------------
// Staging (plaintext rows live in AppState between open and commit)
// ---------------------------------------------------------------------------

/// One validated CSV row. Derives `Zeroize`/`ZeroizeOnDrop` (plan WP2): the
/// staging may hold thousands of plaintext passwords and must wipe on drop —
/// including the lock-path drop performed by `AppState::lock_vault`.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct CsvStagedRow {
    pub title: String,
    pub url: Option<String>,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    /// Validated (trimmed) group NAME — ids are only resolved at commit.
    pub group: Option<String>,
}

/// The staged import as a whole. Re-staging a new file supersedes the old
/// staging; committing consumes it; locking drops it.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct CsvStagedImport {
    pub preset: String,
    /// Rows rejected at open time (validation failures + blank layout rows) —
    /// echoed back by the commit result so the final toast reconciles with
    /// the preview even though commit only ever sees valid rows.
    pub skipped_rows: usize,
    pub rows: Vec<CsvStagedRow>,
}

/// One preview row — password presence only, never the value.
#[derive(Debug, Serialize)]
pub struct CsvImportPreviewRow {
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub group: Option<String>,
    pub has_password: bool,
    pub has_notes: bool,
    pub has_totp: bool,
}

/// Response of `import_csv_open`. `duplicate_candidates` counts staged rows
/// whose (username, url) pair already exists in the vault — informational:
/// they are STILL imported as new entries (Bitwarden import semantics, no
/// merge/skip UI in v1).
#[derive(Debug, Serialize)]
pub struct CsvImportPreview {
    pub preset: String,
    /// Data rows in the file (header excluded, blank lines included).
    pub total_rows: usize,
    /// Rows that will NOT import (blank lines + validation failures).
    pub skipped_rows: usize,
    pub duplicate_candidates: usize,
    pub rows: Vec<CsvImportPreviewRow>,
}

/// Response of `import_csv_commit`.
#[derive(Debug, Serialize)]
pub struct CsvImportResult {
    pub created_entries: usize,
    pub created_groups: usize,
    pub skipped_rows: usize,
}

// ---------------------------------------------------------------------------
// import_csv_open — parse, validate, stage, preview
// ---------------------------------------------------------------------------

/// Parse + validate + stage a CSV file. Requires an UNLOCKED vault (the
/// duplicate scan reads live entries, and a staging that could never be
/// committed should never exist). The staging replaces any previous one.
pub fn import_csv_open(
    state: &Arc<AppState>,
    bytes: Vec<u8>,
) -> Result<CsvImportPreview, VaultError> {
    let lease = state.lease()?;
    // Any new open attempt invalidates a PREVIOUS staging right away: a
    // failed open must not leave commit-able rows behind that the user never
    // saw a preview for.
    *state
        .csv_import_staging
        .lock()
        .expect("csv staging lock poisoned") = None;
    if bytes.len() > MAX_CSV_FILE_BYTES {
        return Err(invalid_csv(
            "CSV_FILE_TOO_LARGE",
            format!(
                "The selected file is larger than {} MiB",
                MAX_CSV_FILE_BYTES / (1024 * 1024)
            ),
        ));
    }

    let text = decode_csv_text(&bytes)?;
    let grid = parse_csv(&text);
    if grid.is_empty() {
        return Err(invalid_csv(
            "CSV_EMPTY",
            "The selected file has no CSV rows",
        ));
    }
    let header_map = header_index_map(&grid[0]);
    let Some(preset) = detect_preset(&header_map) else {
        return Err(invalid_csv("CSV_FORMAT_UNKNOWN", unrecognized_message()));
    };

    let staged = stage_rows(preset, &grid)?;
    let preview = build_preview(preset, &staged);

    // Duplicate statistic (username + url) against the live vault. Both
    // sides normalize through the same validation helpers so the comparison
    // cannot diverge from what the entry screens store.
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let existing: HashSet<(String, String)> = list_all_entries_bulk(&db, key, None)?
        .into_iter()
        .filter(|entry| entry.deleted_at.is_none())
        .map(|entry| {
            (
                entry.username.trim().to_string(),
                pwdvault_domain::validation::normalize_url(entry.url.clone()).unwrap_or_default(),
            )
        })
        .collect();
    let duplicate_candidates = staged
        .rows
        .iter()
        .filter(|row| {
            existing.contains(&(
                row.username.trim().to_string(),
                row.url.clone().unwrap_or_default(),
            ))
        })
        .count();

    *state
        .csv_import_staging
        .lock()
        .expect("csv staging lock poisoned") = Some(staged);

    lease.touch_remote_activity();
    Ok(CsvImportPreview {
        duplicate_candidates,
        ..preview
    })
}

/// One column value by canonical header name (free fn so the return
/// lifetime can be tied to `row` — a closure cannot express that).
fn column_lookup<'a>(
    header_map: &HashMap<String, usize>,
    row: &'a [String],
    name: &str,
) -> Option<&'a str> {
    header_map
        .get(name)
        .and_then(|index| row.get(*index))
        .map(String::as_str)
}

/// Map + validate every data row. Rows failing DOMAIN validation skip
/// themselves (counted) instead of failing the whole file — one poisoned row
/// in a 3000-row export must not block the other 2999.
fn stage_rows(preset: CsvPreset, grid: &[Vec<String>]) -> Result<CsvStagedImport, VaultError> {
    let spec = columns(preset);
    let header_map = header_index_map(&grid[0]);

    let data_rows = grid.len().saturating_sub(1);
    if data_rows > MAX_CSV_ROWS {
        return Err(invalid_csv(
            "CSV_TOO_MANY_ROWS",
            format!(
                "The file has {} data rows; the limit is {}",
                data_rows, MAX_CSV_ROWS
            ),
        ));
    }

    let mut rows: Vec<CsvStagedRow> = Vec::with_capacity(data_rows);
    let mut skipped = 0usize;
    for row in &grid[1..] {
        // Whitespace-only layout rows are skips, not validation failures.
        if row.iter().all(|field| field.trim().is_empty()) {
            skipped += 1;
            continue;
        }
        let title = column_lookup(&header_map, row, spec.title).unwrap_or_default();
        let username = column_lookup(&header_map, row, spec.username).unwrap_or_default();
        let password = column_lookup(&header_map, row, spec.password).unwrap_or_default();
        let url = pwdvault_domain::validation::normalize_url(
            column_lookup(&header_map, row, spec.url).map(str::to_string),
        );
        let notes = spec
            .notes
            .and_then(|name| column_lookup(&header_map, row, name))
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let group = spec
            .group
            .and_then(|name| column_lookup(&header_map, row, name))
            .map(str::to_string);

        // Domain validation with the exact create_entry policy: title and
        // username non-empty + length caps, password non-empty + length cap,
        // url/notes length caps. Group names validate through group_name
        // (which also performs the canonical trim).
        let group = match group.as_deref() {
            None => None,
            Some(raw) if raw.trim().is_empty() => None,
            Some(raw) => match pwdvault_domain::validation::group_name(raw) {
                Ok(name) => Some(name),
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            },
        };
        let request = CreateEntryRequest {
            url_match_mode: pwdvault_domain::UrlMatchMode::Auto, // CSV imports stay on the default (WP4: the desktop UI is the only setter)
            title: title.to_string(),
            url: url.clone(),
            username: username.to_string(),
            password: Zeroizing::new(password.to_string()),
            notes: notes.clone(),
            tags: Vec::new(),
            group_id: None,
        };
        if pwdvault_domain::validation::entry(&request).is_err() {
            skipped += 1;
            continue;
        }
        // TOTP column: same length policy as the entry-update tri-state;
        // base32 vs otpauth:// format differences are handled by the TOTP
        // generator at read time, not at import.
        let totp_secret = match spec
            .totp
            .and_then(|name| column_lookup(&header_map, row, name))
        {
            None => None,
            Some("") => None,
            Some(value) if value.len() <= MAX_TOTP_SECRET_LENGTH => Some(value.to_string()),
            Some(_) => {
                skipped += 1;
                continue;
            }
        };

        rows.push(CsvStagedRow {
            title: title.to_string(),
            url,
            username: username.to_string(),
            password: password.to_string(),
            notes,
            totp_secret,
            group,
        });
    }

    Ok(CsvStagedImport {
        preset: preset.name().to_string(),
        skipped_rows: skipped,
        rows,
    })
}

fn build_preview(preset: CsvPreset, staged: &CsvStagedImport) -> CsvImportPreview {
    CsvImportPreview {
        preset: preset.name().to_string(),
        total_rows: staged.rows.len() + staged.skipped_rows,
        skipped_rows: staged.skipped_rows,
        duplicate_candidates: 0,
        rows: staged
            .rows
            .iter()
            .map(|row| CsvImportPreviewRow {
                title: row.title.clone(),
                username: row.username.clone(),
                url: row.url.clone(),
                group: row.group.clone(),
                has_password: !row.password.is_empty(),
                has_notes: row.notes.is_some(),
                has_totp: row.totp_secret.is_some(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// import_csv_commit — pre-seal everything, write in ONE transaction
// ---------------------------------------------------------------------------

/// Commit the staged import. The STAGING is authoritative: the file may have
/// changed (or vanished) since the preview — documented, no re-read. Groups
/// dedup by trimmed exact name, both among staged rows and against the live
/// vault; rows without a group column import ungrouped.
pub fn import_csv_commit(state: &Arc<AppState>) -> Result<CsvImportResult, VaultError> {
    let lease = state.lease()?;
    // take() removes the staging up front: every path below (success AND
    // error) ends with the plaintext dropped and zeroized.
    let staged = state
        .csv_import_staging
        .lock()
        .expect("csv staging lock poisoned")
        .take()
        .ok_or_else(|| invalid_csv("CSV_NO_STAGED_IMPORT", "Pick a CSV file to import first"))?;

    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let mac_key = lease.mac_key()?;

    // Existing LIVE groups by trimmed name (plan: exact match after trim —
    // both between staged rows and against the vault).
    let mut groups_by_name: HashMap<String, String> = list_all_groups_bulk(&db, key)?
        .into_iter()
        .filter(|group| group.deleted_at.is_none())
        .map(|group| (group.name.trim().to_string(), group.id))
        .collect();

    // Resolve staged group names to ids; missing names become new groups,
    // created inside the same transaction as the entries.
    let mut group_ids: HashMap<String, String> = HashMap::new();
    let mut new_groups: Vec<Group> = Vec::new();
    for row in &staged.rows {
        let Some(name) = row.group.as_deref() else {
            continue;
        };
        if group_ids.contains_key(name) {
            continue;
        }
        if let Some(existing_id) = groups_by_name.get(name) {
            group_ids.insert(name.to_string(), existing_id.clone());
            continue;
        }
        let group = Group::new(name.to_string());
        group_ids.insert(name.to_string(), group.id.clone());
        groups_by_name.insert(name.to_string(), group.id.clone());
        new_groups.push(group);
    }

    // Pre-seal EVERY row before opening the write transaction (backup.rs
    // Stage 5 precedent): an encryption failure aborts cleanly without
    // holding the write lock, leaving vault and staging untouched.
    let mut sealed_entries: Vec<PasswordEntry> = Vec::with_capacity(staged.rows.len());
    for row in &staged.rows {
        let mut entry =
            PasswordEntry::new(row.title.clone(), row.url.clone(), row.username.clone());
        entry.encrypted_password = seal_field(key, &row.password)?;
        if let Some(notes) = &row.notes {
            entry.encrypted_notes = Some(seal_field(key, notes)?);
        }
        if let Some(totp) = &row.totp_secret {
            entry.encrypted_totp_secret = Some(seal_field(key, totp)?);
        }
        if let Some(name) = &row.group {
            entry.group_id = group_ids.get(name).cloned();
        }
        sealed_entries.push(entry);
    }

    // ONE transaction = ONE whole-database digest refresh (§5.1.2). Per-row
    // commits would refresh the digest once per row — the O(n²) write
    // amplification the batch-write discipline exists to prevent. Regression
    // fuse: the commit tests only verify post-hoc integrity, which per-row
    // writes would ALSO pass — this single `store.write` call is the guard
    // itself; do not split it.
    let store = vault_store::VaultStore::new(&db);
    store.write(mac_key, |txn| {
        for group in &new_groups {
            vault_store::save_group_in_txn(txn, key, group)?;
        }
        for entry in &sealed_entries {
            vault_store::save_entry_in_txn(txn, key, entry)?;
        }
        Ok(())
    })?;

    lease.touch_remote_activity();
    Ok(CsvImportResult {
        created_entries: sealed_entries.len(),
        created_groups: new_groups.len(),
        skipped_rows: staged.skipped_rows,
    })
}

/// Encrypt one plaintext field into its stored blob form (create_entry's
/// encrypt + bc_serialize pair).
fn seal_field(key: &[u8; 32], plaintext: &str) -> Result<Vec<u8>, VaultError> {
    let encrypted = encrypt(key, plaintext.as_bytes())?;
    bc_serialize(&encrypted).map_err(|e| VaultError::EncryptionFailed(e.to_string()))
}

#[cfg(test)]
#[path = "csv_import_tests.rs"]
mod tests;
