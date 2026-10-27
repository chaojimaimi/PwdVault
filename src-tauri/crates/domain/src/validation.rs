//! Shared input validation policy for every adapter (§5.2.1).
//!
//! Returns [`crate::DomainError`] so the domain layer has no dependency on the
//! application-layer `VaultError`. The application layer adds a
//! `From<DomainError> for VaultError` so call sites can keep using `?`.

use std::collections::HashSet;

use crate::dto::{BackupPayload, CreateEntryRequest, UpdateEntryRequest};
use crate::entities::Settings;
use crate::error::DomainError;
use crate::{MAX_FIELD_LENGTH, MAX_NOTES_LENGTH, MAX_PASSWORD_LENGTH, MAX_TOTP_SECRET_LENGTH};

pub const MIN_MASTER_PASSWORD_CHARS: usize = 8;
pub const MAX_INPUT_PASSWORD_BYTES: usize = 1024;
pub const MAX_GROUP_NAME_BYTES: usize = 256;
pub const MAX_TAGS: usize = 64;
pub const MAX_TAG_BYTES: usize = 128;
/// Custom-field budget per entry (v1.6.0 WP1): bounded rows keep the entry
/// blob, the backup payload and the sync snapshot within sane sizes.
pub const MAX_CUSTOM_FIELDS: usize = 32;
pub const MAX_CUSTOM_LABEL_BYTES: usize = 256;
pub const MAX_ID_BYTES: usize = 128;
pub const MAX_BACKUP_ENTRIES: usize = 100_000;
pub const MAX_BACKUP_GROUPS: usize = 10_000;
pub const MAX_BACKUP_DECODED_BYTES: usize = 10 * 1024 * 1024;
/// Storage cap for the global-shortcut accelerator string (v1.4.0).
pub const MAX_GLOBAL_SHORTCUT_BYTES: usize = 128;

/// Public facade re-exported by the crate so call sites can write
/// `pwdvault_domain::ValidationPolicy::master_password(...)`.
pub struct ValidationPolicy;

fn invalid(code: &str, message: &str) -> DomainError {
    DomainError::new(code, message)
}

pub fn master_password(password: &str) -> Result<(), DomainError> {
    if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(invalid(
            "PASSWORD_TOO_SHORT",
            "Password must contain at least 8 characters",
        ));
    }
    password_size(password)
}

pub fn export_password(password: &str) -> Result<(), DomainError> {
    master_password(password)
}

pub fn import_password(password: &str) -> Result<(), DomainError> {
    if password.is_empty() {
        return Err(invalid("PASSWORD_EMPTY", "Password must not be empty"));
    }
    password_size(password)
}

/// Canonicalize an optional URL at every persistence and backup boundary.
/// Historical releases stored an unfilled URL as `Some("")`; semantically
/// that is the same as no URL and must not make the whole vault unexportable.
pub fn normalize_url(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn password_size(password: &str) -> Result<(), DomainError> {
    if password.len() > MAX_INPUT_PASSWORD_BYTES {
        return Err(invalid("PASSWORD_TOO_LONG", "Password is too long"));
    }
    Ok(())
}

pub fn entry(request: &CreateEntryRequest) -> Result<(), DomainError> {
    entry_fields(
        &request.title,
        request.url.as_deref(),
        &request.username,
        Some(request.password.as_str()),
        request.notes.as_deref(),
        &request.tags,
        request.group_id.as_deref(),
        request
            .custom_fields
            .iter()
            .map(|field| (field.label.as_str(), field.value.as_str()))
            .collect(),
    )
}

pub fn entry_update(request: &UpdateEntryRequest) -> Result<(), DomainError> {
    // TOTP tri-state: empty string = clear, otherwise length-bound. The value
    // may be a plain base32 secret or a whole `otpauth://` URI (P2.4).
    if let Some(totp) = &request.totp_secret {
        if totp.len() > MAX_TOTP_SECRET_LENGTH {
            return Err(invalid("TOTP_SECRET_TOO_LONG", "TOTP secret is too long"));
        }
    }
    // Custom fields tri-state batch: `None` leaves the stored fields untouched
    // (nothing new to validate), `Some(list)` replaces wholesale and validates
    // in full.
    let custom_fields: Vec<(&str, &str)> = request
        .custom_fields
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|field| (field.label.as_str(), field.value.as_str()))
        .collect();
    entry_fields(
        &request.title,
        request.url.as_deref(),
        &request.username,
        request.password.as_deref().map(String::as_str),
        if request.update_notes {
            request.notes.as_deref()
        } else {
            None
        },
        &request.tags,
        request.group_id.as_deref(),
        custom_fields,
    )
}

/// Custom fields validated at the PLAINTEXT layer only (D2): the ciphertext
/// size is an implementation detail of the sealing point, never a validation
/// concern. `(label, plaintext value)` pairs keep the check shareable between
/// the create/update inputs and the backup payload shape.
fn validate_custom_field_pairs(pairs: &[(&str, &str)]) -> Result<(), DomainError> {
    if pairs.len() > MAX_CUSTOM_FIELDS {
        return Err(invalid("TOO_MANY_CUSTOM_FIELDS", "Too many custom fields"));
    }
    // Duplicate rejection follows the tags convention: trim + case-fold, so
    // "API Key" and "api key " cannot coexist on one entry.
    let mut seen = HashSet::new();
    for (label, value) in pairs {
        let normalized = label.trim();
        if normalized.is_empty() || normalized.len() > MAX_CUSTOM_LABEL_BYTES {
            return Err(invalid(
                "INVALID_CUSTOM_FIELD_LABEL",
                "Custom field label is empty or too long",
            ));
        }
        if !seen.insert(normalized.to_lowercase()) {
            return Err(invalid(
                "DUPLICATE_CUSTOM_FIELD_LABEL",
                "Duplicate custom field label",
            ));
        }
        // Empty values are legal (placeholder row); anything over the shared
        // field cap is not.
        if value.len() > MAX_FIELD_LENGTH {
            return Err(invalid(
                "CUSTOM_FIELD_VALUE_TOO_LONG",
                "Custom field value is too long",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn entry_fields(
    title: &str,
    url: Option<&str>,
    username: &str,
    password: Option<&str>,
    notes: Option<&str>,
    tag_values: &[String],
    group_id: Option<&str>,
    custom_field_pairs: Vec<(&str, &str)>,
) -> Result<(), DomainError> {
    if title.trim().is_empty() || title.len() > MAX_FIELD_LENGTH {
        return Err(invalid("INVALID_TITLE", "Title is empty or too long"));
    }
    if username.trim().is_empty() || username.len() > MAX_FIELD_LENGTH {
        return Err(invalid("INVALID_USERNAME", "Username is empty or too long"));
    }
    if password.is_some_and(|value| value.is_empty() || value.len() > MAX_PASSWORD_LENGTH) {
        return Err(invalid(
            "INVALID_ENTRY_PASSWORD",
            "Entry password is empty or too long",
        ));
    }
    if url.is_some_and(|value| {
        let trimmed = value.trim();
        !trimmed.is_empty() && trimmed.len() > MAX_FIELD_LENGTH
    }) {
        return Err(invalid("INVALID_URL", "URL is too long"));
    }
    if notes.is_some_and(|value| value.len() > MAX_NOTES_LENGTH) {
        return Err(invalid("NOTES_TOO_LONG", "Notes are too long"));
    }
    tags(tag_values)?;
    validate_custom_field_pairs(&custom_field_pairs)?;
    if let Some(group_id) = group_id {
        id(group_id)?;
    }
    Ok(())
}

pub fn group_name(name: &str) -> Result<String, DomainError> {
    let normalized = name.trim();
    if normalized.is_empty() || normalized.len() > MAX_GROUP_NAME_BYTES {
        return Err(invalid(
            "INVALID_GROUP_NAME",
            "Group name is empty or too long",
        ));
    }
    Ok(normalized.to_string())
}

pub fn id(value: &str) -> Result<(), DomainError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES {
        return Err(invalid("INVALID_ID", "Identifier is empty or too long"));
    }
    Ok(())
}

pub fn tags(values: &[String]) -> Result<(), DomainError> {
    if values.len() > MAX_TAGS {
        return Err(invalid("TOO_MANY_TAGS", "Too many tags"));
    }
    let mut seen = HashSet::new();
    for value in values {
        let normalized = value.trim();
        if normalized.is_empty() || normalized.len() > MAX_TAG_BYTES {
            return Err(invalid("INVALID_TAG", "Tag is empty or too long"));
        }
        if !seen.insert(normalized.to_lowercase()) {
            return Err(invalid("DUPLICATE_TAG", "Duplicate tag"));
        }
    }
    Ok(())
}

pub fn settings(value: &Settings) -> Result<(), DomainError> {
    if !(30..=3600).contains(&value.auto_lock_secs) {
        return Err(invalid(
            "INVALID_AUTO_LOCK",
            "Auto-lock must be between 30 and 3600 seconds",
        ));
    }
    if !(8..=128).contains(&value.default_length) {
        return Err(invalid(
            "INVALID_GENERATOR_LENGTH",
            "Generator length must be between 8 and 128",
        ));
    }
    generator(
        value.default_length,
        value.default_include_uppercase,
        value.default_include_lowercase,
        value.default_include_numbers,
        value.default_include_symbols,
    )?;
    // v1.4.0 global shortcut: an enabled shortcut needs an accelerator
    // string (syntax itself is validated by the plugin's parser at
    // registration time — see the tauri-app shortcuts module); the length
    // cap only bounds storage. Disabled shortcuts may keep their string so
    // re-enabling restores the last binding.
    if value.global_shortcut.len() > MAX_GLOBAL_SHORTCUT_BYTES {
        return Err(invalid(
            "INVALID_GLOBAL_SHORTCUT",
            "Global shortcut is too long",
        ));
    }
    if value.global_shortcut_enabled && value.global_shortcut.trim().is_empty() {
        return Err(invalid(
            "INVALID_GLOBAL_SHORTCUT",
            "Enabled global shortcut needs an accelerator string",
        ));
    }
    Ok(())
}

pub fn generator(
    length: usize,
    upper: bool,
    lower: bool,
    numbers: bool,
    symbols: bool,
) -> Result<(), DomainError> {
    if !(4..=128).contains(&length) {
        return Err(invalid(
            "INVALID_GENERATOR_LENGTH",
            "Generator length must be between 4 and 128",
        ));
    }
    let selected = [upper, lower, numbers, symbols]
        .into_iter()
        .filter(|v| *v)
        .count();
    if selected == 0 || length < selected {
        return Err(invalid(
            "INVALID_GENERATOR_CHARSETS",
            "Select at least one character type and allow one character per selected type",
        ));
    }
    Ok(())
}

/// Passphrase parameters (v1.4.0): 3-10 words over the EFF short list
/// (3 words ≈ 31 bits is the practical floor; 10 ≈ 103 bits), separator
/// capped so a hostile client cannot smuggle megabytes through it.
pub fn passphrase(words: u8, separator: &str) -> Result<(), DomainError> {
    if !(3..=10).contains(&words) {
        return Err(invalid(
            "INVALID_GENERATOR_WORDS",
            "Passphrase word count must be between 3 and 10",
        ));
    }
    if separator.len() > 4 || !separator.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(invalid(
            "INVALID_GENERATOR_SEPARATOR",
            "Passphrase separator must be at most 4 printable ASCII characters",
        ));
    }
    Ok(())
}

/// PIN parameters (v1.4.0): 4-16 digits.
pub fn pin(len: u8) -> Result<(), DomainError> {
    if !(4..=16).contains(&len) {
        return Err(invalid(
            "INVALID_GENERATOR_PIN",
            "PIN length must be between 4 and 16",
        ));
    }
    Ok(())
}

pub fn backup_payload(payload: &BackupPayload) -> Result<(), DomainError> {
    if payload.entries.len() > MAX_BACKUP_ENTRIES || payload.groups.len() > MAX_BACKUP_GROUPS {
        return Err(invalid(
            "BACKUP_LIMIT_EXCEEDED",
            "Backup contains too many records",
        ));
    }
    settings(&payload.settings)?;
    let group_ids: HashSet<&str> = payload
        .groups
        .iter()
        .map(|group| group.id.as_str())
        .collect();
    if group_ids.len() != payload.groups.len() {
        return Err(invalid(
            "DUPLICATE_GROUP_ID",
            "Backup contains duplicate group identifiers",
        ));
    }
    let mut group_names = HashSet::new();
    for group in &payload.groups {
        // Symmetric live-only invariant (v1.6.2): export filters tombstoned
        // groups out (backup.rs), so import must REJECT them. The previous
        // re-id path sanitized `deleted_at` away through `Group::new`, which
        // let a hand-edited payload bury a deletion into the vault and spread
        // it to every peer on the next sync. Backwards compatible by
        // construction: legitimate exports never carry tombstones, and
        // pre-v1.1.6 backups deserialize with `deleted_at: None` (serde
        // default).
        if group.deleted_at.is_some() {
            return Err(invalid(
                "TOMBSTONED_GROUP_IN_BACKUP",
                "Backup contains a deleted (tombstoned) group",
            ));
        }
        id(&group.id)?;
        let name = group_name(&group.name)?;
        if !group_names.insert(name.to_lowercase()) {
            return Err(invalid(
                "DUPLICATE_GROUP_NAME",
                "Backup contains duplicate group names",
            ));
        }
    }
    let mut entry_ids = HashSet::new();
    for entry in &payload.entries {
        id(&entry.id)?;
        if !entry_ids.insert(entry.id.as_str()) {
            return Err(invalid(
                "DUPLICATE_ENTRY_ID",
                "Backup contains duplicate entry identifiers",
            ));
        }
        // New entries require a non-empty password, but historical databases
        // can contain username-only records. Preserve those records across a
        // backup round trip while applying every other field/size boundary.
        entry_fields(
            &entry.title,
            entry.url.as_deref(),
            &entry.username,
            (!entry.password.is_empty()).then_some(entry.password.as_str()),
            entry.notes.as_deref().map(String::as_str),
            &entry.tags,
            entry.group_id.as_deref(),
            // v1.6.0: backup entries carry their custom fields through the
            // same plaintext-layer rules as the live CRUD paths.
            entry
                .custom_fields
                .iter()
                .map(|field| (field.label.as_str(), field.value.as_str()))
                .collect(),
        )?;
        if entry
            .group_id
            .as_deref()
            .is_some_and(|group_id| !group_ids.contains(group_id))
        {
            return Err(invalid(
                "UNKNOWN_GROUP",
                "Backup entry references an unknown group",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    use crate::dto::{CustomFieldInput, ExportEntry};

    #[test]
    fn rejects_short_master_password() {
        assert!(master_password("short").is_err());
        assert!(master_password("long-enough").is_ok());
    }

    #[test]
    fn rejects_invalid_generator_configuration() {
        assert!(generator(16, false, false, false, false).is_err());
        assert!(generator(2, true, true, true, false).is_err());
    }

    #[test]
    fn validation_errors_expose_stable_codes() {
        let error = master_password("short").unwrap_err();
        assert!(error.to_string().starts_with("PASSWORD_TOO_SHORT:"));
    }

    #[test]
    fn optional_url_normalization_preserves_legacy_empty_values_as_absent() {
        assert_eq!(normalize_url(None), None);
        assert_eq!(normalize_url(Some(String::new())), None);
        assert_eq!(normalize_url(Some("   ".to_string())), None);
        assert_eq!(
            normalize_url(Some("  https://example.com/login  ".to_string())),
            Some("https://example.com/login".to_string())
        );
    }

    // -----------------------------------------------------------------
    // v1.6.0 WP1: custom-field validation boundaries (plaintext layer)
    // -----------------------------------------------------------------

    fn field(label: &str, value: &str) -> CustomFieldInput {
        CustomFieldInput {
            label: label.to_string(),
            value: value.to_string(),
            secret: false,
        }
    }

    fn create_request(fields: Vec<CustomFieldInput>) -> CreateEntryRequest {
        CreateEntryRequest {
            title: "Title".to_string(),
            url: None,
            username: "user".to_string(),
            password: Zeroizing::new("password-value".to_string()),
            notes: None,
            tags: vec![],
            group_id: None,
            url_match_mode: crate::UrlMatchMode::Auto,
            custom_fields: fields,
        }
    }

    #[test]
    fn custom_fields_accept_valid_rows_including_empty_values() {
        let request = create_request(vec![
            field("API Key", "key-value"),
            field("Placeholder", ""), // empty value is the legal placeholder
        ]);
        assert!(entry(&request).is_ok());
    }

    #[test]
    fn custom_fields_reject_count_over_cap() {
        let fields: Vec<CustomFieldInput> = (0..=MAX_CUSTOM_FIELDS)
            .map(|i| field(&format!("field-{i}"), "v"))
            .collect();
        let error = entry(&create_request(fields)).unwrap_err();
        assert_eq!(error.code, "TOO_MANY_CUSTOM_FIELDS");
    }

    #[test]
    fn custom_fields_reject_empty_or_oversized_labels() {
        let empty = entry(&create_request(vec![field("   ", "v")])).unwrap_err();
        assert_eq!(empty.code, "INVALID_CUSTOM_FIELD_LABEL");

        let oversized = entry(&create_request(vec![field(
            &"x".repeat(MAX_CUSTOM_LABEL_BYTES + 1),
            "v",
        )]))
        .unwrap_err();
        assert_eq!(oversized.code, "INVALID_CUSTOM_FIELD_LABEL");
    }

    #[test]
    fn custom_fields_reject_duplicate_labels_case_insensitively() {
        let dup = create_request(vec![field("API Key", "a"), field("api key", "b")]);
        let error = entry(&dup).unwrap_err();
        assert_eq!(error.code, "DUPLICATE_CUSTOM_FIELD_LABEL");
    }

    #[test]
    fn custom_fields_reject_values_over_the_field_cap() {
        let oversized = create_request(vec![field("Notes-ish", &"x".repeat(MAX_FIELD_LENGTH + 1))]);
        let error = entry(&oversized).unwrap_err();
        assert_eq!(error.code, "CUSTOM_FIELD_VALUE_TOO_LONG");
    }

    #[test]
    fn entry_update_validates_custom_fields_only_when_present() {
        // None = leave unchanged: nothing to validate, so an otherwise valid
        // patch must not fail on custom fields.
        let untouched = UpdateEntryRequest {
            title: "Patched".to_string(),
            url: None,
            username: "user".to_string(),
            password: None,
            notes: None,
            update_notes: false,
            tags: vec![],
            group_id: None,
            totp_secret: None,
            url_match_mode: crate::UrlMatchMode::Auto,
            custom_fields: None,
        };
        assert!(entry_update(&untouched).is_ok());

        let replaced = UpdateEntryRequest {
            custom_fields: Some(vec![field("dup", "a"), field("dup", "b")]),
            ..untouched
        };
        let error = entry_update(&replaced).unwrap_err();
        assert_eq!(error.code, "DUPLICATE_CUSTOM_FIELD_LABEL");
    }

    #[test]
    fn backup_payload_validates_entry_custom_fields() {
        let oversized = BackupPayload {
            entries: vec![ExportEntry {
                id: "entry-1".to_string(),
                title: "Title".to_string(),
                url: None,
                username: "user".to_string(),
                password: Zeroizing::new("pw".to_string()),
                notes: None,
                tags: vec![],
                group_id: None,
                created_at: 0,
                updated_at: 0,
                url_match_mode: crate::UrlMatchMode::Auto,
                totp_secret: None,
                custom_fields: vec![crate::ExportCustomField {
                    label: "big".to_string(),
                    value: Zeroizing::new("x".repeat(MAX_FIELD_LENGTH + 1)),
                    secret: false,
                }],
            }],
            groups: vec![],
            settings: Settings::default(),
        };
        let error = backup_payload(&oversized).unwrap_err();
        assert_eq!(error.code, "CUSTOM_FIELD_VALUE_TOO_LONG");
    }
}
