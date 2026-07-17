//! Shared input validation policy for every adapter (§5.2.1).
//!
//! Returns [`crate::DomainError`] so the domain layer has no dependency on the
//! application-layer `VaultError`. The application layer adds a
//! `From<DomainError> for VaultError` so call sites can keep using `?`.

use std::collections::HashSet;

use crate::dto::{BackupPayload, CreateEntryRequest, UpdateEntryRequest};
use crate::entities::Settings;
use crate::error::DomainError;
use crate::{MAX_FIELD_LENGTH, MAX_NOTES_LENGTH, MAX_PASSWORD_LENGTH};

pub const MIN_MASTER_PASSWORD_CHARS: usize = 8;
pub const MAX_INPUT_PASSWORD_BYTES: usize = 1024;
pub const MAX_GROUP_NAME_BYTES: usize = 256;
pub const MAX_TAGS: usize = 64;
pub const MAX_TAG_BYTES: usize = 128;
pub const MAX_ID_BYTES: usize = 128;
pub const MAX_BACKUP_ENTRIES: usize = 100_000;
pub const MAX_BACKUP_GROUPS: usize = 10_000;
pub const MAX_BACKUP_DECODED_BYTES: usize = 10 * 1024 * 1024;

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
    )
}

pub fn entry_update(request: &UpdateEntryRequest) -> Result<(), DomainError> {
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
    )
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
) -> Result<(), DomainError> {
    if title.trim().is_empty() || title.len() > MAX_FIELD_LENGTH {
        return Err(invalid("INVALID_TITLE", "Title is empty or too long"));
    }
    if username.trim().is_empty() || username.len() > MAX_FIELD_LENGTH {
        return Err(invalid("INVALID_USERNAME", "Username is empty or too long"));
    }
    if password.is_some_and(|value| {
        value.is_empty() || value.len() > MAX_PASSWORD_LENGTH
    }) {
        return Err(invalid(
            "INVALID_ENTRY_PASSWORD",
            "Entry password is empty or too long",
        ));
    }
    if url.is_some_and(|value| {
        value.trim().is_empty() || value.len() > MAX_FIELD_LENGTH
    }) {
        return Err(invalid("INVALID_URL", "URL is empty or too long"));
    }
    if notes.is_some_and(|value| value.len() > MAX_NOTES_LENGTH) {
        return Err(invalid("NOTES_TOO_LONG", "Notes are too long"));
    }
    tags(tag_values)?;
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
    )
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
        let request = CreateEntryRequest {
            title: entry.title.clone(),
            url: entry.url.clone(),
            username: entry.username.clone(),
            password: entry.password.clone(),
            notes: entry.notes.as_ref().map(|value| value.to_string()),
            tags: entry.tags.clone(),
            group_id: entry.group_id.clone(),
        };
        self::entry(&request)?;
        if request
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
}
