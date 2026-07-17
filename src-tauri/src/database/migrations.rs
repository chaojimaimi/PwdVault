//! Explicit vault-format migration registry.

use crate::VaultError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStep {
    LegacyToV1,
}

pub fn plan(from: u32, to: u32) -> Result<Vec<MigrationStep>, VaultError> {
    match (from, to) {
        (version, target) if version == target => Ok(Vec::new()),
        (0, 1) => Ok(vec![MigrationStep::LegacyToV1]),
        _ => Err(VaultError::InvalidBackup(format!(
            "No migration path from vault format {from} to {to}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_rejects_unknown_future_or_skipped_versions() {
        assert_eq!(plan(0, 1).unwrap(), vec![MigrationStep::LegacyToV1]);
        assert!(plan(1, 2).is_err());
        assert!(plan(2, 1).is_err());
    }
}
