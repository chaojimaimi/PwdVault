//! Domain-layer errors.
//!
//! The domain layer keeps a narrow error type for validation and policy
//! failures. The broader `VaultError` (which aggregates crypto/database
//! errors) lives in the application layer; this `DomainError` is what the
//! validation policy returns, and the application layer maps it into
//! `VaultError::InvalidInput` at the boundary.

use serde::{Deserialize, Serialize};

/// Stable error code returned to adapters when validation fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainError {
    pub code: String,
    pub message: String,
}

impl DomainError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for DomainError {}
