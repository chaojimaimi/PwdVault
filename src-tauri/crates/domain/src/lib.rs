//! PwdVault domain layer (§5.6.3).
//!
//! Pure business model with zero dependencies on Tauri, redb, or crypto
//! implementations. Contains entities, request/response DTOs, the validation
//! policy, stable error codes, and shared constants.
//!
//! `domain` is the innermost layer: `application` and `infrastructure` depend
//! on it, never the reverse.

pub mod constants;
pub mod dto;
pub mod entities;
pub mod error;
pub mod validation;

pub use constants::*;
pub use dto::*;
pub use entities::*;
pub use error::DomainError;
pub use validation::ValidationPolicy;
