//! Centralized constants shared across Tauri commands and the HTTP API.
//!
//! Keeping these in one place avoids drift between the two entry points and
//! makes future tuning a single-file change.

// ---------------------------------------------------------------------------
// Input length limits (enforced in both service layer and HTTP handler)
// ---------------------------------------------------------------------------

/// Maximum length for text fields such as title / username / url.
pub const MAX_FIELD_LENGTH: usize = 4096;

/// Maximum length for a password value.
pub const MAX_PASSWORD_LENGTH: usize = 1024;

/// Maximum length for the notes field.
pub const MAX_NOTES_LENGTH: usize = 65536;

/// Maximum HTTP request body size (10 MB).
pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Auto-lock
// ---------------------------------------------------------------------------

/// Default auto-lock timeout in seconds (10 minutes).
pub const AUTO_LOCK_SECS: u64 = 600;

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// Consecutive failed unlock attempts before lockout.
pub const MAX_FAILED_ATTEMPTS: u32 = 5;

/// Lockout duration in seconds after max failed attempts.
#[cfg(not(test))]
pub const LOCKOUT_DURATION_SECS: u64 = 60;
#[cfg(test)]
pub const LOCKOUT_DURATION_SECS: u64 = 1;

/// Maximum pair requests per minute from the browser extension.
pub const MAX_PAIR_REQUESTS_PER_MIN: u32 = 10;

// ---------------------------------------------------------------------------
// Native messaging
// ---------------------------------------------------------------------------

/// TCP port the embedded HTTP server listens on.
pub const NATIVE_MESSAGING_PORT: u16 = 17429;
