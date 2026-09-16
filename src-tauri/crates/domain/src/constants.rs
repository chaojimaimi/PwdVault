//! Centralized constants shared across all PwdVault layers.
//!
//! Keeping these in the domain layer avoids drift between entry points and
//! makes future tuning a single-file change.

// ---------------------------------------------------------------------------
// Input length limits (enforced in the validation policy)
// ---------------------------------------------------------------------------

/// Maximum length for text fields such as title / username / url.
pub const MAX_FIELD_LENGTH: usize = 4096;

/// Maximum length for a password value.
pub const MAX_PASSWORD_LENGTH: usize = 1024;

/// Maximum length for the notes field.
pub const MAX_NOTES_LENGTH: usize = 65536;

/// Maximum length for a TOTP secret as stored/entered — either a plain base32
/// string (SHA-1 secrets are 32 chars, SHA-256 are 52) or a full `otpauth://`
/// URI, which runs a few hundred bytes.
pub const MAX_TOTP_SECRET_LENGTH: usize = 512;

/// Maximum HTTP request body size (10 MB).
pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Browser extension ↔ native host ↔ desktop protocol version.
///
/// Per §5.6.5, this is **independent of the product version** (the X.Y.Z in
/// Cargo.toml / package.json / manifests). The protocol version tracks the
/// wire format compatibility between the extension, the native host binary,
/// and the desktop HTTP API. It bumps only when the message contract changes
/// in a backwards-incompatible way.
pub const NATIVE_PROTOCOL_VERSION: u16 = 1;

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

// ---------------------------------------------------------------------------
// Baidu Netdisk sync (P3.4)
// ---------------------------------------------------------------------------

/// Baidu Netdisk OAuth AppKey — a COMPILE-TIME placeholder (plan P3.4/P3.8).
/// Ship the empty string; to enable the Baidu backend, fill in the AppKey
/// (and [`BAIDU_SECRET_KEY`]) from the open-platform application and rebuild
/// — see docs/BAIDU-SETUP.md. Empty → the adapter answers `NotConfigured`
/// and the frontend shows setup guidance.
pub const BAIDU_APP_KEY: &str = "";

/// Baidu Netdisk OAuth SecretKey — companion to [`BAIDU_APP_KEY`]. The plan
/// explicitly accepts embedding it (the binary offers no confidentiality on
/// the user's own machine; the container itself stays E2E encrypted).
pub const BAIDU_SECRET_KEY: &str = "";

/// Fixed loopback port of the OAuth callback listener. Deliberately distinct
/// from [`NATIVE_MESSAGING_PORT`] (17429); the open platform requires the
/// redirect_uri to match EXACTLY, port included — see docs/BAIDU-SETUP.md.
pub const BAIDU_OAUTH_PORT: u16 = 17777;

/// Redirect URI registered on the open platform (must equal the one sent in
/// the authorize/token requests byte-for-byte).
pub const BAIDU_REDIRECT_URI: &str = "http://127.0.0.1:17777/";
