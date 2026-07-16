//! API Token Authentication
//!
//! Provides Bearer token authentication for the HTTP API.
//! Token is stored in memory only and regenerated on each application start.

use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Token length in bytes (32 bytes = 64 hex chars)
const TOKEN_BYTES: usize = 32;

/// In-memory token storage (regenerated on each app start)
static API_TOKEN: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(generate_token()));

/// Generate a cryptographically random hex token
fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(&bytes)
}

/// Get the current API token. The token is generated once per application session
/// and stored in memory. It is never written to disk.
pub fn get_token() -> String {
    let guard = API_TOKEN.lock().expect("token lock poisoned");
    guard.clone()
}

/// Regenerate the API token. This invalidates all existing browser extensions
/// and requires them to re-pair. Call this when the user wants to revoke extension access.
pub fn regenerate_token() -> String {
    let mut guard = API_TOKEN.lock().expect("token lock poisoned");
    let new_token = generate_token();
    *guard = new_token.clone();
    new_token
}

/// Validate a Bearer token from the Authorization header.
/// Returns true if the token matches the current in-memory token.
pub fn validate_token(auth_header: &str) -> bool {
    let current = API_TOKEN.lock().expect("token lock poisoned");
    let expected = current.trim();

    // Parse "Bearer <token>"
    if let Some(provided) = auth_header.strip_prefix("Bearer ") {
        subtle::ConstantTimeEq::ct_eq(provided.trim().as_bytes(), expected.as_bytes()).into()
    } else {
        false
    }
}

/// Check if the Origin header indicates a browser extension
pub fn is_extension_origin(origin: Option<&str>) -> bool {
    match origin {
        Some(o) => o.starts_with("chrome-extension://") || o.starts_with("moz-extension://"),
        None => false,
    }
}

// hex encoding without adding a dependency
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_length() {
        let token = generate_token();
        // 32 bytes = 64 hex chars
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn test_generate_token_hex() {
        let token = generate_token();
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_is_extension_origin() {
        assert!(is_extension_origin(Some("chrome-extension://abc123")));
        assert!(is_extension_origin(Some("moz-extension://xyz789")));
        assert!(!is_extension_origin(Some("http://localhost:3000")));
        assert!(!is_extension_origin(None));
    }

    #[test]
    fn test_token_consistency_and_lifecycle() {
        // All stateful token tests are combined to avoid races on the global
        // in-memory token when tests run in parallel.
        let t1 = get_token();
        let t2 = get_token();
        assert_eq!(t1, t2, "token should be consistent within a session");

        let t3 = regenerate_token();
        assert_ne!(t1, t3, "regenerated token should be different");
        assert_eq!(
            t3,
            get_token(),
            "after regeneration, get_token should return new token"
        );
        assert!(validate_token(&format!("Bearer {}", t3)));
    }

    #[test]
    fn test_validate_token_failure() {
        assert!(!validate_token("Bearer wrongtoken"));
        assert!(!validate_token("invalid"));
    }
}
