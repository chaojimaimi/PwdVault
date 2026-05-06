//! API Token Authentication
//!
//! Provides Bearer token authentication for the HTTP API.
//! Token is stored in a file with restricted permissions (0o600).

use std::io::Write;
use std::path::PathBuf;

/// Token length in bytes (32 bytes = 64 hex chars)
const TOKEN_BYTES: usize = 32;

/// Get the API token file path
fn token_path() -> PathBuf {
    let base = {
        #[cfg(target_os = "macos")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join("com.pwdvault.app")
        }
        #[cfg(target_os = "windows")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join("PwdVault")
        }
        #[cfg(target_os = "linux")]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join("pwdvault")
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            std::env::current_dir().unwrap()
        }
    };
    base.join("api_token")
}

/// Generate a cryptographically random hex token
fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(&bytes)
}

/// Get or create the API token. Returns the token as a string.
pub fn get_or_create_token() -> Result<String, String> {
    let path = token_path();

    // Try to read existing token
    if path.exists() {
        let token = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read token: {}", e))?;
        let trimmed = token.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    // Generate new token
    let token = generate_token();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create token dir: {}", e))?;
    }

    // Write token with restricted permissions
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| format!("Failed to create token file: {}", e))?;
            file.write_all(token.as_bytes())
                .map_err(|e| format!("Failed to write token: {}", e))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&path, &token)
                .map_err(|e| format!("Failed to write token: {}", e))?;
        }
    }

    Ok(token)
}

/// Validate a Bearer token from the Authorization header.
/// Returns true if the token matches the stored token.
pub fn validate_token(auth_header: &str) -> bool {
    let expected = match get_or_create_token() {
        Ok(t) => t,
        Err(_) => return false,
    };

    // Parse "Bearer <token>"
    if let Some(provided) = auth_header.strip_prefix("Bearer ") {
        subtle::ConstantTimeEq::ct_eq(
            provided.trim().as_bytes(),
            expected.as_bytes(),
        ).into()
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
}
