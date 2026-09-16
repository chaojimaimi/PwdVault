//! TOTP code generation for entries (P2.4).
//!
//! Tauri-only (D6, `touch_activity` precedent): the browser-extension bridge
//! does not expose TOTP codes. The stored secret is AES-GCM ciphertext; the
//! plaintext value may be a plain base32 secret or a whole `otpauth://` URI —
//! both parse here so the frontend can persist either form.

use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use crate::service::vault::get_db;
use crate::{validation, AppState, TotpCodeResponse, VaultError};
use pwdvault_infrastructure::crypto::{decrypt, EncryptedData};
use pwdvault_infrastructure::database::load_entry;
use pwdvault_infrastructure::totp::{
    base32_decode, parse_otpauth_uri, totp_code as generate_code, TotpAlgorithm, DEFAULT_DIGITS,
    DEFAULT_PERIOD,
};

fn invalid_totp(message: &'static str) -> VaultError {
    VaultError::InvalidInput {
        code: "INVALID_TOTP_SECRET".into(),
        message: message.into(),
    }
}

/// Normalize a stored TOTP secret into (bytes, algorithm, digits, period).
/// `otpauth://` URIs carry their own parameters; plain base32 uses the
/// standard defaults (SHA1 / 6 digits / 30 s).
fn normalize_secret(text: &str) -> Result<(Vec<u8>, TotpAlgorithm, u8, u32), VaultError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(invalid_totp("TOTP secret is empty"));
    }
    if trimmed.starts_with("otpauth://") {
        let params = parse_otpauth_uri(trimmed)
            .map_err(|_| invalid_totp("TOTP secret is a malformed otpauth:// URI"))?;
        Ok((params.secret, params.algo, params.digits, params.period))
    } else {
        let secret = base32_decode(trimmed)
            .map_err(|_| invalid_totp("TOTP secret is neither base32 nor an otpauth:// URI"))?;
        if secret.is_empty() {
            return Err(invalid_totp("TOTP secret decodes to zero bytes"));
        }
        Ok((secret, TotpAlgorithm::Sha1, DEFAULT_DIGITS, DEFAULT_PERIOD))
    }
}

/// Generate the current TOTP code for an entry.
///
/// Tombstoned entries and entries without a configured secret fail closed
/// (`EntryNotFound` / `INVALID_TOTP_SECRET` respectively).
pub fn totp_code(state: &Arc<AppState>, id: String) -> Result<TotpCodeResponse, VaultError> {
    validation::id(&id)?;
    let lease = state.lease()?;
    let db = get_db(state)?;
    let key = lease.enc_key()?;
    let entry = load_entry(&db, key, &id, false)?.ok_or(VaultError::EntryNotFound)?;
    if entry.deleted_at.is_some() {
        return Err(VaultError::EntryNotFound);
    }

    let sealed_bytes = entry
        .encrypted_totp_secret
        .as_ref()
        .ok_or(VaultError::InvalidInput {
            code: "TOTP_NOT_CONFIGURED".into(),
            message: "Entry has no TOTP secret".into(),
        })?;

    // Same resilient shape as the password/notes reads: bincode(EncryptedData)
    // first, raw nonce||ciphertext fallback for historical layouts.
    let encrypted: EncryptedData = bincode::deserialize(sealed_bytes).or_else(|e| {
        EncryptedData::from_bytes(sealed_bytes)
            .map_err(|e2| VaultError::DecryptionFailed(format!("bincode: {} / raw: {}", e, e2)))
    })?;
    let mut secret_bytes = decrypt(key, &encrypted)?;
    let secret_text = Zeroizing::new(
        String::from_utf8(secret_bytes.clone())
            .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?,
    );
    secret_bytes.zeroize();

    let (secret, algo, digits, period) = normalize_secret(secret_text.as_str())?;

    let now = chrono::Utc::now().timestamp();
    let code = generate_code(&secret, algo, digits, period, now);
    let seconds_remaining = i64::from(period) - now.rem_euclid(i64::from(period));

    lease.touch_activity();

    Ok(TotpCodeResponse {
        code,
        seconds_remaining,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plain base32 with default parameters.
    #[test]
    fn normalize_plain_base32_secret() {
        let (secret, algo, digits, period) =
            normalize_secret("  mzxw6ytb \n").expect("plain base32 accepted");
        assert_eq!(secret, b"fooba");
        assert_eq!(algo, TotpAlgorithm::Sha1);
        assert_eq!(digits, DEFAULT_DIGITS);
        assert_eq!(period, DEFAULT_PERIOD);
    }

    /// A full otpauth:// URI supplies its own parameters.
    #[test]
    fn normalize_otpauth_uri_secret() {
        let (secret, algo, digits, period) = normalize_secret(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(secret, b"Hello!\xDE\xAD\xBE\xEF");
        assert_eq!(algo, TotpAlgorithm::Sha256);
        assert_eq!(digits, 8);
        assert_eq!(period, 60);
    }

    #[test]
    fn normalize_rejects_garbage() {
        assert!(normalize_secret("").is_err());
        assert!(normalize_secret("   ").is_err());
        assert!(normalize_secret("not!base32").is_err());
        assert!(normalize_secret("otpauth://hotp/x?secret=MZXW6YTB").is_err());
    }
}
