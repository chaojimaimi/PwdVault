//! RFC 6238 TOTP code generation and `otpauth://` URI parsing.
//!
//! Supports HMAC-SHA1 (the de-facto default every authenticator app speaks)
//! and HMAC-SHA256, with configurable digits and period; the PwdVault default
//! is the standard 6 digits / 30 seconds. Base32 (RFC 4648) decoding is
//! implemented here (~30 lines) instead of pulling in another dependency, with
//! padding/whitespace/case tolerance so real-world authenticator secrets parse
//! as-is.

use thiserror::Error;

use sha1::Sha1;
use sha2::Sha256;

use hmac::{Hmac, Mac};

/// Default digits per the TOTP standard (RFC 6238 §5.2 recommends 6).
pub const DEFAULT_DIGITS: u8 = 6;
/// Default time step in seconds (RFC 6238 §5.2 recommends 30).
pub const DEFAULT_PERIOD: u32 = 30;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Hash algorithm used for the HMAC in a TOTP scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
}

impl TotpAlgorithm {
    /// Parse the `algorithm` query parameter of an `otpauth://` URI
    /// (case-insensitive; absent means SHA1 per the key URI format).
    fn from_param(value: &str) -> Result<Self, TotpError> {
        match value.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(TotpAlgorithm::Sha1),
            "SHA256" => Ok(TotpAlgorithm::Sha256),
            other => Err(TotpError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum TotpError {
    #[error("invalid otpauth URI: {0}")]
    InvalidUri(String),
    #[error("secret is not valid base32")]
    InvalidSecret,
    #[error("unsupported TOTP algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("invalid TOTP parameter: {0}")]
    InvalidParam(String),
}

/// Parsed `otpauth://totp/...` parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpauthParams {
    /// Label path segment (after the type), percent-decoded.
    pub label: String,
    /// Raw secret bytes (base32-decoded, percent-decoding applied first).
    pub secret: Vec<u8>,
    pub algo: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
}

// ---------------------------------------------------------------------------
// Base32 (RFC 4648)
// ---------------------------------------------------------------------------

/// Decode standard base32. Tolerates `=` padding, whitespace, and lowercase
/// input; leftover bits (< 5) are zero-padded per the canonical rules.
pub fn base32_decode(input: &str) -> Result<Vec<u8>, TotpError> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    for ch in input.chars() {
        if ch == '=' || ch.is_whitespace() {
            continue;
        }
        let value = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32,
            '2'..='7' => ch as u32 - '2' as u32 + 26,
            _ => return Err(TotpError::InvalidSecret),
        };
        accumulator = (accumulator << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Encode to canonical base32 without padding (authenticator-app style).
pub fn base32_encode(data: &[u8]) -> String {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    for &byte in data {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((accumulator >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// otpauth:// URI parsing
// ---------------------------------------------------------------------------

/// Percent-decode a URI component. Malformed escapes (`%` not followed by two
/// hex digits) are kept literally — the base32 validation downstream rejects
/// garbage secrets anyway.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(hex) = bytes.get(i + 1..i + 3) {
                if let (Some(hi), Some(lo)) = (hex_val(hex[0]), hex_val(hex[1])) {
                    out.push(hi * 16 + lo);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parse an `otpauth://totp/...` key URI (Google Authenticator key URI format).
///
/// - `secret` is required; percent-decoding is applied before base32 decode.
/// - `algorithm` defaults to SHA1; only SHA1/SHA256 are supported.
/// - `digits` defaults to 6 (1–10 accepted); `period` defaults to 30 (> 0).
pub fn parse_otpauth_uri(uri: &str) -> Result<OtpauthParams, TotpError> {
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| TotpError::InvalidUri("scheme must be otpauth://".to_string()))?;

    // Split off the query string first, then the type ("totp") from the
    // label path — handles both `totp/label?query` and `totp?query`.
    let (path, query) = match rest.split_once('?') {
        Some((path, query)) => (path, query),
        None => (rest, ""),
    };
    let (type_part, label) = match path.split_once('/') {
        Some((host, label)) => (host, label),
        None => (path, ""),
    };
    if !type_part.eq_ignore_ascii_case("totp") {
        return Err(TotpError::InvalidUri(format!(
            "unsupported otpauth type '{}'",
            type_part
        )));
    }

    let mut secret: Option<Vec<u8>> = None;
    let mut algo = TotpAlgorithm::Sha1;
    let mut digits = DEFAULT_DIGITS;
    let mut period = DEFAULT_PERIOD;

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| TotpError::InvalidUri(format!("malformed parameter '{}'", pair)))?;
        match key.to_ascii_lowercase().as_str() {
            "secret" => {
                let decoded = percent_decode(value);
                secret = Some(base32_decode(&decoded)?);
            }
            "algorithm" => algo = TotpAlgorithm::from_param(value)?,
            "digits" => {
                digits = value.parse().map_err(|_| {
                    TotpError::InvalidParam(format!("digits '{}' is not a number", value))
                })?;
                if !(1..=10).contains(&digits) {
                    return Err(TotpError::InvalidParam(format!(
                        "digits {} out of range 1..=10",
                        digits
                    )));
                }
            }
            "period" => {
                period = value.parse().map_err(|_| {
                    TotpError::InvalidParam(format!("period '{}' is not a number", value))
                })?;
                if period == 0 {
                    return Err(TotpError::InvalidParam(
                        "period must be positive".to_string(),
                    ));
                }
            }
            // issuer/image/lock etc. are informational — ignore them.
            _ => {}
        }
    }

    let secret = secret.ok_or_else(|| TotpError::InvalidUri("secret is required".to_string()))?;
    if secret.is_empty() {
        return Err(TotpError::InvalidSecret);
    }

    Ok(OtpauthParams {
        label: percent_decode(label),
        secret,
        algo,
        digits,
        period,
    })
}

// ---------------------------------------------------------------------------
// RFC 4226 / RFC 6238 code generation
// ---------------------------------------------------------------------------

/// HMAC over the 8-byte big-endian counter with the configured algorithm.
fn hmac_counter(secret: &[u8], counter: u64, algo: TotpAlgorithm) -> Vec<u8> {
    let message = counter.to_be_bytes();
    match algo {
        TotpAlgorithm::Sha1 => {
            let mut mac =
                Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts keys of any length");
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts keys of any length");
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Generate the TOTP code for `secret` at Unix time `at` (RFC 6238 §5.2:
/// dynamic truncation per RFC 4226 §5.4). `at` is clamped to non-negative so
/// a bogus clock cannot produce a negative counter.
pub fn totp_code(secret: &[u8], algo: TotpAlgorithm, digits: u8, period: u32, at: i64) -> String {
    let period = u64::from(period.max(1));
    let counter = at.clamp(0, i64::MAX) as u64 / period;
    let digest = hmac_counter(secret, counter, algo);

    // Dynamic truncation: low 4 bits of the last byte pick the offset; take
    // 4 bytes there with the top bit masked, then reduce mod 10^digits.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let truncated = (u64::from(digest[offset] & 0x7f) << 24)
        | (u64::from(digest[offset + 1]) << 16)
        | (u64::from(digest[offset + 2]) << 8)
        | u64::from(digest[offset + 3]);
    let digits = u32::from(digits.clamp(1, 10));
    let code = truncated % 10u64.pow(digits);
    format!("{:0width$}", code, width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B: SHA-1 reference secret (20 × "1" ASCII).
    const RFC_SECRET_SHA1: &[u8; 20] = b"12345678901234567890";
    /// RFC 6238 Appendix B: SHA-256 reference secret (32 × "1" ASCII).
    const RFC_SECRET_SHA256: &[u8; 32] = b"12345678901234567890123456789012";

    /// RFC 6238 Appendix B test vectors (8-digit codes), SHA-1 column.
    #[test]
    fn rfc6238_appendix_b_sha1_vectors() {
        let cases = [
            (59i64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (at, expected) in cases {
            assert_eq!(
                totp_code(RFC_SECRET_SHA1, TotpAlgorithm::Sha1, 8, 30, at),
                expected,
                "SHA1 vector at T={}",
                at
            );
        }
    }

    /// RFC 6238 Appendix B test vectors (8-digit codes), SHA-256 column.
    #[test]
    fn rfc6238_appendix_b_sha256_vectors() {
        let cases = [
            (59i64, "46119246"),
            (1_111_111_109, "68084774"),
            (1_111_111_111, "67062674"),
            (1_234_567_890, "91819424"),
            (2_000_000_000, "90698825"),
            (20_000_000_000, "77737706"),
        ];
        for (at, expected) in cases {
            assert_eq!(
                totp_code(RFC_SECRET_SHA256, TotpAlgorithm::Sha256, 8, 30, at),
                expected,
                "SHA256 vector at T={}",
                at
            );
        }
    }

    /// The default 6-digit form is the 8-digit reference value mod 10^6
    /// (same dynamic truncation, fewer digits).
    #[test]
    fn six_digit_codes_match_reference_truncation() {
        // RFC 6238 Appendix B SHA-1 row at T=59 → 94287082 → 287082.
        assert_eq!(
            totp_code(RFC_SECRET_SHA1, TotpAlgorithm::Sha1, 6, 30, 59),
            "287082"
        );
        assert_eq!(
            totp_code(RFC_SECRET_SHA256, TotpAlgorithm::Sha256, 6, 30, 59),
            "119246"
        );
    }

    /// Codes change between time steps and stay stable within one step.
    #[test]
    fn code_rotates_each_period() {
        let a = totp_code(RFC_SECRET_SHA1, TotpAlgorithm::Sha1, 6, 30, 120);
        let b = totp_code(RFC_SECRET_SHA1, TotpAlgorithm::Sha1, 6, 30, 149);
        let c = totp_code(RFC_SECRET_SHA1, TotpAlgorithm::Sha1, 6, 30, 150);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// RFC 4648 §10 test vectors — padded canonical forms decode exactly.
    #[test]
    fn base32_decodes_rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("MY======", "f"),
            ("MZXQ====", "fo"),
            ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"),
            ("MZXW6YTB", "fooba"),
            ("MZXW6YTBOI======", "foobar"),
        ];
        for (encoded, decoded) in cases {
            assert_eq!(
                base32_decode(encoded).unwrap(),
                decoded.as_bytes(),
                "decoding {}",
                encoded
            );
        }
    }

    /// Padding-free and lowercase/whitespace-tolerant decoding.
    #[test]
    fn base32_decode_is_padding_and_case_tolerant() {
        assert_eq!(base32_decode("MZXW6").unwrap(), b"foo");
        assert_eq!(base32_decode("mzxw6ytb").unwrap(), b"fooba");
        assert_eq!(base32_decode("MZXW6 YTB\n").unwrap(), b"fooba");
        assert!(base32_decode("MZXW6!").is_err());
        assert!(base32_decode("1").is_err());
    }

    /// Round trip: encode → decode returns the original bytes for every
    /// length (exercises both partial-quintet padding paths).
    #[test]
    fn base32_roundtrip_all_lengths() {
        for len in 0..=21usize {
            let data: Vec<u8> = (0..len as u8)
                .map(|i| i.wrapping_mul(37).wrapping_add(1))
                .collect();
            let encoded = base32_encode(&data);
            assert_eq!(base32_decode(&encoded).unwrap(), data, "len={}", len);
        }
    }

    /// Canonical URI with all parameters.
    #[test]
    fn parses_full_otpauth_uri() {
        let params = parse_otpauth_uri(
            "otpauth://totp/Example%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60&issuer=Example",
        )
        .unwrap();
        assert_eq!(params.label, "Example:alice@example.com");
        assert_eq!(params.secret, b"Hello!\xDE\xAD\xBE\xEF");
        assert_eq!(params.algo, TotpAlgorithm::Sha256);
        assert_eq!(params.digits, 8);
        assert_eq!(params.period, 60);
    }

    /// Defaults: SHA1 / 6 digits / 30 seconds; lowercase algorithm accepted;
    /// percent-encoded secret handled; unknown informational params ignored.
    #[test]
    fn otpauth_defaults_and_tolerant_params() {
        let params = parse_otpauth_uri(
            "otpauth://totp/acme:prod?secret=mzxw6ytb&algorithm=sha256&image=x.png",
        )
        .unwrap();
        assert_eq!(params.label, "acme:prod");
        assert_eq!(params.secret, b"fooba");
        assert_eq!(params.algo, TotpAlgorithm::Sha256);
        assert_eq!(params.digits, DEFAULT_DIGITS);
        assert_eq!(params.period, DEFAULT_PERIOD);

        let minimal = parse_otpauth_uri("otpauth://totp?secret=MZXW6YTB").unwrap();
        assert_eq!(minimal.algo, TotpAlgorithm::Sha1);
        assert_eq!(minimal.label, "");
    }

    /// Malformed URIs and hostile parameter values fail closed.
    #[test]
    fn otpauth_rejects_malformed_input() {
        assert!(parse_otpauth_uri("https://totp/x?secret=MZXW6YTB").is_err());
        assert!(parse_otpauth_uri("otpauth://hotp/x?secret=MZXW6YTB").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x").is_err()); // no secret
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=not!base32").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=MZXW6YTB&digits=99").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=MZXW6YTB&digits=abc").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=MZXW6YTB&period=0").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=MZXW6YTB&algorithm=SHA512").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=MZXW6YTB&algorithm=NOPE").is_err());
    }
}
