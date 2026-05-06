//! Key Derivation Function (Argon2id)
//!
//! Provides secure key derivation from master password using Argon2id
//! with adaptive parameters targeting ~500ms derivation time.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;
use zeroize::Zeroize;

use super::KEY_SIZE;
use super::SALT_SIZE;

/// Error type for KDF operations
#[derive(Error, Debug)]
pub enum KdfError {
    #[error("Failed to derive key: {0}")]
    DerivationFailed(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
}

/// Adaptive Argon2id parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveParams {
    /// Memory cost in KiB (e.g., 65536 = 64 MB)
    pub m_cost: u32,
    /// Time cost (iterations)
    pub t_cost: u32,
    /// Parallelism
    pub p_cost: u32,
}

impl Default for AdaptiveParams {
    fn default() -> Self {
        Self {
            m_cost: 65536, // 64 MB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl AdaptiveParams {
    /// Creates parameters targeting a specific derivation time
    pub fn adaptive(target_ms: u64) -> Self {
        let password = b"benchmark_password";
        let salt = [0u8; SALT_SIZE];

        let mut params = Self {
            m_cost: 16384,
            t_cost: 1,
            p_cost: 4,
        };

        for _ in 0..10 {
            let start = Instant::now();

            let argon2_params =
                Params::new(params.m_cost, params.t_cost, params.p_cost, None).unwrap();

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

            let mut output = [0u8; KEY_SIZE];
            let _ = argon2.hash_password_into(password, &salt, &mut output);
            output.zeroize();

            let elapsed = start.elapsed().as_millis() as u64;

            if elapsed >= target_ms {
                return params;
            }

            if params.m_cost < 65536 {
                params.m_cost *= 2;
            } else if params.t_cost < 4 {
                params.t_cost += 1;
            } else {
                return params;
            }
        }

        params
    }

    /// Convert to Argon2 Params
    pub fn to_argon2_params(&self) -> Result<Params, KdfError> {
        Params::new(self.m_cost, self.t_cost, self.p_cost, None)
            .map_err(|e| KdfError::InvalidParams(e.to_string()))
    }
}

/// Generate a random salt
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a key from a password using Argon2id with adaptive parameters
pub fn derive_key(
    password: &str,
    salt: &[u8; SALT_SIZE],
) -> Result<([u8; KEY_SIZE], AdaptiveParams), KdfError> {
    let params = AdaptiveParams::adaptive(500);
    derive_key_with_params(password, salt, &params)
}

/// Derive a key from a password using specific parameters
pub fn derive_key_with_params(
    password: &str,
    salt: &[u8; SALT_SIZE],
    params: &AdaptiveParams,
) -> Result<([u8; KEY_SIZE], AdaptiveParams), KdfError> {
    let argon2_params = params.to_argon2_params()?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key_bytes = [0u8; KEY_SIZE];

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| KdfError::DerivationFailed(e.to_string()))?;

    Ok((key_bytes, params.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let salt = generate_salt();
        let result = derive_key("test_password", &salt);
        assert!(result.is_ok());
    }

    #[test]
    fn test_adaptive_params() {
        let params = AdaptiveParams::adaptive(100);
        assert!(params.m_cost >= 16384);
    }

    #[test]
    fn test_deterministic() {
        let salt = generate_salt();
        let params = AdaptiveParams::default();

        // Derive twice with same parameters
        let (key1, _) = derive_key_with_params("password", &salt, &params).unwrap();
        let (key2, _) = derive_key_with_params("password", &salt, &params).unwrap();

        // Keys should match for same password, salt, and params
        assert_eq!(key1, key2);
    }
}