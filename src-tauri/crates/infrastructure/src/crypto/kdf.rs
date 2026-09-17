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

        // X6: the starting point is clamped to the import-side floor so every
        // newly generated parameter set (vault creation, export) satisfies the
        // import policy — on a slow machine the benchmark loop below returns
        // the starting point immediately, which previously could yield t=1
        // backups that the importer would now reject ("generate-then-reject").
        let mut params = Self {
            m_cost: KdfPolicy::IMPORT_MIN_MEMORY_KIB,
            t_cost: KdfPolicy::IMPORT_MIN_ITERATIONS,
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
        KdfPolicy::validate(self)?;
        Params::new(self.m_cost, self.t_cost, self.p_cost, None)
            .map_err(|e| KdfError::InvalidParams(e.to_string()))
    }
}

/// Product-level bounds applied before Argon2 allocates memory or starts work.
pub struct KdfPolicy;

impl KdfPolicy {
    pub const MIN_MEMORY_KIB: u32 = 16 * 1024;
    pub const MAX_MEMORY_KIB: u32 = 256 * 1024;
    pub const MIN_ITERATIONS: u32 = 1;
    pub const MAX_ITERATIONS: u32 = 10;
    pub const MIN_PARALLELISM: u32 = 1;
    pub const MAX_PARALLELISM: u32 = 8;
    pub const MAX_MEMORY_TIME_COST: u64 = 1024 * 1024;

    /// X6: import-side product floor (OWASP baseline: 19 MiB / t=2).
    ///
    /// Deliberately separate from `validate`: `validate` serves the UNLOCK
    /// path and must keep accepting any historical parameter set stored in a
    /// vault's verification row (including 16 MiB / t=1 from the old adaptive
    /// floor), while the IMPORT path rejects backups whose embedded params
    /// fall below this baseline.
    pub const IMPORT_MIN_MEMORY_KIB: u32 = 19 * 1024;
    pub const IMPORT_MIN_ITERATIONS: u32 = 2;

    /// X6: import-policy check applied to the KDF params embedded in a
    /// backup before any key derivation. Returns `true` when the params are
    /// at or above the import floor.
    pub fn meets_import_floor(params: &AdaptiveParams) -> bool {
        params.m_cost >= Self::IMPORT_MIN_MEMORY_KIB && params.t_cost >= Self::IMPORT_MIN_ITERATIONS
    }

    pub fn validate(params: &AdaptiveParams) -> Result<(), KdfError> {
        if !(Self::MIN_MEMORY_KIB..=Self::MAX_MEMORY_KIB).contains(&params.m_cost) {
            return Err(KdfError::InvalidParams(
                "memory cost outside product policy".into(),
            ));
        }
        if !(Self::MIN_ITERATIONS..=Self::MAX_ITERATIONS).contains(&params.t_cost) {
            return Err(KdfError::InvalidParams(
                "iteration cost outside product policy".into(),
            ));
        }
        if !(Self::MIN_PARALLELISM..=Self::MAX_PARALLELISM).contains(&params.p_cost) {
            return Err(KdfError::InvalidParams(
                "parallelism outside product policy".into(),
            ));
        }
        if u64::from(params.m_cost) * u64::from(params.t_cost) > Self::MAX_MEMORY_TIME_COST {
            return Err(KdfError::InvalidParams(
                "combined KDF cost outside product policy".into(),
            ));
        }
        Ok(())
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

/// Derive two independent subkeys from a single master key using HKDF-SHA256.
/// Returns (encryption_key, integrity_mac_key).
pub fn derive_subkeys(
    master_key: &[u8; KEY_SIZE],
    salt: &[u8; SALT_SIZE],
) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut enc_key = [0u8; KEY_SIZE];
    let mut mac_key = [0u8; KEY_SIZE];
    hk.expand(b"pwdvault/encryption", &mut enc_key)
        .expect("HKDF expand for encryption key failed");
    hk.expand(b"pwdvault/integrity", &mut mac_key)
        .expect("HKDF expand for integrity key failed");
    (enc_key, mac_key)
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

    /// X6: the adaptive starting point must never fall below the import-side
    /// floor, so freshly generated vault/export parameters always satisfy the
    /// import policy. A zero target makes the benchmark loop return the
    /// starting point on its first pass, isolating the clamp.
    #[test]
    fn test_adaptive_start_clamped_to_import_floor() {
        let params = AdaptiveParams::adaptive(0);
        assert!(params.m_cost >= KdfPolicy::IMPORT_MIN_MEMORY_KIB);
        assert!(params.t_cost >= KdfPolicy::IMPORT_MIN_ITERATIONS);
    }

    /// X6: the import floor accepts exactly the boundary values and rejects
    /// anything one step below on either axis.
    #[test]
    fn test_import_floor_boundary() {
        let at_floor = AdaptiveParams {
            m_cost: KdfPolicy::IMPORT_MIN_MEMORY_KIB,
            t_cost: KdfPolicy::IMPORT_MIN_ITERATIONS,
            p_cost: 1,
        };
        assert!(KdfPolicy::meets_import_floor(&at_floor));

        let weak_memory = AdaptiveParams {
            m_cost: KdfPolicy::IMPORT_MIN_MEMORY_KIB - 1,
            t_cost: KdfPolicy::IMPORT_MIN_ITERATIONS,
            p_cost: 1,
        };
        assert!(!KdfPolicy::meets_import_floor(&weak_memory));

        let weak_iterations = AdaptiveParams {
            m_cost: KdfPolicy::IMPORT_MIN_MEMORY_KIB,
            t_cost: KdfPolicy::IMPORT_MIN_ITERATIONS - 1,
            p_cost: 1,
        };
        assert!(!KdfPolicy::meets_import_floor(&weak_iterations));
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

    #[test]
    fn test_extreme_params_rejected_before_derivation() {
        let params = AdaptiveParams {
            m_cost: u32::MAX,
            t_cost: u32::MAX,
            p_cost: u32::MAX,
        };
        let start = Instant::now();
        assert!(derive_key_with_params("password", &[0u8; SALT_SIZE], &params).is_err());
        assert!(start.elapsed().as_millis() < 50);
    }
}
