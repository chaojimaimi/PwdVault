//! Extension pairing confirmation
//!
//! Pairing challenges are bound to the browser caller label supplied by the
//! native host. A challenge also carries an unguessable nonce, expires after a
//! short TTL, limits code attempts, and is consumed after successful use.

use rand::{rngs::OsRng, Rng, RngCore};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct PairSession {
    code: String,
    nonce: String,
    expires_at: Instant,
    attempts_remaining: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairChallenge {
    pub code: String,
    pub nonce: String,
}

/// One pending challenge per trusted caller. This prevents one browser from
/// overwriting another browser's in-progress pairing flow.
static SESSIONS: LazyLock<Mutex<HashMap<String, PairSession>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

const SESSION_TTL: Duration = Duration::from_secs(30);
const MAX_CODE_ATTEMPTS: u8 = 5;

/// Create (or replace) the pending challenge for `caller`.
pub fn create_session(caller: &str) -> PairChallenge {
    let challenge = PairChallenge {
        code: generate_code(),
        nonce: generate_nonce(),
    };
    let session = PairSession {
        code: challenge.code.clone(),
        nonce: challenge.nonce.clone(),
        expires_at: Instant::now() + SESSION_TTL,
        attempts_remaining: MAX_CODE_ATTEMPTS,
    };
    SESSIONS
        .lock()
        .expect("pair sessions lock poisoned")
        .insert(caller.to_string(), session);
    challenge
}

/// Verify and consume a caller-bound challenge.
///
/// A different caller or nonce cannot consume/decrement the legitimate
/// challenge. A wrong code for the correct caller+nonce consumes one attempt.
pub fn verify(caller: &str, nonce: &str, code: &str) -> bool {
    let mut sessions = SESSIONS.lock().expect("pair sessions lock poisoned");
    let Some(session) = sessions.get_mut(caller) else {
        return false;
    };

    if session.expires_at <= Instant::now() {
        sessions.remove(caller);
        return false;
    }
    if session.nonce != nonce {
        return false;
    }
    if session.code != code {
        session.attempts_remaining = session.attempts_remaining.saturating_sub(1);
        if session.attempts_remaining == 0 {
            sessions.remove(caller);
        }
        return false;
    }

    sessions.remove(caller);
    true
}

/// Invalidate all outstanding pairing challenges, e.g. when extension access
/// is revoked from Settings.
pub fn cancel_all_sessions() {
    SESSIONS
        .lock()
        .expect("pair sessions lock poisoned")
        .clear();
}

fn generate_code() -> String {
    let mut rng = OsRng;
    (0..6).map(|_| rng.gen_range(0..10).to_string()).collect()
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(name: &str) -> String {
        format!("chrome-extension://{name}")
    }

    #[test]
    fn challenge_is_caller_bound_single_use_and_nonce_protected() {
        let owner = caller("owner");
        let attacker = caller("attacker");
        let challenge = create_session(&owner);

        assert_eq!(challenge.code.len(), 6);
        assert_eq!(challenge.nonce.len(), 32);
        assert!(!verify(&attacker, &challenge.nonce, &challenge.code));
        assert!(!verify(&owner, "wrong-nonce", &challenge.code));
        assert!(verify(&owner, &challenge.nonce, &challenge.code));
        assert!(!verify(&owner, &challenge.nonce, &challenge.code));
    }

    #[test]
    fn wrong_codes_are_limited_but_do_not_affect_other_callers() {
        let owner = caller("limited-owner");
        let other = caller("other-owner");
        let challenge = create_session(&owner);
        let other_challenge = create_session(&other);

        for _ in 0..MAX_CODE_ATTEMPTS {
            assert!(!verify(&owner, &challenge.nonce, "wrong"));
        }
        assert!(!verify(&owner, &challenge.nonce, &challenge.code));
        assert!(verify(
            &other,
            &other_challenge.nonce,
            &other_challenge.code
        ));
    }

    #[test]
    fn expired_challenge_is_rejected_and_removed() {
        let owner = caller("expired-owner");
        let challenge = create_session(&owner);
        {
            let mut sessions = SESSIONS.lock().expect("pair sessions lock");
            sessions.get_mut(&owner).expect("session").expires_at =
                Instant::now() - Duration::from_secs(1);
        }

        assert!(!verify(&owner, &challenge.nonce, &challenge.code));
        assert!(!SESSIONS
            .lock()
            .expect("pair sessions lock")
            .contains_key(&owner));
    }
}
