//! Extension pairing confirmation
//!
//! Provides an out-of-band pairing confirmation flow: when a browser
//! extension requests pairing, the desktop app displays a short numeric
//! code. The user must enter the same code in the extension before an
//! API token is issued.

use rand::{Rng, rngs::OsRng};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A pending pairing session.
struct PairSession {
    code: String,
    expires_at: Instant,
    #[allow(dead_code)]
    origin: Option<String>,
}

/// Global pending pairing session. Protected by a Mutex; `None` means no
/// active session.
static SESSION: Mutex<Option<PairSession>> = Mutex::new(None);

/// Session lifetime. Kept in sync with the frontend toast duration so the
/// code remains valid for as long as it is visible on screen.
const SESSION_TTL: Duration = Duration::from_secs(30);

/// Create a new pairing session and return the 6-digit code to display.
pub fn create_session(origin: Option<String>) -> String {
    let code = generate_code();
    let session = PairSession {
        code: code.clone(),
        expires_at: Instant::now() + SESSION_TTL,
        origin,
    };
    *SESSION.lock().expect("pair session lock poisoned") = Some(session);
    code
}

/// Verify the user-entered code. A session can only be used once.
pub fn verify(code: &str) -> bool {
    let mut guard = SESSION.lock().expect("pair session lock poisoned");
    guard.take().map_or(false, |session| {
        session.code == code && session.expires_at > Instant::now()
    })
}

/// Generate a 6-digit numeric code.
fn generate_code() -> String {
    let mut rng = OsRng;
    (0..6).map(|_| rng.gen_range(0..10).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify() {
        let code = create_session(None);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(verify(&code));
    }

    #[test]
    fn test_verify_consumes_session() {
        let code = create_session(None);
        assert!(verify(&code));
        assert!(!verify(&code));
    }

    #[test]
    fn test_verify_wrong_code_fails() {
        let _ = create_session(None);
        assert!(!verify("000000"));
    }

    #[test]
    fn test_session_expires() {
        let code = "123456";
        {
            let mut guard = SESSION.lock().unwrap();
            *guard = Some(PairSession {
                code: code.to_string(),
                expires_at: Instant::now() - Duration::from_secs(1),
                origin: None,
            });
        }
        assert!(!verify(code));
    }
}
