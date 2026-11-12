use super::*;

const TEST_ENC_KEY: EncKey = [0xAA; 32];
const TEST_MAC_KEY: MacKey = [0xBB; 32];

#[test]
fn test_session_starts_locked() {
    let session = VaultSession::new();
    assert!(!session.is_unlocked());
    assert!(session.get_enc_key().is_err());
    assert!(session.get_mac_key().is_err());
}

#[test]
fn test_unlock_sets_keys() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

    assert!(session.is_unlocked());
    assert_eq!(session.get_enc_key().unwrap(), TEST_ENC_KEY);
    assert_eq!(session.get_mac_key().unwrap(), TEST_MAC_KEY);
}

#[test]
fn test_lease_prevents_clear() {
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    let session = Arc::new(VaultSession::new());
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

    let lease = session.lease().unwrap();
    assert_eq!(lease.enc_key().unwrap(), &TEST_ENC_KEY);
    let (tx, rx) = mpsc::channel();
    let locking_session = Arc::clone(&session);
    let handle = std::thread::spawn(move || {
        let locked = locking_session.exclusive_lock_and_clear();
        tx.send(locked).unwrap();
    });

    // The write lock must not clear the keys while the read lease exists.
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    assert_eq!(lease.enc_key().unwrap(), &TEST_ENC_KEY);
    drop(lease);
    assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
    handle.join().unwrap();
    assert!(!session.is_unlocked());
}

#[test]
fn test_lease_fails_when_locked() {
    let session = VaultSession::new();
    assert!(session.lease().is_err());
}

#[test]
fn test_generation_increments_on_reunlock() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
    let lease1 = session.lease().unwrap();
    assert_eq!(lease1.generation, 1);
    // Must drop the lease before exclusive_lock_and_clear, otherwise
    // the spin-wait inside exclusive_lock_and_clear waits for this
    // lease to drain — which can't happen since we're on the same thread.
    assert!(lease1.check_valid().is_ok());
    drop(lease1);

    session.exclusive_lock_and_clear();

    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
    let lease2 = session.lease().unwrap();
    assert_eq!(lease2.generation, 2);
    assert!(lease2.check_valid().is_ok());
}

#[test]
fn test_touch_activity_updates_timestamp() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

    let deadline1 = session.auto_lock_deadline(60).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    session.touch_activity();
    let deadline2 = session.auto_lock_deadline(60).unwrap();

    assert!(deadline2 > deadline1);
}

#[test]
fn test_auto_lock_deadline_none_when_locked() {
    let session = VaultSession::new();
    assert!(session.auto_lock_deadline(60).is_none());
}

#[test]
fn test_should_auto_lock() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

    // Just unlocked — should not auto-lock yet.
    assert!(!session.should_auto_lock(60));

    // Simulate old activity by checking with timeout=0.
    // (elapsed is always >= 0, so with timeout 0 it should be true)
    std::thread::sleep(std::time::Duration::from_millis(1));
    assert!(session.should_auto_lock(0));
}

/// SEC-L5: a remote touch grants only the short grace window, never the
/// full auto-lock timeout.
#[test]
fn remote_touch_grants_only_grace() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

    // Full-window deadline is set by the unlock alone; a remote touch
    // must not move it (its grace window is far shorter than 600s).
    let full_window = session.auto_lock_deadline(600).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    session.touch_remote_activity();
    assert_eq!(
        session.auto_lock_deadline(600).unwrap(),
        full_window,
        "remote touch must not extend the full auto-lock window"
    );

    // With a tiny local timeout the deadline is the remote grace window
    // (~120s), not the local one (~1s).
    let now = Instant::now();
    let deadline = session.auto_lock_deadline(1).unwrap();
    assert!(
        deadline > now + std::time::Duration::from_secs(115),
        "remote touch must yield the ~120s grace deadline"
    );
    assert!(
        deadline <= now + std::time::Duration::from_secs(121),
        "remote touch must not exceed one grace window"
    );

    // The pending grace also blocks auto-lock even though the local
    // window (timeout=0) has already expired.
    assert!(!session.should_auto_lock(0));
}

/// SEC-L5 max semantics: the deadline is the LATER of the local window
/// and the remote grace window — whichever side is currently later wins.
#[test]
fn max_semantics() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
    std::thread::sleep(std::time::Duration::from_millis(10));
    session.touch_remote_activity();

    // Remote is the most recent activity: with a short local timeout the
    // grace window (remote + 120s) beats the local one (unlock + 1s).
    let now = Instant::now();
    let deadline = session.auto_lock_deadline(1).unwrap();
    assert!(
        deadline > now + std::time::Duration::from_secs(115),
        "the later remote grace window must win"
    );

    // Reverse: the local window is older in wall-clock terms but longer
    // (unlock + 600s > remote + 120s), so the local deadline wins.
    let deadline = session.auto_lock_deadline(600).unwrap();
    assert!(
        deadline > now + std::time::Duration::from_secs(595),
        "the later long local window must win over the short grace"
    );
    assert!(deadline <= now + std::time::Duration::from_secs(600));
}

/// v1.8.3 F1/R3: the snapshot mirrors the presence timestamps the sync
/// cycle must restore across its merge window — fresh unlock has no
/// grace slot, a remote touch shows up, and a locked session reports no
/// slot (defensive arm — the cycle snapshots while unlocked only).
#[test]
fn activity_snapshot_mirrors_presence() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

    let (la0, ra0) = session.activity_snapshot();
    assert_eq!(ra0, None, "fresh unlock has no remote grace slot");
    let _ = la0;

    session.touch_remote_activity();
    let (_, ra1) = session.activity_snapshot();
    assert!(ra1.is_some(), "a remote touch must show in the snapshot");

    session.exclusive_lock_and_clear();
    let (_, ra2) = session.activity_snapshot();
    assert_eq!(ra2, None, "the locked arm reports no grace slot");
}

/// v1.8.3 F1/R3: `unlock_if_restoring` republishes keys while restoring
/// the caller's presence timestamps (plain `unlock_if` would stamp
/// `now`/`None` and silently refresh the auto-lock window on every sync
/// cycle). Refusal behaves exactly like `unlock_if`: keys dropped,
/// session untouched, no generation bump.
#[test]
fn unlock_if_restoring_publishes_with_restored_presence() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

    // Anchor in the past: if the republish stamped `now` instead, the
    // restored `last_activity` would differ from this instant.
    let anchor = Instant::now() - std::time::Duration::from_secs(60);
    let restored_remote = Some(Instant::now());

    let published = session.unlock_if_restoring(
        TEST_ENC_KEY,
        TEST_MAC_KEY,
        |live_generation| live_generation == 1,
        anchor,
        restored_remote,
    );
    assert!(published, "the republish must go through on generation 1");

    // Presence restored verbatim — not refreshed.
    let (la, ra) = session.activity_snapshot();
    assert_eq!(la, anchor, "last_activity must be the caller's timestamp");
    assert_eq!(ra, restored_remote, "the grace slot must be restored");

    // Refusal path: wrong expected generation → false, and the session
    // is left exactly as the restoring publish left it.
    let refused = session.unlock_if_restoring(
        TEST_ENC_KEY,
        TEST_MAC_KEY,
        |generation| generation == 1,
        anchor,
        None,
    );
    assert!(!refused);
    let (la_after, ra_after) = session.activity_snapshot();
    assert_eq!(la_after, anchor, "a refusal must not touch the session");
    assert_eq!(
        ra_after, restored_remote,
        "a refusal must not touch the session"
    );

    // Generation bumped exactly once (same rule as unlock_if): the next
    // republish keys on generation 2.
    let republished = session.unlock_if(TEST_ENC_KEY, TEST_MAC_KEY, |generation| generation == 2);
    assert!(republished, "generation must have advanced exactly +1");
}

/// SEC-L5: locking discards the grace slot — a lock/unlock cycle leaves
/// no stale remote window behind.
#[test]
fn lock_clears_remote_activity() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
    session.touch_remote_activity();

    // Grace pending: even an expired local window (timeout=0) must not
    // auto-lock.
    assert!(!session.should_auto_lock(0));

    assert!(session.exclusive_lock_and_clear());
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

    // Fresh session, no remote activity recorded: the expired local
    // window locks again — no stale grace.
    assert!(session.should_auto_lock(0));
}

#[test]
fn test_exclusive_lock_clears_keys() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
    assert!(session.is_unlocked());

    let was_unlocked = session.exclusive_lock_and_clear();
    assert!(was_unlocked);
    assert!(!session.is_unlocked());
    assert!(session.get_enc_key().is_err());
    assert!(session.get_mac_key().is_err());
}

#[test]
fn test_exclusive_lock_on_already_locked() {
    let session = VaultSession::new();
    assert!(!session.exclusive_lock_and_clear());
}

/// Fix plan A §2.3: `unlock_if` publishes only when the predicate holds,
/// the predicate sees the live generation under the same critical
/// section, and a declined publish leaves the session untouched.
#[test]
fn test_unlock_if_predicate_gates_publish() {
    let session = VaultSession::new();

    // Declined: no publish, session stays Locked.
    assert!(!session.unlock_if(TEST_ENC_KEY, TEST_MAC_KEY, |_| false));
    assert!(!session.is_unlocked());

    // Accepted: keys are live and the generation bumped by exactly one.
    assert!(session.unlock_if(TEST_ENC_KEY, TEST_MAC_KEY, |gen| gen == 0));
    assert!(session.is_unlocked());
    assert_eq!(session.get_enc_key().unwrap(), TEST_ENC_KEY);

    // The predicate observes the live generation (1 after one publish).
    let seen = std::cell::Cell::new(0u64);
    assert!(!session.unlock_if(TEST_ENC_KEY, TEST_MAC_KEY, |gen| {
        seen.set(gen);
        false
    }));
    assert_eq!(seen.get(), 1);
    // Still the first publish's generation — the declined call was inert.
    let lease = session.lease().unwrap();
    assert_eq!(lease.generation(), 1);
}

/// Phase 1 (D5): the wrap key slot lives only in the session that
/// unlocked via Touch ID — a republish (session.unlock) drops it and an
/// exclusive lock zeroizes it.
#[test]
fn test_wrap_key_slot_lifecycle() {
    let session = VaultSession::new();
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
    assert!(session.cached_wrap_key().is_none());

    session.set_wrap_key(SecretKey::new([0xCC; 32]));
    let cached = session.cached_wrap_key();
    assert_eq!(cached.as_ref().map(SecretKey::as_ref), Some(&[0xCC_u8; 32]));
    drop(cached);

    // Republish (e.g. change_password) rebuilds the session without it.
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
    assert!(session.cached_wrap_key().is_none());

    session.set_wrap_key(SecretKey::new([0xDD; 32]));
    // Locking clears the slot entirely.
    assert!(session.exclusive_lock_and_clear());
    assert!(session.cached_wrap_key().is_none());

    // set_wrap_key on a Locked session is a silent no-op (key dropped).
    session.set_wrap_key(SecretKey::new([0xEE; 32]));
    assert!(session.cached_wrap_key().is_none());
}

#[test]
fn test_concurrent_leases() {
    use std::sync::Arc;
    use std::thread;

    let session = Arc::new(VaultSession::new());
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);

    let mut handles = Vec::new();
    for _ in 0..10 {
        let s = session.clone();
        handles.push(thread::spawn(move || {
            let lease = s.lease().unwrap();
            assert_eq!(lease.enc_key().unwrap(), &TEST_ENC_KEY);
            // Simulate work
            std::thread::sleep(std::time::Duration::from_millis(5));
            assert!(lease.check_valid().is_ok());
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // After all leases dropped, exclusive_lock should succeed immediately.
    assert!(session.exclusive_lock_and_clear());
}

#[test]
fn test_one_thousand_mixed_session_operations() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let session = Arc::new(VaultSession::new());
    session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
    let barrier = Arc::new(Barrier::new(10));
    let mut handles = Vec::new();

    // Eight operation workers model IPC/HTTP service calls.
    for _ in 0..8 {
        let session = Arc::clone(&session);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..100 {
                if let Ok(lease) = session.lease() {
                    assert_eq!(lease.enc_key().unwrap(), &TEST_ENC_KEY);
                    assert_eq!(lease.mac_key().unwrap(), &TEST_MAC_KEY);
                    assert!(lease.check_valid().is_ok());
                }
                thread::yield_now();
            }
        }));
    }

    // One activity worker models successful commands resetting auto-lock.
    {
        let session = Arc::clone(&session);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..100 {
                session.touch_activity();
                thread::yield_now();
            }
        }));
    }

    // One exclusive worker models auto-lock followed by user unlock.
    {
        let session = Arc::clone(&session);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..100 {
                session.exclusive_lock_and_clear();
                session.unlock(TEST_ENC_KEY, TEST_MAC_KEY);
                thread::yield_now();
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
    assert!(session.is_unlocked());
}
