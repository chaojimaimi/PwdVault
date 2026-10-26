//! Tests for the Tauri IPC command wrappers (moved out of commands.rs to
//! keep the adapter module under the 800-line cap — WP3, v1.5.0).

use super::*;
use pwdvault_infrastructure::crypto;
use tauri::Manager;

/// The std-only civil_from_days used for the default export file name
/// must agree with known UTC dates.
#[test]
fn civil_from_days_known_dates() {
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    assert_eq!(civil_from_days(11_017), (2000, 3, 1));
    assert_eq!(civil_from_days(19_358), (2023, 1, 1));
    assert_eq!(civil_from_days(19_723), (2024, 1, 1));
}

/// utc_today_string renders the same shape as the webview's
/// `new Date().toISOString().slice(0, 10)`.
#[test]
fn utc_today_string_is_iso_date_shape() {
    let today = utc_today_string();
    assert_eq!(today.len(), 10, "YYYY-MM-DD: {today}");
    assert_eq!(&today[4..5], "-");
    assert_eq!(&today[7..8], "-");
    assert!(today[..4].chars().all(|c| c.is_ascii_digit()));
    assert!(today[5..7].chars().all(|c| c.is_ascii_digit()));
    assert!(today[8..10].chars().all(|c| c.is_ascii_digit()));
}

/// A1: the `touch_activity` command must delegate to
/// `AppState::touch_activity` so pure-local user input advances the
/// auto-lock deadline exactly like vault operations do.
#[test]
fn touch_activity_command_advances_auto_lock_deadline() {
    let app = tauri::test::mock_app();
    let state = Arc::new(AppState::default());
    app.manage(state.clone());

    // Locked session: no deadline exists and touching stays a no-op.
    assert!(state.session.auto_lock_deadline(600).is_none());

    // Unlock the session (same helper pattern as the native messaging tests).
    let salt = crypto::kdf::generate_salt();
    let (master_key, _params) =
        crypto::kdf::derive_key("correct horse battery staple", &salt).expect("derive master key");
    let (enc_key, mac_key) = crypto::kdf::derive_subkeys(&master_key, &salt);
    state.session.unlock(enc_key, mac_key);

    let before = state
        .session
        .auto_lock_deadline(600)
        .expect("unlocked deadline before touch");
    std::thread::sleep(std::time::Duration::from_millis(10));

    let ipc_state: State<'_, AppHandle> = app.state();
    touch_activity(ipc_state);

    let after = state
        .session
        .auto_lock_deadline(600)
        .expect("deadline after touch");
    assert!(
        after > before,
        "touch_activity must advance the auto-lock deadline"
    );
}
