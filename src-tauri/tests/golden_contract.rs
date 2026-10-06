//! Golden contract test (§5.6.3).
//!
//! Verifies that the Tauri IPC command list and the Native Messaging HTTP
//! dispatch table expose the same set of commands. The two adapter paths must
//! stay in sync; this test fails if one side adds, renames, or removes a
//! command without updating the other.
//!
//! Beyond the IPC sync contract, this file also pins the updater trust
//! anchor (v1.2.3) — see `updater_trust_anchor_matches_pinned_key`.

use std::collections::HashSet;

/// Command names handled by the Native Messaging HTTP dispatcher
/// (native_messaging::execute_command). Extracted by reading the match arms.
/// This is the authoritative list — when the dispatcher changes, update here
/// and the IPC handler list in lib.rs together.
fn native_messaging_commands() -> HashSet<&'static str> {
    [
        "setup_vault",
        "is_initialized",
        "init_vault",
        "unlock_vault",
        "lock_vault",
        "get_settings",
        "update_settings",
        "create_entry",
        "list_all_entries",
        "get_entry",
        "get_entry_secret",
        "generate_password",
        "update_entry",
        "remove_entry",
        "get_entry_count",
        "create_group",
        "list_all_groups",
        "update_group",
        "remove_group",
        "export_vault",
        "import_vault",
        "handshake",
        "pair",
        "pair_confirm",
        "revoke_extension_access",
    ]
    .into_iter()
    .collect()
}

/// Command names registered with the Tauri invoke_handler (lib.rs).
/// These are the #[tauri::command] functions in commands.rs.
fn tauri_ipc_commands() -> HashSet<&'static str> {
    [
        "is_vault_initialized",
        "is_vault_unlocked",
        "init_vault",
        "unlock_vault",
        "lock_vault",
        // A1: desktop-only auto-lock activity heartbeat (local user input).
        "touch_activity",
        "generate_password",
        "setup_vault",
        "create_entry",
        "get_entry_meta",
        "get_entry_secret",
        "list_all_entries",
        "update_entry",
        "remove_entry",
        "get_entry_count",
        // P2.4 (D6): Tauri-only TOTP code generation — never reachable from
        // the browser extension.
        "totp_code",
        "create_group",
        "list_all_groups",
        "remove_group",
        "update_group",
        "get_settings",
        "update_settings",
        "revoke_extension_access",
        "export_vault",
        "import_vault",
        // SEC-M2 (v1.1.9): backup file IO behind native dialogs — desktop
        // UI only, never reachable from the browser extension.
        "export_vault_file",
        "read_backup_file",
        // Phase 1 security operations — desktop-only (D6): they drive the
        // local credential store / touch the session state machine and must
        // never be reachable from the browser extension.
        "change_password",
        "biometric_status",
        "enable_biometric",
        "disable_biometric",
        "unlock_biometric",
        "recovery_status",
        "enable_recovery",
        "disable_recovery",
        "recover_vault",
        // Phase 3 cloud sync — desktop-only (D6): sync drives the session
        // keys and the user's cloud credentials, never exposed via NM.
        "sync_status",
        "sync_connect",
        "sync_disconnect",
        "sync_now",
        // P3.4 (D6): Baidu Netdisk OAuth pairing — cloud-credential flow,
        // desktop-only like the rest of sync.
        "baidu_start_auth",
        "baidu_complete_auth",
    ]
    .into_iter()
    .collect()
}

#[test]
fn native_messaging_dispatcher_exposes_all_core_commands() {
    let nm = native_messaging_commands();
    let ipc = tauri_ipc_commands();

    // Commands that exist in both adapters — these are the "core" vault
    // operations that must be reachable from both the desktop UI and the
    // browser extension.
    let core = [
        "setup_vault",
        "init_vault",
        "unlock_vault",
        "lock_vault",
        "get_settings",
        "update_settings",
        "create_entry",
        "list_all_entries",
        "get_entry_secret",
        "generate_password",
        "update_entry",
        "remove_entry",
        "get_entry_count",
        "create_group",
        "list_all_groups",
        "update_group",
        "remove_group",
        "export_vault",
        "import_vault",
        "revoke_extension_access",
    ];

    for cmd in &core {
        assert!(
            nm.contains(*cmd),
            "Native Messaging dispatcher is missing core command '{cmd}'"
        );
        assert!(
            ipc.contains(*cmd),
            "Tauri IPC handler is missing core command '{cmd}'"
        );
    }
}

#[test]
fn adapter_only_commands_are_documented() {
    let nm = native_messaging_commands();
    let ipc = tauri_ipc_commands();

    // Commands exclusive to Native Messaging (extension-only).
    let nm_only: Vec<&&str> = {
        let mut v: Vec<_> = nm.difference(&ipc).collect();
        v.sort();
        v
    };
    assert_eq!(
        nm_only,
        vec![
            &"get_entry",
            &"handshake",
            &"is_initialized",
            &"pair",
            &"pair_confirm"
        ],
        "NM-only command set changed — update this test if intentional"
    );

    // Commands exclusive to Tauri IPC (desktop-only).
    let ipc_only: Vec<&&str> = {
        let mut v: Vec<_> = ipc.difference(&nm).collect();
        v.sort();
        v
    };
    assert_eq!(
        ipc_only,
        vec![
            &"baidu_complete_auth",
            &"baidu_start_auth",
            &"biometric_status",
            &"change_password",
            &"disable_biometric",
            &"disable_recovery",
            &"enable_biometric",
            &"enable_recovery",
            &"export_vault_file",
            &"get_entry_meta",
            &"is_vault_initialized",
            &"is_vault_unlocked",
            &"read_backup_file",
            &"recover_vault",
            &"recovery_status",
            &"sync_connect",
            &"sync_disconnect",
            &"sync_now",
            &"sync_status",
            &"totp_code",
            &"touch_activity",
            &"unlock_biometric",
        ],
        "IPC-only command set changed — update this test if intentional"
    );
}

/// UPDATER TRUST ANCHOR (v1.2.3, H3 hardening): the updater pubkey baked into
/// tauri.conf.json is the root of trust for every auto-update
/// (docs/UPDATER-KEYS.md). Pinning it here means a key swap cannot land
/// silently — changing the pubkey requires changing this constant in the
/// SAME commit, which is an unmissable review diff.
/// Current key: minisign public key 237BD03CF7C9D12D (decoded from the base64
/// below; the full string is compared byte-for-byte, no decoding here to
/// avoid adding a dependency).
const PINNED_UPDATER_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDIzN0JEMDNDRjdDOUQxMkQKUldRdDBjbjNQTkI3SS9TUzJhZnVMdjJPOFRHcDJ6U3F6NHlOVGRNMGZDamI3dWdOQkFiZWhZTmcK";

#[test]
fn updater_trust_anchor_matches_pinned_key() {
    let conf = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tauri.conf.json"))
        .expect("tauri.conf.json readable next to the crate manifest");
    let value: serde_json::Value = serde_json::from_str(&conf).expect("tauri.conf.json parses");

    // WHY: a compromised repo could silently swap the update-signing key and
    // ship malicious updates that verify as "legit"; the pin turns that into
    // an unmissable same-commit diff.
    let pubkey = value["plugins"]["updater"]["pubkey"]
        .as_str()
        .expect("plugins.updater.pubkey present");
    assert_eq!(
        pubkey, PINNED_UPDATER_PUBKEY,
        "UPDATER TRUST ANCHOR CHANGED. If this is an intentional rotation, update \
         PINNED_UPDATER_PUBKEY in this same commit and follow docs/UPDATER-KEYS.md \
         §3 (transition release, users must manually upgrade once). If not \
         intentional, treat it as a security incident (§4) — do NOT merge."
    );

    // WHY: Tauri v2 platform overlays deep-merge over the base conf, so a
    // new tauri.<platform>.conf.json could override plugins.updater and
    // bypass the pin above entirely.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for overlay in [
        "tauri.macos.conf.json",
        "tauri.windows.conf.json",
        "tauri.linux.conf.json",
        // Mobile overlays (android/ios) are included for completeness — the
        // project is desktop-only today, but a future Tauri Mobile overlay
        // must not silently bypass this guard either.
        "tauri.android.conf.json",
        "tauri.ios.conf.json",
    ] {
        let path = std::path::Path::new(manifest_dir).join(overlay);
        assert!(
            !path.exists(),
            "platform overlay '{overlay}' must not exist: it can deep-merge over \
             plugins.updater in tauri.conf.json and bypass the pinned trust anchor. \
             If an overlay is genuinely required, remove this guard explicitly in \
             the same commit and re-pin whatever it would override."
        );
    }

    // WHY: pointing the updater at another (e.g. attacker-controlled) feed
    // hijacks update lookups even with the key pinned — endpoint changes are
    // as sensitive as a key rotation.
    assert_eq!(
        value["plugins"]["updater"]["endpoints"],
        serde_json::json!([
            "https://raw.githubusercontent.com/chaojimaimi/PwdVault/main/latest.json"
        ]),
        "updater endpoints changed. Endpoint changes are as sensitive as a trust \
         anchor rotation: update this assertion explicitly in the same commit and \
         follow docs/UPDATER-KEYS.md — do NOT merge silently."
    );
}
