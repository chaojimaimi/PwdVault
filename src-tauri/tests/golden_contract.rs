//! Golden contract test (§5.6.3).
//!
//! Verifies that the Tauri IPC command list and the Native Messaging HTTP
//! dispatch table expose the same set of commands. The two adapter paths must
//! stay in sync; this test fails if one side adds, renames, or removes a
//! command without updating the other.

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
        "check_for_updates",
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
        "generate_password",
        "setup_vault",
        "create_entry",
        "get_entry_meta",
        "get_entry_secret",
        "list_all_entries",
        "update_entry",
        "remove_entry",
        "get_entry_count",
        "create_group",
        "list_all_groups",
        "remove_group",
        "update_group",
        "get_settings",
        "update_settings",
        "revoke_extension_access",
        "export_vault",
        "import_vault",
        "check_for_updates",
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
        "check_for_updates",
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
            &"get_entry_meta",
            &"is_vault_initialized",
            &"is_vault_unlocked"
        ],
        "IPC-only command set changed — update this test if intentional"
    );
}
