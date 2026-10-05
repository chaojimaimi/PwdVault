use std::collections::HashSet;

// X5/SEC-M2: collect the identifier from both the plain-string and the
// object form of a permission entry.
fn permission_identifiers(capability: &serde_json::Value) -> HashSet<String> {
    capability["permissions"]
        .as_array()
        .expect("permissions must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_string)
                .or_else(|| entry["identifier"].as_str().map(str::to_string))
                .unwrap_or_else(|| {
                    panic!("permission entry must be a string or carry an identifier: {entry}")
                })
        })
        .collect()
}

#[test]
fn fs_webview_scopes_revoked_desktop_commands_own_file_io() {
    let capability: serde_json::Value =
        serde_json::from_str(include_str!("../capabilities/default.json"))
            .expect("default capability must be valid JSON");
    let permissions = permission_identifiers(&capability);

    // SEC-M2 (v1.1.9): the scoped fs permissions that used to let the webview
    // read/write arbitrary $HOME locations are revoked — backup/restore and
    // recovery-key file IO moved into dedicated desktop commands
    // (export_vault_file, read_backup_file, enable_recovery).
    for revoked in ["fs:allow-write-file", "fs:allow-read-file", "fs:allow-stat"] {
        assert!(
            !permissions.contains(revoked),
            "fs permission must stay revoked (SEC-M2): {revoked}"
        );
    }

    // No scoped permission objects may remain: every entry is a plain string,
    // so no allow/deny scope blocks survive in the capability.
    for entry in capability["permissions"]
        .as_array()
        .expect("permissions must be an array")
    {
        assert!(
            entry.get("allow").is_none() && entry.get("deny").is_none(),
            "no allow/deny scope objects may remain: {entry}"
        );
    }

    // The plugin-level defaults and the other boundary grants must not regress:
    // fs:default keeps the fs plugin usable for its built-ins, dialog:default
    // is required for the frontend save dialog of the recovery key, and the
    // clipboard pair is the M11 decision (auto-clear digest guard).
    for required in [
        "dialog:default",
        "fs:default",
        "clipboard-manager:allow-write-text",
        "clipboard-manager:allow-read-text",
    ] {
        assert!(
            permissions.contains(required),
            "capability must keep permission: {required}"
        );
    }
}
