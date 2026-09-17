use std::collections::HashSet;

// X5: fs permissions are objects with allow/deny scopes; collect the
// identifier from both the plain-string and the object form.
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
fn backup_and_restore_file_commands_are_authorized() {
    let capability: serde_json::Value =
        serde_json::from_str(include_str!("../capabilities/default.json"))
            .expect("default capability must be valid JSON");
    let permissions = permission_identifiers(&capability);

    for required in [
        "dialog:default",
        "fs:allow-write-file",
        "fs:allow-read-file",
        "fs:allow-stat",
    ] {
        assert!(
            permissions.contains(required),
            "missing backup/restore permission: {required}"
        );
    }

    // X5: every scoped fs permission must allow ordinary user locations for
    // export/import, and MUST deny the vault database directories on both
    // supported platforms (macOS: com.pwdvault.app; Windows: %LOCALAPPDATA%
    // /PwdVault — reachable via the `$HOME/**` allow rule).
    let allow_paths = ["$HOME/**", "/Volumes/**", "$TEMP/**"];
    let deny_paths = [
        "$HOME/Library/Application Support/com.pwdvault.app/**",
        "$LOCALDATA/PwdVault/**",
    ];
    for identifier in ["fs:allow-write-file", "fs:allow-read-file", "fs:allow-stat"] {
        let entry = capability["permissions"]
            .as_array()
            .expect("permissions must be an array")
            .iter()
            .find(|entry| entry["identifier"].as_str() == Some(identifier))
            .unwrap_or_else(|| panic!("{identifier} must be an object with a scope"));

        let allow: Vec<&str> = entry["allow"]
            .as_array()
            .unwrap_or_else(|| panic!("{identifier} must declare an allow scope"))
            .iter()
            .filter_map(|scope| scope["path"].as_str())
            .collect();
        for path in allow_paths {
            assert!(
                allow.contains(&path),
                "{identifier} allow scope must contain {path}"
            );
        }

        let deny: Vec<&str> = entry["deny"]
            .as_array()
            .unwrap_or_else(|| panic!("{identifier} must declare a deny scope"))
            .iter()
            .filter_map(|scope| scope["path"].as_str())
            .collect();
        for path in deny_paths {
            assert!(
                deny.contains(&path),
                "{identifier} deny scope must contain {path}"
            );
        }
    }
}
