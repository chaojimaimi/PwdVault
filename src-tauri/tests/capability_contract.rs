use std::collections::HashSet;

#[test]
fn backup_and_restore_file_commands_are_authorized() {
    let capability: serde_json::Value =
        serde_json::from_str(include_str!("../capabilities/default.json"))
            .expect("default capability must be valid JSON");
    let permissions: HashSet<&str> = capability["permissions"]
        .as_array()
        .expect("permissions must be an array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();

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
}
