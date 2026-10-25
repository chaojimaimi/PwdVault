//! Global shortcut wiring (v1.4.0, WP5).
//!
//! Registration lives in Rust (not the plugin's JS API) so the capability
//! grants stay minimal and the webview never needs `global-shortcut`
//! permissions for the feature to work — the `register_global_shortcut`
//! command is the only IPC entry point, and settings persistence flows
//! through the normal settings pipeline.
//!
//! Action contract (mirrors the tray "show" branch + a route hint): show the
//! main window, focus it, and emit `global-shortcut-vault` — App.tsx listens
//! for that event and routes to the vault screen + focuses the search input.

use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};

/// Default accelerator: Cmd/Ctrl+Shift+Space. Stored in Settings
/// (`global_shortcut`, domain default keeps the same string).
pub const DEFAULT_GLOBAL_SHORTCUT: &str = "CmdOrCtrl+Shift+Space";

/// Frontend event that routes to the vault screen and focuses search.
pub const SHORTCUT_VAULT_EVENT: &str = "global-shortcut-vault";

/// Parse (and thereby validate) an accelerator string without registering
/// it. The plugin's parser accepts the documented Tauri accelerator syntax
/// ("CmdOrCtrl+Shift+Space", "CommandOrControl+P", ...); unknown keys or
/// missing main key fail here, which is exactly the check the settings page
/// needs before persisting a new binding.
pub fn parse_accelerator(accelerator: &str) -> Result<Shortcut, String> {
    accelerator
        .trim()
        .parse::<Shortcut>()
        .map_err(|error| format!("Invalid shortcut '{accelerator}': {error}"))
}

/// (Re)register the global shortcut: unregister everything this app holds,
/// then — when enabled — register the accelerator with the show-vault
/// handler. Errors carry a user-presentable message (settings page renders
/// it and reverts to the previous binding).
///
/// Unregistering ALL first makes repeated calls idempotent and lets a rebind
/// swap the accelerator; the "nothing was registered" case of
/// `unregister_all` is deliberately ignored.
pub fn apply_global_shortcut(
    app: &AppHandle,
    enabled: bool,
    accelerator: &str,
) -> Result<(), String> {
    let shortcuts = app.global_shortcut();
    let _ = shortcuts.unregister_all();
    if !enabled {
        return Ok(());
    }
    let shortcut = parse_accelerator(accelerator)?;
    shortcuts
        .on_shortcut(shortcut, |app, _shortcut, event| {
            // macOS double-fire (upstream tauri#10025): the handler can be
            // invoked for BOTH the press and the release of one physical
            // keypress. The state guard keeps the action to a single run;
            // watch item T37 (qa_manual) tracks real-device behavior.
            if event.state() == ShortcutState::Pressed {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                    let _ = app.emit(SHORTCUT_VAULT_EVENT, ());
                }
            }
        })
        .map_err(|error| format!("Cannot register shortcut '{accelerator}': {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default binding parses and normalizes to the super/meta modifier.
    #[test]
    fn default_accelerator_parses() {
        let shortcut = parse_accelerator(DEFAULT_GLOBAL_SHORTCUT).expect("default parses");
        let text = shortcut.to_string();
        assert!(
            text.to_lowercase().contains("super") || text.to_lowercase().contains("cmd"),
            "CmdOrCtrl maps to a command-ish modifier, got: {text}"
        );
    }

    /// Garbage accelerators fail the parse (the settings page reverts on
    /// this error class instead of persisting a dead binding).
    #[test]
    fn invalid_accelerators_fail_parse() {
        for bad in ["", "   ", "NotAKey", "Shift", "Ctrl++"] {
            assert!(
                parse_accelerator(bad).is_err(),
                "'{bad}' must not parse as an accelerator"
            );
        }
    }

    /// A modifier-only string is rejected: the parser requires exactly one
    /// main key, so "Ctrl+Shift" cannot silently register a dead binding.
    #[test]
    fn modifier_only_fails_parse() {
        assert!(parse_accelerator("Ctrl+Shift").is_err());
    }

    /// Common alternative spellings users may type/copy all parse.
    #[test]
    fn alternative_spellings_parse() {
        for good in [
            "CommandOrControl+Shift+Space",
            "CmdOrCtrl+P",
            "Control+Alt+G",
            "Super+Shift+F9",
        ] {
            assert!(
                parse_accelerator(good).is_ok(),
                "'{good}' should parse as an accelerator"
            );
        }
    }
}
