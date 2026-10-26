//! Native Messaging command dispatcher.
//!
//! `execute_command` maps the extension's command names onto the application
//! service layer — the HTTP counterpart of the Tauri IPC handlers.

use std::sync::Arc;

use tauri::Emitter;

use pwdvault_application::service;
use pwdvault_application::{
    AppState, CreateEntryRequest, UpdateEntryRequest, VaultBackup, VaultError,
};
use pwdvault_domain::constants;
use pwdvault_domain::Settings;
use pwdvault_infrastructure::auth;

use super::protocol::{enforce_pair_rate_limit, GeneratorMode, NativeRequest};

/// Convert a `VaultError` into a sanitized user-facing error message for HTTP
/// responses. Internal details (paths, serialization errors, etc.) are stripped.
fn vault_error_to_message(err: VaultError) -> String {
    err.public_message()
}

/// WP5 (v1.5.0): payload of the `pair-request` desktop event. The caller
/// label rides along so the desktop toast can show an ID digest the user can
/// compare against chrome://extensions / about:addons.
///
/// SECURITY POSITIONING: `X-PwdVault-Caller` is derived by the native host
/// from browser process arguments, but on a loopback socket any local
/// process can forge the header (protocol.rs origin note) — the digest is a
/// comparison AID for the user, NOT an authentication signal. The pairing
/// code itself remains the secret being displayed.
fn pair_request_payload(code: &str, caller: &str) -> serde_json::Value {
    serde_json::json!({ "code": code, "caller": caller })
}

pub(super) fn execute_command(
    req: NativeRequest,
    state: Arc<AppState>,
    app_handle: Option<tauri::AppHandle>,
    caller: Option<String>,
) -> Result<serde_json::Value, String> {
    // Vault operations acquire a per-operation session lease (§5.1.1) inside
    // each service function: the lease holds a read guard that keeps the keys
    // alive and blocks auto-lock's exclusive clear until the operation
    // finishes, and snapshots the session generation for staleness checks.
    // This provides the same serialization guarantee that op_lock formerly
    // provided — but uniformly across HTTP and Tauri IPC paths. Pair /
    // pair_confirm only manipulate in-memory state and don't need a lease.

    match req.command.as_str() {
        // Protocol negotiation only: version/capabilities. The application
        // version is deliberately NOT reported (v1.3.2) — it zero-consumed
        // across extensions/ and only broadened the fingerprint an attacker
        // can collect from the unauthenticated handshake.
        "handshake" => Ok(serde_json::json!({
            "protocol_version": constants::NATIVE_PROTOCOL_VERSION,
            "capabilities": [
                "caller_bound_pairing",
                "entry_secret_split",
                "trusted_token_storage",
            ],
        })),

        "revoke_extension_access" => service::revoke_extension_access(&state)
            .map(|()| serde_json::json!(true))
            .map_err(vault_error_to_message),

        // Extension pairing — returns API token (no auth required, origin checked in handle_request)
        // Rate limited to prevent token enumeration attacks
        "pair" => {
            let caller_label = caller.as_deref().ok_or("Browser caller required")?;
            enforce_pair_rate_limit(&state)?;

            let challenge = pwdvault_infrastructure::pairing::create_session(caller_label);
            // Notify desktop UI to display the pairing code. SF-P3c: an emit
            // failure must not stay silent — the pairing would stall with no
            // code shown anywhere and no trace of why. WP5: the payload now
            // carries the caller label (see `pair_request_payload` for the
            // security positioning — comparison aid, not authentication).
            if let Some(handle) = app_handle {
                let payload = pair_request_payload(&challenge.code, caller_label);
                if let Err(error) = handle.emit("pair-request", &payload) {
                    tracing::error!("could not surface the pair-request code: {}", error);
                }
            }
            Ok(serde_json::json!({
                "pending": true,
                "session_nonce": challenge.nonce,
            }))
        }

        "pair_confirm" => {
            let caller = caller.as_deref().ok_or("Browser caller required")?;
            // Same shared 10/min counter as "pair": code guessing and
            // pairing-prompt bombing are throttled across BOTH endpoints,
            // not per method.
            enforce_pair_rate_limit(&state)?;
            let session_nonce = req.session_nonce.ok_or("Pairing session required")?;
            let user_code = req.code.ok_or("Code required")?;
            if pwdvault_infrastructure::pairing::verify(
                caller,
                session_nonce.as_str(),
                user_code.as_str(),
            ) {
                let token = auth::get_token();
                Ok(serde_json::json!({ "token": token }))
            } else {
                Err("Invalid or expired code".to_string())
            }
        }

        "is_vault_initialized" => {
            Ok(serde_json::to_value(service::is_initialized(&state)).expect("bool serializable"))
        }

        "is_vault_unlocked" => {
            Ok(serde_json::to_value(service::is_unlocked(&state)).expect("bool serializable"))
        }

        "setup_vault" => service::setup_vault(&state)
            .map(|ok| serde_json::to_value(ok).expect("bool serializable"))
            .map_err(vault_error_to_message),

        "init_vault" => {
            let password = req.password.ok_or("Password required".to_string())?;
            service::init_vault(&state, password)
                .map(|()| serde_json::json!(true))
                .map_err(vault_error_to_message)
        }

        "unlock_vault" => {
            let password = req.password.ok_or("Password required".to_string())?;
            let unlocked =
                service::unlock_vault(&state, password).map_err(vault_error_to_message)?;
            // WP3 (v1.5.0): same post-unlock trash auto-purge as the Tauri
            // unlock commands — runs after the keys are published, one batch
            // (≤500 rows) per unlock; count=0 is not emitted. A failed sweep
            // is logged inside the helper, never surfaced as an unlock error.
            if unlocked {
                if let Some(handle) = app_handle.as_ref() {
                    crate::unlock_effects::sweep_trash_and_emit(handle, &state);
                }
            }
            Ok(serde_json::to_value(unlocked).expect("bool serializable"))
        }

        "lock_vault" => {
            service::lock_vault(&state);
            Ok(serde_json::json!(null))
        }

        "get_settings" => service::get_settings(&state)
            .map(|settings| serde_json::to_value(settings).expect("settings serializable"))
            .map_err(vault_error_to_message),

        "update_settings" => {
            let settings_json = req.settings.ok_or("Settings required".to_string())?;
            let settings: Settings = serde_json::from_value(settings_json)
                .map_err(|_| "Invalid settings".to_string())?;
            service::update_settings(&state, settings)
                .map(|s| serde_json::to_value(s).expect("settings serializable"))
                .map_err(vault_error_to_message)
        }

        "create_entry" => {
            let request = CreateEntryRequest {
                title: req.title.ok_or("Title required".to_string())?,
                username: req.username.ok_or("Username required".to_string())?,
                password: req.password.ok_or("Password required".to_string())?,
                url: req.url,
                notes: req.notes,
                tags: req.tags.unwrap_or_default(),
                group_id: req.group_id,
                // v1.5.0 WP4: the serde default (Auto) covers pre-v1.5.0
                // extension payloads that omit the field.
                url_match_mode: req.url_match_mode,
            };
            service::create_entry(&state, request)
                .map(|summary| serde_json::to_value(summary).expect("entry serializable"))
                .map_err(vault_error_to_message)
        }

        "list_all_entries" => service::list_all_entries(&state)
            .map(|entries| serde_json::to_value(entries).expect("entries serializable"))
            .map_err(vault_error_to_message),

        "get_entry_meta" => {
            let id = req.id_param.ok_or("Entry ID required".to_string())?;
            service::get_entry_meta(&state, id)
                .map(|entry| serde_json::to_value(entry).expect("entry serializable"))
                .map_err(vault_error_to_message)
        }

        "get_entry_secret" => {
            let id = req.id_param.ok_or("Entry ID required".to_string())?;
            service::get_entry_secret(&state, id)
                .map(|secret| serde_json::to_value(secret).expect("secret serializable"))
                .map_err(vault_error_to_message)
        }

        "generate_password" => {
            let options = req.options.unwrap_or_default();
            // v1.4.0: one command, three backends. `mode` defaults to
            // Password (serde default) so pre-v1.4.0 payloads are untouched.
            match options.mode {
                GeneratorMode::Password => service::generate_password(
                    options.length,
                    options.include_uppercase,
                    options.include_lowercase,
                    options.include_numbers,
                    options.include_symbols,
                ),
                GeneratorMode::Passphrase => service::generate_passphrase(
                    options.words,
                    options.separator.as_deref().unwrap_or("-"),
                    options.capitalize,
                    options.append_number,
                ),
                // PIN reuses the shared `length` field (saturating cast; the
                // domain validation rejects anything outside 4..=16).
                GeneratorMode::Pin => {
                    service::generate_pin(options.length.min(u8::MAX as usize) as u8)
                }
            }
            .map(|password| serde_json::to_value(password).expect("password serializable"))
            .map_err(vault_error_to_message)
        }

        "update_entry" => {
            let id = req.id_param.ok_or("Entry ID required".to_string())?;
            let update_notes = req.notes.is_some();
            let request = UpdateEntryRequest {
                title: req.title.ok_or("Title required".to_string())?,
                username: req.username.ok_or("Username required".to_string())?,
                password: req.password,
                url: req.url,
                notes: req.notes,
                update_notes,
                tags: req.tags.unwrap_or_default(),
                group_id: req.group_id,
                // totp_code is Tauri-only (D6); the extension never patches
                // TOTP secrets.
                totp_secret: None,
                // v1.5.0 WP4: the serde default (Auto) covers pre-v1.5.0
                // extension payloads that omit the field.
                url_match_mode: req.url_match_mode,
            };
            service::update_entry(&state, id, request)
                .map(|summary| serde_json::to_value(summary).expect("entry serializable"))
                .map_err(vault_error_to_message)
        }

        "remove_entry" => {
            let id = req.id_param.ok_or("Entry ID required".to_string())?;
            service::remove_entry(&state, id)
                .map(|ok| serde_json::to_value(ok).expect("bool serializable"))
                .map_err(vault_error_to_message)
        }

        "get_entry_count" => service::get_entry_count(&state)
            .map(|count| serde_json::to_value(count).expect("count serializable"))
            .map_err(vault_error_to_message),

        "create_group" => {
            let name = req.name.ok_or("Group name required".to_string())?;
            service::create_group(&state, name)
                .map(|group| serde_json::to_value(group).expect("group serializable"))
                .map_err(vault_error_to_message)
        }

        "list_all_groups" => service::list_all_groups(&state)
            .map(|groups| serde_json::to_value(groups).expect("groups serializable"))
            .map_err(vault_error_to_message),

        "update_group" => {
            let id = req.id_param.ok_or("Group ID required".to_string())?;
            let name = req.name.ok_or("Group name required".to_string())?;
            service::update_group(&state, id, name)
                .map(|group| serde_json::to_value(group).expect("group serializable"))
                .map_err(vault_error_to_message)
        }

        "remove_group" => {
            let id = req.id_param.ok_or("Group ID required".to_string())?;
            service::remove_group(&state, id)
                .map(|ok| serde_json::to_value(ok).expect("bool serializable"))
                .map_err(vault_error_to_message)
        }

        "export_vault" => {
            let export_password = req
                .export_password
                .ok_or("Export password required".to_string())?;
            service::export_vault(&state, export_password)
                .map(|backup| serde_json::to_value(backup).expect("backup serializable"))
                .map_err(vault_error_to_message)
        }

        "import_vault" => {
            let backup_json = req.backup.ok_or("Backup data required".to_string())?;
            let backup: VaultBackup =
                serde_json::from_value(backup_json).map_err(|_| "Invalid backup".to_string())?;
            let import_password = req
                .import_password
                .ok_or("Import password required".to_string())?;
            service::import_vault(&state, backup, import_password)
                .map(|result| serde_json::to_value(result).expect("result serializable"))
                .map_err(vault_error_to_message)
        }

        _ => Err("Unknown command".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::pair_request_payload;

    /// WP5: the desktop `pair-request` payload carries BOTH the code and the
    /// caller label. The frontend formats the label for display (Chrome ids
    /// truncated to first4…last4); the raw label shape is pinned here so a
    /// payload-shape drift cannot silently blank the toast's 请求方 row.
    #[test]
    fn pair_request_payload_carries_code_and_caller() {
        let payload = pair_request_payload(
            "123456",
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
        );
        assert_eq!(payload["code"], "123456");
        assert_eq!(
            payload["caller"],
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        );

        let firefox = pair_request_payload("654321", "moz-extension://pwdvault@pwdvault.app");
        assert_eq!(firefox["code"], "654321");
        assert_eq!(firefox["caller"], "moz-extension://pwdvault@pwdvault.app");
    }
}
