//! Browser-extension access control (CQ-P3a, v1.2.0): the revocation entry
//! point shared by the desktop IPC command and the extension HTTP
//! dispatcher, so both adapters run exactly the same sequence instead of
//! each hand-rolling the infrastructure calls.

use std::sync::Arc;

use crate::{AppState, VaultError};

/// Revoke all browser-extension access: regenerate the API token (every
/// paired extension's stored Bearer token stops validating) and cancel all
/// pending pairing sessions.
///
/// `state` is kept for the uniform service-layer signature; revocation
/// itself only touches process-global auth/pairing state, and neither
/// infrastructure call is fallible today, so the `Result` simply carries the
/// layer's standard fallible shape (mapped adapters can append cleanup steps
/// that CAN fail without another signature change).
pub fn revoke_extension_access(state: &Arc<AppState>) -> Result<(), VaultError> {
    let _ = state;
    pwdvault_infrastructure::auth::revoke_extension_access();
    pwdvault_infrastructure::pairing::cancel_all_sessions();
    Ok(())
}
