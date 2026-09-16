import type { CreateEntryRequest, UpdateEntryRequest, EntrySecretResponse, EntrySummary, PasswordGeneratorOptions, Settings, VaultBackup, ImportResult, UpdateInfo, Group, BiometricStatus, SyncConfig, SyncStatusResponse, TotpCodeResponse, BaiduAuthStart } from '../types';

// Private-repository builds have no suitable unauthenticated release feed.
// A release pipeline may explicitly enable this only after publishing a public,
// trusted metadata endpoint. Never embed a GitHub token in the client.
export const UPDATE_CHECK_AVAILABLE = import.meta.env.VITE_UPDATE_CHECK_ENABLED === 'true';

// Unified invoke function that works in both Tauri and browser environments
async function invoke<T>(cmd: string, args?: Record<string, any>): Promise<T> {
  // Check if running in Tauri environment
  if (typeof window !== 'undefined' && (window as any).__TAURI_INTERNALS__) {
    const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
    return tauriInvoke(cmd, args);
  }

  // Not in Tauri environment — this frontend is designed for the Tauri desktop app only.
  // Browser extension uses its own background.js with proper Bearer Token auth.
  throw new Error('PwdVault desktop app is required. Please run this application inside the Tauri desktop environment.');
}

// Vault Management

export async function setupVault(): Promise<boolean> {
  return invoke('setup_vault');
}

export async function isVaultInitialized(): Promise<boolean> {
  return invoke('is_vault_initialized');
}

export async function isVaultUnlocked(): Promise<boolean> {
  return invoke('is_vault_unlocked');
}

export async function initVault(password: string): Promise<void> {
  return invoke('init_vault', { password });
}

export async function unlockVault(password: string): Promise<boolean> {
  return invoke('unlock_vault', { password });
}

export async function lockVault(): Promise<void> {
  return invoke('lock_vault');
}

// A1: auto-lock activity heartbeat. Called on local user input (pointer /
// keyboard) so the auto-lock timer is advanced by real usage, not only by
// vault API traffic.
export async function touchActivity(): Promise<void> {
  return invoke('touch_activity');
}

// Password Generator

export async function generatePassword(options: PasswordGeneratorOptions): Promise<string> {
  return invoke('generate_password', {
    length: options.length,
    includeUppercase: options.includeUppercase,
    includeLowercase: options.includeLowercase,
    includeNumbers: options.includeNumbers,
    includeSymbols: options.includeSymbols,
  });
}

// Entry Management

export async function createEntry(request: CreateEntryRequest): Promise<EntrySummary> {
  return invoke('create_entry', { request });
}

export async function getEntryMeta(id: string): Promise<EntrySummary> {
  return invoke('get_entry_meta', { id });
}

export async function getEntrySecret(id: string): Promise<EntrySecretResponse> {
  return invoke('get_entry_secret', { id });
}

export async function listAllEntries(): Promise<EntrySummary[]> {
  return invoke('list_all_entries');
}

export async function updateEntry(id: string, request: UpdateEntryRequest): Promise<EntrySummary> {
  return invoke('update_entry', { id, request });
}

export async function removeEntry(id: string): Promise<boolean> {
  return invoke('remove_entry', { id });
}

export async function getEntryCount(): Promise<number> {
  return invoke('get_entry_count');
}

// Group Management

export async function createGroup(name: string): Promise<Group> {
  return invoke('create_group', { name });
}

export async function listAllGroups(): Promise<Group[]> {
  return invoke('list_all_groups');
}

export async function removeGroup(id: string): Promise<boolean> {
  return invoke('remove_group', { id });
}

export async function updateGroup(id: string, name: string): Promise<Group> {
  return invoke('update_group', { id, name });
}

// Settings

export async function getSettings(): Promise<Settings> {
  return invoke('get_settings');
}

export async function updateSettings(settings: Settings): Promise<Settings> {
  return invoke('update_settings', { settings });
}

export async function revokeExtensionAccess(): Promise<boolean> {
  return invoke('revoke_extension_access');
}

// Import/Export

export async function exportVault(exportPassword: string): Promise<VaultBackup> {
  return invoke('export_vault', { exportPassword });
}

export async function importVault(backup: VaultBackup, importPassword: string): Promise<ImportResult> {
  return invoke('import_vault', { backup, importPassword });
}

// Update Check

export async function checkForUpdates(): Promise<UpdateInfo> {
  return invoke('check_for_updates');
}

// Security operations (Phase 1) — Tauri-IPC only (D6, touch_activity
// precedent). Password arguments use camelCase keys; Tauri v2 maps them onto
// the snake_case parameters of the Rust commands (same convention as
// generate_password above).

export async function changePassword(
  currentPassword: string,
  newPassword: string,
  recoveryKey?: string | null,
): Promise<void> {
  return invoke('change_password', {
    currentPassword,
    newPassword,
    recoveryKey: recoveryKey ?? null,
  });
}

export async function biometricStatus(): Promise<BiometricStatus> {
  return invoke('biometric_status');
}

export async function enableBiometric(password: string): Promise<void> {
  return invoke('enable_biometric', { password });
}

export async function disableBiometric(): Promise<void> {
  return invoke('disable_biometric');
}

export async function unlockBiometric(): Promise<void> {
  return invoke('unlock_biometric');
}

export async function recoveryStatus(): Promise<boolean> {
  return invoke('recovery_status');
}

/** One-time plaintext recovery key (base64url, 43 chars). */
export async function enableRecovery(password: string): Promise<string> {
  return invoke('enable_recovery', { password });
}

export async function disableRecovery(currentPassword: string): Promise<void> {
  return invoke('disable_recovery', { currentPassword });
}

/** Backend publishes the new session keys on success — no unlock call needed. */
export async function recoverVault(recoveryKey: string, newPassword: string): Promise<void> {
  return invoke('recover_vault', { recoveryKey, newPassword });
}

// TOTP (Phase 2) — Tauri-IPC only (D6, touch_activity precedent). The
// browser-extension bridge never sees TOTP codes.

export async function totpCode(id: string): Promise<TotpCodeResponse> {
  return invoke('totp_code', { id });
}

// Cloud sync (Phase 3) — Tauri-IPC only (D6). Password arguments use
// camelCase keys; Tauri v2 maps them onto the snake_case parameters of the
// Rust commands (change_password precedent above). The nested `config`
// object keeps the backend's serde field names (snake_case) because the
// camelCase rewrite only applies to top-level command arguments.

export async function syncStatus(): Promise<SyncStatusResponse> {
  return invoke('sync_status');
}

/**
 * Bootstrap cloud sync. `containerPassword` derives the sync container key
 * (independent from the master password); `webdavPassword` is required for
 * the WebDAV backend and ignored for Baidu.
 */
export async function syncConnect(
  config: SyncConfig,
  containerPassword: string,
  webdavPassword?: string | null,
): Promise<SyncStatusResponse> {
  return invoke('sync_connect', {
    config,
    containerPassword,
    webdavPassword: webdavPassword ?? null,
  });
}

/** Removes local sync credentials/config; cloud files are kept. */
export async function syncDisconnect(): Promise<void> {
  return invoke('sync_disconnect');
}

export async function syncNow(): Promise<SyncStatusResponse> {
  return invoke('sync_now');
}

/** Returns the Baidu OAuth authorize URL and arms the loopback callback. */
export async function baiduStartAuth(): Promise<BaiduAuthStart> {
  return invoke('baidu_start_auth');
}

/** `null`/empty consumes the code captured by the pending callback. */
export async function baiduCompleteAuth(code: string | null): Promise<void> {
  return invoke('baidu_complete_auth', { code });
}
