import type { CreateEntryRequest, EntryResponse, EntrySummary, PasswordGeneratorOptions, Settings, VaultBackup, ImportResult, UpdateInfo, Group } from '../types';

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

export async function getEntry(id: string): Promise<EntryResponse> {
  return invoke('get_entry', { id });
}

export async function listAllEntries(): Promise<EntrySummary[]> {
  return invoke('list_all_entries');
}

export async function updateEntry(id: string, request: CreateEntryRequest): Promise<EntrySummary> {
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

// Import/Export

export async function exportVault(exportPassword: string): Promise<VaultBackup> {
  return invoke('export_vault', { export_password: exportPassword });
}

export async function importVault(backup: VaultBackup, importPassword: string): Promise<ImportResult> {
  return invoke('import_vault', { backup, import_password: importPassword });
}

// Update Check

export async function checkForUpdates(): Promise<UpdateInfo> {
  return invoke('check_for_updates');
}