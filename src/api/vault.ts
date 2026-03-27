import type { CreateEntryRequest, EntryResponse, EntrySummary, PasswordGeneratorOptions } from '../types';

// Unified invoke function that works in both Tauri and browser environments
async function invoke<T>(cmd: string, args?: Record<string, any>): Promise<T> {
  // Check if running in Tauri environment
  if (typeof window !== 'undefined' && (window as any).__TAURI_INTERNALS__) {
    const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
    return tauriInvoke(cmd, args);
  }

  // Fallback to HTTP API for browser extension or dev in browser
  const response = await fetch('http://127.0.0.1:17429', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: 1, command: cmd, ...args }),
  });

  if (!response.ok) {
    throw new Error(`HTTP error: ${response.status}`);
  }

  const data = await response.json();

  if (!data.success) {
    const errorMsg = typeof data.error === 'string'
      ? data.error
      : JSON.stringify(data.error) || 'Request failed';
    throw new Error(errorMsg);
  }

  return data.data;
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