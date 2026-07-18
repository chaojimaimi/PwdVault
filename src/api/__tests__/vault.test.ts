import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock @tauri-apps/api/core so the Tauri path is taken when __TAURI_INTERNALS__ is set
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

// Import after mock setup
import {
  createEntry,
  exportVault,
  importVault,
  isVaultInitialized,
  unlockVault,
} from '../vault';
import type { VaultBackup } from '../../types';

describe('vault API client', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();
    // Default: no Tauri environment
    delete (window as any).__TAURI_INTERNALS__;
  });

  describe('non-Tauri environment', () => {
    it('should throw descriptive error when not in Tauri environment', async () => {
      await expect(isVaultInitialized()).rejects.toThrow('PwdVault desktop app is required');
    });

    it('should throw for all API calls when not in Tauri environment', async () => {
      await expect(unlockVault('test')).rejects.toThrow('PwdVault desktop app is required');
      await expect(createEntry({ title: 'T', username: 'u', password: 'p', tags: [] })).rejects.toThrow('PwdVault desktop app is required');
    });
  });

  describe('Tauri environment', () => {
    it('should call tauriInvoke when __TAURI_INTERNALS__ is set', async () => {
      (window as any).__TAURI_INTERNALS__ = {};

      const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
      (tauriInvoke as ReturnType<typeof vi.fn>).mockResolvedValue(true);

      const result = await isVaultInitialized();

      expect(result).toBe(true);
      expect(tauriInvoke).toHaveBeenCalledWith('is_vault_initialized', undefined);
    });

    it('should pass args to tauriInvoke', async () => {
      (window as any).__TAURI_INTERNALS__ = {};

      const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
      (tauriInvoke as ReturnType<typeof vi.fn>).mockResolvedValue(true);

      await unlockVault('mypassword');

      expect(tauriInvoke).toHaveBeenCalledWith('unlock_vault', { password: 'mypassword' });
    });

    it('uses Tauri camelCase argument names for backup commands', async () => {
      (window as any).__TAURI_INTERNALS__ = {};

      const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
      (tauriInvoke as ReturnType<typeof vi.fn>).mockResolvedValue({});
      const backup = {
        version: 2,
        created_at: 0,
        salt: '',
        kdf_memory: 65536,
        kdf_iterations: 3,
        kdf_parallelism: 1,
        nonce: '',
        data: '',
      } as VaultBackup;

      await exportVault('export-password');
      await importVault(backup, 'import-password');

      expect(tauriInvoke).toHaveBeenNthCalledWith(1, 'export_vault', {
        exportPassword: 'export-password',
      });
      expect(tauriInvoke).toHaveBeenNthCalledWith(2, 'import_vault', {
        backup,
        importPassword: 'import-password',
      });
    });
  });
});
