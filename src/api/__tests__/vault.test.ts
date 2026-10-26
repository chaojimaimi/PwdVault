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
  getSecurityReport,
  importCsvOpen,
  importCsvOpenBytes,
  importCsvCommit,
} from '../vault';
import type { VaultBackup } from '../../types';

// Tauri injects __TAURI_INTERNALS__ onto window at runtime; this narrow
// augmentation replaces the previous `(window as any)` casts.
type TauriInternalsWindow = Window & {
  __TAURI_INTERNALS__?: Record<string, unknown>;
};
const asTauriWindow = (): TauriInternalsWindow => window as TauriInternalsWindow;

describe('vault API client', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();
    // Default: no Tauri environment
    delete asTauriWindow().__TAURI_INTERNALS__;
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
      asTauriWindow().__TAURI_INTERNALS__ = {};

      const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
      (tauriInvoke as ReturnType<typeof vi.fn>).mockResolvedValue(true);

      const result = await isVaultInitialized();

      expect(result).toBe(true);
      expect(tauriInvoke).toHaveBeenCalledWith('is_vault_initialized', undefined);
    });

    it('should pass args to tauriInvoke', async () => {
      asTauriWindow().__TAURI_INTERNALS__ = {};

      const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
      (tauriInvoke as ReturnType<typeof vi.fn>).mockResolvedValue(true);

      await unlockVault('mypassword');

      expect(tauriInvoke).toHaveBeenCalledWith('unlock_vault', { password: 'mypassword' });
    });

    it('uses Tauri camelCase argument names for backup commands', async () => {
      asTauriWindow().__TAURI_INTERNALS__ = {};

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

    // v1.5.0 (WP1/WP2): security dashboard + CSV importer wrappers.

    it('calls security_report without arguments', async () => {
      asTauriWindow().__TAURI_INTERNALS__ = {};

      const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
      (tauriInvoke as ReturnType<typeof vi.fn>).mockResolvedValue({});

      await getSecurityReport();

      expect(tauriInvoke).toHaveBeenCalledWith('security_report', undefined);
    });

    it('passes bytes: null to import_csv_open for the native dialog path', async () => {
      asTauriWindow().__TAURI_INTERNALS__ = {};

      const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
      (tauriInvoke as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      const result = await importCsvOpen();

      expect(result).toBeNull();
      expect(tauriInvoke).toHaveBeenCalledWith('import_csv_open', {
        bytes: null,
      });
    });

    it('encodes fallback bytes as a UTF-8 byte array for import_csv_open', async () => {
      asTauriWindow().__TAURI_INTERNALS__ = {};

      const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
      (tauriInvoke as ReturnType<typeof vi.fn>).mockResolvedValue({});

      await importCsvOpenBytes('name,url');

      expect(tauriInvoke).toHaveBeenCalledWith('import_csv_open', {
        // "name,url" has no non-ASCII characters — plain char codes.
        bytes: [110, 97, 109, 101, 44, 117, 114, 108],
      });
    });

    it('calls import_csv_commit without arguments', async () => {
      asTauriWindow().__TAURI_INTERNALS__ = {};

      const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
      (tauriInvoke as ReturnType<typeof vi.fn>).mockResolvedValue({
        created_entries: 2,
        created_groups: 1,
        skipped_rows: 0,
      });

      const result = await importCsvCommit();

      expect(result.created_entries).toBe(2);
      expect(tauriInvoke).toHaveBeenCalledWith('import_csv_commit', undefined);
    });
  });
});
