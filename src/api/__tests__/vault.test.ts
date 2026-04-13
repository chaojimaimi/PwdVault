import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock @tauri-apps/api/core so the Tauri path is taken when __TAURI_INTERNALS__ is set
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

// Import after mock setup
import { isVaultInitialized, unlockVault, createEntry, listAllEntries } from '../vault';

describe('vault API client', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // Default: no Tauri environment, so HTTP path is used
    delete (window as any).__TAURI_INTERNALS__;
  });

  describe('HTTP fallback path', () => {
    it('should send correct JSON body with command via fetch', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: true, data: true }),
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await isVaultInitialized();

      expect(result).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith('http://127.0.0.1:17429', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: 1, command: 'is_vault_initialized' }),
      });
    });

    it('should pass args in the request body', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: true, data: true }),
      });
      vi.stubGlobal('fetch', mockFetch);

      await unlockVault('mypassword');

      expect(mockFetch).toHaveBeenCalledWith('http://127.0.0.1:17429', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: 1, command: 'unlock_vault', password: 'mypassword' }),
      });
    });

    it('should pass nested args for createEntry', async () => {
      const mockEntry = { title: 'Test', username: 'user', password: 'pass', url: 'https://example.com', tags: [] };
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: true, data: { id: '123', ...mockEntry } }),
      });
      vi.stubGlobal('fetch', mockFetch);

      await createEntry(mockEntry);

      const callBody = JSON.parse((mockFetch.mock.calls[0] as any)[1].body);
      expect(callBody.command).toBe('create_entry');
      expect(callBody.request).toEqual(mockEntry);
    });
  });

  describe('error handling', () => {
    it('should throw on non-OK HTTP response', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
      });
      vi.stubGlobal('fetch', mockFetch);

      await expect(listAllEntries()).rejects.toThrow('HTTP error: 500');
    });

    it('should throw with string error message for success:false response', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: false, error: 'Vault is locked' }),
      });
      vi.stubGlobal('fetch', mockFetch);

      await expect(listAllEntries()).rejects.toThrow('Vault is locked');
    });

    it('should throw with stringified error for non-string error in success:false response', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: false, error: { code: 42, detail: 'unknown' } }),
      });
      vi.stubGlobal('fetch', mockFetch);

      await expect(listAllEntries()).rejects.toThrow('{"code":42,"detail":"unknown"}');
    });

    it('should throw generic message when error is missing', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: false }),
      });
      vi.stubGlobal('fetch', mockFetch);

      await expect(listAllEntries()).rejects.toThrow('Request failed');
    });
  });
});
