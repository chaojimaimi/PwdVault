import { render, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SettingsProvider, useSettings, type SettingsContextValue } from './SettingsContext';
import * as api from '../api/vault';
import { DEFAULT_SETTINGS } from '../types';
import { check, type Update } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';

vi.mock('./AuthContext', () => ({
  useAuth: () => ({ state: { isUnlocked: true } }),
}));

vi.mock('../api/vault', () => ({
  getSettings: vi.fn(),
  updateSettings: vi.fn(),
}));

vi.mock('@tauri-apps/plugin-updater', () => ({
  check: vi.fn(),
}));

vi.mock('@tauri-apps/plugin-process', () => ({
  relaunch: vi.fn(),
}));

/** Minimal plugin `Update` double: version metadata + install/close spies. */
function fakeUpdate(
  version: string,
  downloadAndInstall?: Update['downloadAndInstall'],
): Update {
  return {
    version,
    currentVersion: '1.1.6',
    close: vi.fn().mockResolvedValue(undefined),
    downloadAndInstall: downloadAndInstall ?? vi.fn().mockResolvedValue(undefined),
  } as unknown as Update;
}

let latestCtx: SettingsContextValue | null = null;

function Probe() {
  const ctx = useSettings();
  latestCtx = ctx;
  return (
    <div>
      <span data-testid="status">{ctx.state.status}</span>
      <span data-testid="version">{ctx.state.update?.version ?? ''}</span>
      <span data-testid="phase">{ctx.state.updatePhase}</span>
      <span data-testid="progress">{ctx.state.downloadProgress}</span>
    </div>
  );
}

async function renderWithSettings(checkUpdates: boolean) {
  vi.mocked(api.getSettings).mockResolvedValue({ ...DEFAULT_SETTINGS, check_updates: checkUpdates });
  render(<SettingsProvider><Probe /></SettingsProvider>);
  await waitFor(() => expect(latestCtx?.state.status).toBe('success'));
}

describe('SettingsProvider update privacy', () => {
  // localStorage is not provided in this jsdom setup (useTheme.test.tsx
  // precedent): stub it with a Map-backed Storage.
  let storage: Map<string, string>;

  beforeEach(() => {
    vi.clearAllMocks();
    storage = new Map();
    vi.stubGlobal('localStorage', {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
      removeItem: (key: string) => storage.delete(key),
      clear: () => storage.clear(),
      key: (index: number) => Array.from(storage.keys())[index] ?? null,
      get length() { return storage.size; },
    } as Storage);
    latestCtx = null;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('does not call updater check when check_updates is false', async () => {
    await renderWithSettings(false);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(vi.mocked(check)).not.toHaveBeenCalled();
    expect(latestCtx?.state.update).toBeNull();
  });

  it('passes the 5s timeout to the plugin check', async () => {
    vi.mocked(check).mockResolvedValue(null);
    await renderWithSettings(true);
    await waitFor(() => expect(vi.mocked(check)).toHaveBeenCalled());
    expect(vi.mocked(check)).toHaveBeenCalledWith({ timeout: 5000 });
  });

  it('checks at most once per startup even when settings reload', async () => {
    vi.mocked(check).mockResolvedValue(null);
    await renderWithSettings(true);
    await waitFor(() => expect(vi.mocked(check)).toHaveBeenCalledOnce());
    // Simulate a settings re-render (e.g. another save) — must not re-check.
    await latestCtx!.actions.loadSettings();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(vi.mocked(check)).toHaveBeenCalledTimes(1);
  });

  it('stays silent when no update is available', async () => {
    vi.mocked(check).mockResolvedValue(null);
    await renderWithSettings(true);
    await waitFor(() => expect(vi.mocked(check)).toHaveBeenCalledOnce());
    expect(latestCtx?.state.update).toBeNull();
    expect(latestCtx?.state.updatePhase).toBe('available');
  });

  it('degrades silently when the check fails', async () => {
    vi.mocked(check).mockRejectedValue(new Error('feed unreachable'));
    await renderWithSettings(true);
    await waitFor(() => expect(vi.mocked(check)).toHaveBeenCalledOnce());
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(latestCtx?.state.update).toBeNull();
    expect(latestCtx?.state.status).toBe('success');
  });

  it('surfaces the new version when the feed has an update', async () => {
    vi.mocked(check).mockResolvedValue(fakeUpdate('1.1.7'));
    await renderWithSettings(true);
    await waitFor(() => expect(latestCtx?.state.update).toEqual({ version: '1.1.7' }));
    expect(latestCtx?.state.updatePhase).toBe('available');
  });

  it('suppresses the banner for a version the user dismissed', async () => {
    storage.set('pwdvault_dismissed_update', '1.1.7');
    vi.mocked(check).mockResolvedValue(fakeUpdate('1.1.7'));
    await renderWithSettings(true);
    await waitFor(() => expect(vi.mocked(check)).toHaveBeenCalledOnce());
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(latestCtx?.state.update).toBeNull();
  });

  it('tracks download progress and flips to ready after install', async () => {
    const downloadAndInstall = vi.fn(async (cb?: (event: { event: string; data?: { contentLength?: number; chunkLength?: number } }) => void) => {
      cb?.({ event: 'Started', data: { contentLength: 200 } });
      cb?.({ event: 'Progress', data: { chunkLength: 100 } });
      cb?.({ event: 'Progress', data: { chunkLength: 50 } });
      cb?.({ event: 'Finished' });
    });
    vi.mocked(check).mockResolvedValue(fakeUpdate('1.1.7', downloadAndInstall as unknown as Update['downloadAndInstall']));
    await renderWithSettings(true);
    await waitFor(() => expect(latestCtx?.state.update).toEqual({ version: '1.1.7' }));

    await latestCtx!.actions.installUpdate();

    await waitFor(() => expect(latestCtx?.state.updatePhase).toBe('ready'));
    expect(latestCtx?.state.downloadProgress).toBe(100);
    expect(downloadAndInstall).toHaveBeenCalledOnce();
  });

  it('returns to the offer state (silent retry) when the download fails', async () => {
    const downloadAndInstall = vi.fn().mockRejectedValue(new Error('download interrupted'));
    vi.mocked(check).mockResolvedValue(fakeUpdate('1.1.7', downloadAndInstall as unknown as Update['downloadAndInstall']));
    await renderWithSettings(true);
    await waitFor(() => expect(latestCtx?.state.update).toEqual({ version: '1.1.7' }));

    await latestCtx!.actions.installUpdate();

    await waitFor(() => expect(latestCtx?.state.updatePhase).toBe('available'));
    expect(latestCtx?.state.downloadProgress).toBe(0);
  });

  it('relaunches through the process plugin', async () => {
    vi.mocked(check).mockResolvedValue(null);
    await renderWithSettings(true);
    await latestCtx!.actions.relaunchApp();
    expect(vi.mocked(relaunch)).toHaveBeenCalledOnce();
  });

  it('dismissUpdate persists the version and clears the banner', async () => {
    vi.mocked(check).mockResolvedValue(fakeUpdate('1.1.7'));
    await renderWithSettings(true);
    await waitFor(() => expect(latestCtx?.state.update).toEqual({ version: '1.1.7' }));

    latestCtx!.actions.dismissUpdate();

    await waitFor(() => expect(latestCtx?.state.update).toBeNull());
    expect(storage.get('pwdvault_dismissed_update')).toBe('1.1.7');
  });
});
