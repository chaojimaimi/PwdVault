import { render, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SettingsProvider, useSettings } from './SettingsContext';
import * as api from '../api/vault';
import { DEFAULT_SETTINGS } from '../types';

vi.mock('./AuthContext', () => ({
  useAuth: () => ({ state: { isUnlocked: true } }),
}));

vi.mock('../api/vault', () => ({
  UPDATE_CHECK_AVAILABLE: true,
  getSettings: vi.fn(),
  updateSettings: vi.fn(),
  checkForUpdates: vi.fn(),
}));

function Probe() {
  const { state } = useSettings();
  return <span data-testid="status">{state.status}</span>;
}

describe('SettingsProvider update privacy', () => {
  beforeEach(() => vi.clearAllMocks());

  it('does not call update API when check_updates is false', async () => {
    vi.mocked(api.getSettings).mockResolvedValue({ ...DEFAULT_SETTINGS, check_updates: false });
    render(<SettingsProvider><Probe /></SettingsProvider>);
    await waitFor(() => expect(vi.mocked(api.getSettings)).toHaveBeenCalledOnce());
    await waitFor(() => expect(document.querySelector('[data-testid="status"]')).toHaveTextContent('success'));
    expect(api.checkForUpdates).not.toHaveBeenCalled();
  });

  it('checks at most once after opted-in settings load successfully', async () => {
    vi.mocked(api.getSettings).mockResolvedValue({ ...DEFAULT_SETTINGS, check_updates: true });
    vi.mocked(api.checkForUpdates).mockResolvedValue({
      has_update: false,
      latest_version: '1.0.5',
      release_notes: '',
      download_url: '',
    });
    render(<SettingsProvider><Probe /></SettingsProvider>);
    await waitFor(() => expect(api.checkForUpdates).toHaveBeenCalledOnce());
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(api.checkForUpdates).toHaveBeenCalledTimes(1);
  });
});
