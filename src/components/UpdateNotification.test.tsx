import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { UpdateNotification } from './UpdateNotification';
import type { UpdatePhase } from '../context/SettingsContext';

function setup(phase: UpdatePhase, progress = 0) {
  const handlers = {
    onUpdate: vi.fn(),
    onRelaunch: vi.fn(),
    onDismiss: vi.fn(),
  };
  render(
    <UpdateNotification
      version="1.1.7"
      phase={phase}
      progress={progress}
      {...handlers}
    />,
  );
  return handlers;
}

describe('UpdateNotification (updater banner)', () => {
  it('offers Update now / Dismiss while the update is only available', () => {
    const handlers = setup('available');
    expect(screen.getByText('PwdVault 1.1.7 is available')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Update now' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Dismiss' })).toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    screen.getByRole('button', { name: 'Update now' }).click();
    expect(handlers.onUpdate).toHaveBeenCalledOnce();
  });

  it('shows the download progress bar while downloading', () => {
    setup('downloading', 40);
    expect(screen.getByText('PwdVault 1.1.7 is available')).toBeInTheDocument();
    const bar = screen.getByRole('progressbar', { name: 'Downloading update' });
    expect(bar).toHaveAttribute('aria-valuenow', '40');
    expect(screen.queryByRole('button', { name: 'Update now' })).toBeNull();
  });

  it('offers Relaunch once the update is installed', () => {
    const handlers = setup('ready', 100);
    expect(screen.getByRole('button', { name: 'Relaunch' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Update now' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull();
    screen.getByRole('button', { name: 'Relaunch' }).click();
    expect(handlers.onRelaunch).toHaveBeenCalledOnce();
  });
});
