import { useState } from 'react';
import { fireEvent, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// A1: mock the vault API so the activity hook can be exercised without a
// Tauri backend (see hooksSanity.test.tsx for the lightweight harness style).
vi.mock('./api/vault', () => ({
  touchActivity: vi.fn(() => Promise.resolve()),
}));

import { touchActivity } from './api/vault';
import { useAutoLockActivity } from './App';

const mockTouchActivity = vi.mocked(touchActivity);

function Harness({ enabled }: { enabled: boolean }) {
  useAutoLockActivity(enabled);
  return <div>activity harness</div>;
}

function movePointer(): void {
  // A plain Event is enough: the hook only listens for the event type.
  fireEvent(window, new Event('pointermove'));
}

describe('useAutoLockActivity (A1)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockTouchActivity.mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('reports activity once and throttles repeats within 60s', () => {
    render(<Harness enabled />);

    movePointer();
    expect(mockTouchActivity).toHaveBeenCalledTimes(1);

    // Further input inside the throttle window must not call the backend.
    fireEvent.keyDown(window, { key: 'Enter' });
    fireEvent(window, new Event('pointerdown'));
    movePointer();
    expect(mockTouchActivity).toHaveBeenCalledTimes(1);

    // After the throttle window elapses, activity is reported again.
    vi.advanceTimersByTime(61_000);
    movePointer();
    expect(mockTouchActivity).toHaveBeenCalledTimes(2);
  });

  it('does not report when disabled', () => {
    render(<Harness enabled={false} />);

    movePointer();
    fireEvent.keyDown(window, { key: 'Enter' });

    expect(mockTouchActivity).not.toHaveBeenCalled();
  });

  it('stops reporting after the vault locks', () => {
    const { rerender } = render(<Harness enabled />);

    movePointer();
    expect(mockTouchActivity).toHaveBeenCalledTimes(1);

    // Vault locked: listeners must be removed so no further calls happen.
    rerender(<Harness enabled={false} />);
    vi.advanceTimersByTime(61_000);
    movePointer();
    expect(mockTouchActivity).toHaveBeenCalledTimes(1);
  });
});
