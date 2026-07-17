import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useTheme } from './useTheme';

function Harness() {
  const { theme, resolvedTheme, setTheme } = useTheme();
  return (
    <div>
      <span>{theme}:{resolvedTheme}</span>
      <button onClick={() => setTheme('light')}>Light</button>
    </div>
  );
}

describe('useTheme system mode', () => {
  let dark = false;
  const listeners = new Set<() => void>();

  beforeEach(() => {
    const values = new Map<string, string>([['pwdvault-theme', 'system']]);
    const storage = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
      clear: () => values.clear(),
      key: (index: number) => Array.from(values.keys())[index] ?? null,
      get length() { return values.size; },
    } as Storage;
    vi.stubGlobal('localStorage', storage);
    dark = false;
    listeners.clear();
    vi.stubGlobal('matchMedia', vi.fn(() => ({
      get matches() { return dark; },
      media: '(prefers-color-scheme: dark)',
      onchange: null,
      addEventListener: (_type: string, listener: () => void) => listeners.add(listener),
      removeEventListener: (_type: string, listener: () => void) => listeners.delete(listener),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('tracks OS theme changes and allows an explicit override', async () => {
    render(<Harness />);
    await waitFor(() => expect(document.documentElement).toHaveAttribute('data-theme', 'light'));
    expect(screen.getByText('system:light')).toBeInTheDocument();

    dark = true;
    listeners.forEach((listener) => listener());
    await waitFor(() => expect(document.documentElement).toHaveAttribute('data-theme', 'dark'));

    screen.getByRole('button', { name: 'Light' }).click();
    await waitFor(() => expect(screen.getByText('light:light')).toBeInTheDocument());
    expect(document.documentElement).toHaveAttribute('data-theme', 'light');
  });
});
