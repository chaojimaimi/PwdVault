import { useCallback, useEffect, useSyncExternalStore } from 'react';

export type ThemeName = 'system' | 'light' | 'dark';

const STORAGE_KEY = 'pwdvault-theme';
const THEMES: ThemeName[] = ['system', 'light', 'dark'];
let sessionTheme: ThemeName | null = null;

function getSystemPreference(): 'light' | 'dark' {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function getSnapshot(): ThemeName {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (THEMES.includes(stored as ThemeName)) return stored as ThemeName;
  } catch {
    // Fall through to System when storage is unavailable.
  }
  return sessionTheme ?? 'system';
}

function getServerSnapshot(): ThemeName {
  return 'system';
}

function subscribe(callback: () => void): () => void {
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  const notify = () => {
    if (getSnapshot() === 'system') applyTheme('system');
    callback();
  };
  window.addEventListener('storage', notify);
  media.addEventListener('change', notify);
  return () => {
    window.removeEventListener('storage', notify);
    media.removeEventListener('change', notify);
  };
}

function resolveTheme(theme: ThemeName): 'light' | 'dark' {
  return theme === 'system' ? getSystemPreference() : theme;
}

function applyTheme(theme: ThemeName): void {
  const resolved = resolveTheme(theme);
  const root = document.documentElement;
  root.classList.add('theme-transitioning');
  root.setAttribute('data-theme', resolved);
  root.setAttribute('data-theme-mode', theme);
  root.style.colorScheme = resolved;
  const themeColor = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  if (themeColor) themeColor.content = resolved === 'dark' ? '#020203' : '#F8FAFC';
  setTimeout(() => root.classList.remove('theme-transitioning'), 300);
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = useCallback((newTheme: ThemeName) => {
    sessionTheme = newTheme;
    try {
      localStorage.setItem(STORAGE_KEY, newTheme);
    } catch {
      // The selected theme still applies for the current session.
    }
    applyTheme(newTheme);
    window.dispatchEvent(new StorageEvent('storage', { key: STORAGE_KEY }));
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(resolveTheme(theme) === 'light' ? 'dark' : 'light');
  }, [theme, setTheme]);

  return { theme, resolvedTheme: resolveTheme(theme), setTheme, toggleTheme, themes: THEMES };
}
