import { useCallback, useEffect, useSyncExternalStore } from 'react';

export type ThemeName = 'light' | 'dark';

const STORAGE_KEY = 'pwdvault-theme';
const THEMES: ThemeName[] = ['light', 'dark'];

function getSystemPreference(): ThemeName {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function getSnapshot(): ThemeName {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (THEMES.includes(stored as ThemeName)) return stored as ThemeName;
  return getSystemPreference();
}

function getServerSnapshot(): ThemeName {
  return 'light';
}

function subscribe(callback: () => void): () => void {
  window.addEventListener('storage', callback);
  return () => window.removeEventListener('storage', callback);
}

function applyTheme(theme: ThemeName): void {
  const root = document.documentElement;
  root.classList.add('theme-transitioning');
  root.setAttribute('data-theme', theme);
  setTimeout(() => root.classList.remove('theme-transitioning'), 300);
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = useCallback((newTheme: ThemeName) => {
    localStorage.setItem(STORAGE_KEY, newTheme);
    applyTheme(newTheme);
    window.dispatchEvent(new StorageEvent('storage', { key: STORAGE_KEY }));
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(theme === 'light' ? 'dark' : 'light');
  }, [theme, setTheme]);

  return { theme, setTheme, toggleTheme, themes: THEMES };
}
