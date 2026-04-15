import { useCallback, useSyncExternalStore } from 'react';

export type ThemeName = 'classic' | 'cyber' | 'hybrid';

const STORAGE_KEY = 'pwdvault-theme';
const THEMES: ThemeName[] = ['classic', 'cyber', 'hybrid'];

function getSnapshot(): ThemeName {
  const stored = localStorage.getItem(STORAGE_KEY);
  return (THEMES.includes(stored as ThemeName) ? stored : 'classic') as ThemeName;
}

function getServerSnapshot(): ThemeName {
  return 'classic';
}

function subscribe(callback: () => void): () => void {
  window.addEventListener('storage', callback);
  return () => window.removeEventListener('storage', callback);
}

function applyTheme(theme: ThemeName): void {
  const root = document.documentElement;
  root.classList.add('theme-transitioning');
  root.setAttribute('data-theme', theme);
  // Remove transition class after animation completes
  setTimeout(() => root.classList.remove('theme-transitioning'), 300);
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  const setTheme = useCallback((newTheme: ThemeName) => {
    localStorage.setItem(STORAGE_KEY, newTheme);
    applyTheme(newTheme);
    // Trigger re-render via storage event for other tabs
    window.dispatchEvent(new StorageEvent('storage', { key: STORAGE_KEY }));
  }, []);

  return { theme, setTheme, themes: THEMES };
}
