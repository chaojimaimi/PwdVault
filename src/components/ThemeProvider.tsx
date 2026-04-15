import { useEffect } from 'react';
import { useTheme } from '../hooks/useTheme';

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const { theme } = useTheme();

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.body.style.fontFamily =
      'var(--font-body)';
  }, [theme]);

  return <>{children}</>;
}
