import { useTheme } from '../hooks/useTheme';

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  useTheme();
  return <>{children}</>;
}
