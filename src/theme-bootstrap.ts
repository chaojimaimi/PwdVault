let stored: string | null = null;
try {
  stored = localStorage.getItem('pwdvault-theme');
} catch {
  // Storage can be unavailable in hardened WebViews; System remains safe.
}
const mode = stored === 'light' || stored === 'dark' || stored === 'system' ? stored : 'system';
const resolved = mode === 'system'
  ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
  : mode;

document.documentElement.dataset.theme = resolved;
document.documentElement.dataset.themeMode = mode;
document.documentElement.style.colorScheme = resolved;

const themeColor = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
if (themeColor) themeColor.content = resolved === 'dark' ? '#020203' : '#F8FAFC';

export {};
