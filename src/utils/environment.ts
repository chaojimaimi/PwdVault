/**
 * Shared runtime environment detection.
 *
 * Tauri injects `window.__TAURI_INTERNALS__` before any frontend code runs,
 * so its presence is the canonical "IPC is available" signal. Extracted from
 * the inline probe in src/api/vault.ts so clipboard.ts and future utilities
 * share one implementation instead of re-casting `window`.
 */
export function isTauriEnvironment(): boolean {
	return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}
