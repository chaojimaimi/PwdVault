/**
 * Clipboard utility with auto-clear timeout for secure password handling.
 * When a password is copied, it automatically clears from the clipboard
 * after the specified timeout (default: 30 seconds).
 *
 * M11: reads and writes prefer the Tauri clipboard plugin inside the desktop
 * app — navigator.clipboard is focus-gated, so the scheduled clear could
 * never run while the window was unfocused. Non-Tauri contexts (tests) keep
 * using navigator.clipboard.
 */

import {
	readText as pluginReadText,
	writeText as pluginWriteText,
} from '@tauri-apps/plugin-clipboard-manager';
import { isTauriEnvironment } from './environment';
import { showToast } from './toast';

const DEFAULT_TIMEOUT_MS = 30000; // 30 seconds
// Delay before the second (and final) clear attempt: clipboard access
// commonly fails transiently while the window is regaining focus.
const CLEAR_RETRY_DELAY_MS = 1000;

// A3: keep the pending clear timer at module level so a new copy cancels the
// previous timer. Without this, copying the same secret twice in a row let
// the FIRST timer fire early and wipe a secret the user just re-copied.
let activeClearTimer: ReturnType<typeof setTimeout> | null = null;
// The one-shot retry shares the same rule: a new copy cancels it.
let activeRetryTimer: ReturnType<typeof setTimeout> | null = null;

// M11: a failed auto-clear must be visible, not silent. The toast fires once
// per app run (module flag) so a persistently broken clipboard cannot spam
// the user; console.warn stays on for every failure.
let clearFailureNotified = false;

async function writeClipboard(text: string): Promise<void> {
	if (isTauriEnvironment()) {
		await pluginWriteText(text);
		return;
	}
	await navigator.clipboard.writeText(text);
}

async function readClipboard(): Promise<string> {
	if (isTauriEnvironment()) {
		return pluginReadText();
	}
	return navigator.clipboard.readText();
}

/**
 * Copy text to clipboard and auto-clear after timeout.
 *
 * @param text - The text to copy to clipboard
 * @param timeoutMs - Time in milliseconds before auto-clear (default: 30000)
 * @returns Promise that resolves when the text is copied
 */
export async function copyWithTimeout(
	text: string,
	timeoutMs: number = DEFAULT_TIMEOUT_MS
): Promise<void> {
	await writeClipboard(text);
	const expectedDigest = await digestText(text);

	// Reset the 30s window: the most recent copy owns the clear timer.
	if (activeClearTimer !== null) clearTimeout(activeClearTimer);
	if (activeRetryTimer !== null) clearTimeout(activeRetryTimer);

	activeClearTimer = setTimeout(() => {
		activeClearTimer = null;
		void clearClipboardAfterDelay(expectedDigest);
	}, timeoutMs);
}

/**
 * One clear attempt. Resolves true when finished (cleared, or the user
 * replaced the clipboard content — the digest guard intentionally leaves
 * foreign content alone), false only on a clipboard access error.
 */
async function attemptClear(expectedDigest: string): Promise<boolean> {
	try {
		const current = await readClipboard();
		// Only clear if the text hasn't been changed by the user
		if ((await digestText(current)) !== expectedDigest) {
			return true;
		}
		await writeClipboard('');
		return true;
	} catch {
		return false;
	}
}

async function clearClipboardAfterDelay(expectedDigest: string): Promise<void> {
	if (await attemptClear(expectedDigest)) return;

	// M11: retry once; if that also fails, surface it — a secret left on the
	// clipboard must never fail silently.
	activeRetryTimer = setTimeout(() => {
		activeRetryTimer = null;
		void (async () => {
			if (!(await attemptClear(expectedDigest))) {
				notifyClearFailure();
			}
		})();
	}, CLEAR_RETRY_DELAY_MS);
}

function notifyClearFailure(): void {
	console.warn(
		'PwdVault: clipboard auto-clear failed after retry — the copied secret may still be on the clipboard.'
	);
	if (clearFailureNotified) return;
	clearFailureNotified = true;
	showToast(
		'Clipboard auto-clear failed — the copied text may still be on the clipboard'
	);
}

async function digestText(text: string): Promise<string> {
	const bytes = new TextEncoder().encode(text);
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Copy text to clipboard without auto-clear.
 * Use this for non-sensitive data.
 *
 * @param text - The text to copy to clipboard
 * @returns Promise that resolves when the text is copied
 */
export async function copyWithoutClear(text: string): Promise<void> {
	await writeClipboard(text);
}
