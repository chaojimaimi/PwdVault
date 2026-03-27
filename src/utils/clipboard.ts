/**
 * Clipboard utility with auto-clear timeout for secure password handling.
 * When a password is copied, it automatically clears from the clipboard
 * after the specified timeout (default: 30 seconds).
 */

const DEFAULT_TIMEOUT_MS = 30000; // 30 seconds

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
  await navigator.clipboard.writeText(text);

  setTimeout(async () => {
    try {
      const current = await navigator.clipboard.readText();
      // Only clear if the text hasn't been changed by the user
      if (current === text) {
        await navigator.clipboard.writeText('');
      }
    } catch {
      // Clipboard access denied or text already changed - silently ignore
      // This can happen if:
      // - The user has denied clipboard read permissions
      // - Another app has modified the clipboard
      // - The page is no longer focused
    }
  }, timeoutMs);
}

/**
 * Copy text to clipboard without auto-clear.
 * Use this for non-sensitive data.
 *
 * @param text - The text to copy to clipboard
 * @returns Promise that resolves when the text is copied
 */
export async function copyWithoutClear(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}
