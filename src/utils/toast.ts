/**
 * Simple toast notification system for the desktop app.
 * Creates and manages toast notifications that auto-dismiss.
 */

const TOAST_DURATION_MS = 3000; // 3 seconds

let toastContainer: HTMLDivElement | null = null;

/**
 * Ensure the toast container exists in the DOM.
 */
function ensureContainer(): HTMLDivElement {
  if (!toastContainer || !document.body.contains(toastContainer)) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'toast-container';
    document.body.appendChild(toastContainer);
  }
  return toastContainer;
}

/**
 * Show a toast notification.
 *
 * @param message - The message to display
 * @param duration - Duration in milliseconds (default: 3000)
 */
export function showToast(message: string, duration: number = TOAST_DURATION_MS): void {
  const container = ensureContainer();

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;

  container.appendChild(toast);

  // Auto-remove after duration
  setTimeout(() => {
    toast.style.animation = 'fadeOut 0.2s ease-out forwards';
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 200);
  }, duration);
}

/**
 * Show a toast with a custom type (for future styling extensions).
 *
 * @param message - The message to display
 * @param type - The type of toast (info, success, error)
 * @param duration - Duration in milliseconds (default: 3000)
 */
export function showToastWithType(
  message: string,
  type: 'info' | 'success' | 'error' = 'info',
  duration: number = TOAST_DURATION_MS
): void {
  const container = ensureContainer();

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = 'fadeOut 0.2s ease-out forwards';
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 200);
  }, duration);
}
