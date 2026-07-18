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
		toastContainer = document.createElement("div");
		toastContainer.id = "toast-container";
		toastContainer.setAttribute("aria-live", "polite");
		toastContainer.setAttribute("aria-atomic", "false");
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
export function showToast(
	message: string,
	duration: number = TOAST_DURATION_MS,
): void {
	const container = ensureContainer();

	const toast = document.createElement("div");
	toast.className = "toast";
	toast.setAttribute("role", "status");
	toast.textContent = message;

	container.appendChild(toast);

	// Auto-remove after duration
	setTimeout(() => {
		toast.style.animation = "fadeOut 0.2s ease-out forwards";
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
	type: "info" | "success" | "error" = "info",
	duration: number = TOAST_DURATION_MS,
): void {
	const container = ensureContainer();

	const toast = document.createElement("div");
	toast.className = `toast toast-${type}`;
	toast.setAttribute("role", type === "error" ? "alert" : "status");
	toast.textContent = message;

	container.appendChild(toast);

	setTimeout(() => {
		toast.style.animation = "fadeOut 0.2s ease-out forwards";
		setTimeout(() => {
			if (toast.parentNode) {
				toast.parentNode.removeChild(toast);
			}
		}, 200);
	}, duration);
}

/**
 * Show a pairing-code toast with a large code, countdown progress bar,
 * and an OK button to dismiss early. Auto-dismisses after `duration`.
 *
 * Styling follows the V4 "neon" design adapted to both light and dark app
 * themes via CSS variables (see `.pairing-toast` in components.css). The
 * toast automatically switches colors when `<html data-theme>` changes.
 *
 * @param code - The 6-digit pairing code to display
 * @param duration - Duration in milliseconds (default: 30000, kept in sync
 *                   with the backend SESSION_TTL)
 */
export function showPairingCodeToast(
	code: string,
	duration: number = 30000,
): void {
	const container = ensureContainer();

	// Dismiss any existing pairing toast to avoid stacking.
	container.querySelectorAll(".pairing-toast").forEach((el) => el.remove());

	const toast = document.createElement("div");
	toast.className = "toast pairing-toast";
	toast.setAttribute("role", "status");

	// Format code as "XXX XXX" for readability.
	const formatted =
		code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;

	// Build the toast DOM without innerHTML for the code value (VULN-001).
	// The static parts use innerHTML (trusted markup), but the pairing code
	// — the only externally-derived value — is set via textContent.
	toast.innerHTML = `
    <div class="pairing-toast-head">
      <div class="pairing-toast-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
      </div>
      <div class="pairing-toast-title">浏览器扩展配对</div>
      <button class="pairing-toast-close" type="button" aria-label="关闭">×</button>
    </div>
    <div class="pairing-toast-body">
      <div class="pairing-toast-label">请在扩展弹窗中输入此配对码</div>
      <div class="pairing-toast-code"></div>
    </div>
    <div class="pairing-toast-progress">
      <div class="pairing-toast-progress-bar"></div>
    </div>
  `;

	// Set the pairing code via textContent to prevent XSS (CWE-79).
	// Even though the current code is always 6 digits, this is defense-in-depth.
	const codeEl = toast.querySelector<HTMLDivElement>(".pairing-toast-code");
	if (codeEl) codeEl.textContent = formatted;

	container.appendChild(toast);

	// Animate the progress bar from 100% → 0% over `duration`.
	const bar = toast.querySelector<HTMLDivElement>(
		".pairing-toast-progress-bar",
	);
	if (bar) {
		// Force a reflow so the transition runs from the initial 100% width.
		void bar.offsetWidth;
		bar.style.transition = `width ${duration}ms linear`;
		bar.style.width = "0%";
	}

	// OK / close button dismisses immediately.
	const closeBtn = toast.querySelector<HTMLButtonElement>(
		".pairing-toast-close",
	);
	const dismiss = () => {
		if (!toast.parentNode) return;
		toast.style.animation = "fadeOut 0.2s ease-out forwards";
		setTimeout(() => {
			if (toast.parentNode) toast.parentNode.removeChild(toast);
		}, 200);
	};
	if (closeBtn) closeBtn.onclick = dismiss;

	// Auto-dismiss after duration.
	setTimeout(dismiss, duration);
}
