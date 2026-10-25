// PwdVault Content Script
// Detects login forms and handles auto-fill

// === VERBATIM COPY: entryMatchesPageUrl from src/sender-auth.js ===
// Content scripts are classic scripts and cannot import ES modules (a dynamic
// import would require web_accessible_resources = manifest change + fingerprint
// surface). Keep this copy byte-identical to sender-auth.js — the guard test
// in sender-auth.test.js fails when the two drift apart. Hoisted, so the IIFE
// below can use it.
function entryMatchesPageUrl(entryUrl, pageUrl) {
  // Empty entryUrl = generic entry (no stored URL); an explicit popup fill is
  // a deliberate user action, so allow it. Empty pageUrl = cannot judge.
  if (!entryUrl) return true;
  if (!pageUrl) return false;
  // Entries are often stored scheme-less ("github.com/acme"); pad https://
  // exactly like popup.js formatUrl before parsing, otherwise such entries
  // would be rejected here despite being fillable nowhere else.
  const withScheme = /^https?:\/\//i.test(entryUrl)
    ? entryUrl
    : `https://${entryUrl}`;
  const entryDomain = normalizedDomain(withScheme);
  const pageDomain = normalizedDomain(pageUrl);
  // A parse failure yields null (cannot judge) → reject.
  return Boolean(entryDomain && pageDomain && entryDomain === pageDomain);
}

// Verbatim copy of the normalizedDomain helper from sender-auth.js — the
// copied predicate above calls it. Keep in sync with sender-auth.js.
function normalizedDomain(rawUrl) {
	try {
		return new URL(rawUrl).hostname.toLowerCase().replace(/^www\./, "");
	} catch {
		return null;
	}
}

(function () {
	"use strict";

	// ============================================================================
	// Form Detection
	// ============================================================================

	const PASSWORD_INPUT_TYPES = ["password", "text", "email"];
	const USERNAME_INPUT_TYPES = ["text", "email", "tel"];
	const USERNAME_PATTERNS = [
		/user/i,
		/login/i,
		/email/i,
		/e-mail/i,
		/account/i,
		/identifier/i,
		/username/i,
		/name$/i,
		/^log$/i,
		/auth/i,
	];
	const PASSWORD_PATTERNS = [/pass/i, /pwd/i, /secret/i, /credential/i];
	const SUBMIT_PATTERNS = [
		/login/i,
		/sign.?in/i,
		/log.?in/i,
		/submit/i,
		/enter/i,
		/continue/i,
		/next/i,
		/auth/i,
		/go/i,
	];
	// Patterns for registration/change password forms. Deliberately narrow
	// ("create an account", "join now") — bare /create/i and /join/i matched
	// ordinary login pages ("Sign in or create a workspace") and mislabelled
	// them as register forms.
	const REGISTER_PATTERNS = [
		/register/i,
		/sign.?up/i,
		/create\s+(an\s+)?account/i,
		/join\s+now/i,
		/new.?account/i,
	];
	const CHANGE_PASSWORD_PATTERNS = [
		/change.?pass/i,
		/update.?pass/i,
		/new.?pass/i,
		/reset.?pass/i,
		/current.?pass/i,
		/old.?pass/i,
		/confirm.?pass/i,
	];

	// Form types
	const FORM_TYPES = {
		LOGIN: "login",
		REGISTER: "register",
		CHANGE_PASSWORD: "changePassword",
		UNKNOWN: "unknown",
	};

	function detectFormType(container, passwordInput) {
		// Hard signal: autocomplete="new-password" marks a registration or
		// account-creation field by author intent and outranks the text
		// heuristics below (a login page's "create an account" link must not
		// misclassify a form whose password field is explicitly a new one).
		const autocomplete = (
			passwordInput?.getAttribute("autocomplete") || ""
		).toLowerCase();
		if (autocomplete === "new-password") {
			return FORM_TYPES.REGISTER;
		}

		const text = container.textContent || "";
		const formAction = (container.getAttribute("action") || "").toLowerCase();

		if (REGISTER_PATTERNS.some((p) => p.test(text) || p.test(formAction))) {
			return FORM_TYPES.REGISTER;
		}
		if (
			CHANGE_PASSWORD_PATTERNS.some((p) => p.test(text) || p.test(formAction))
		) {
			return FORM_TYPES.CHANGE_PASSWORD;
		}
		return FORM_TYPES.LOGIN;
	}

	// Pick the login password field from every password input on the page:
	// 1. autocomplete="current-password" wins outright;
	// 2. a single password field is unambiguous — take it;
	// 3. multiple unlabelled fields (register / change-password layouts) fall
	//    back to the first, with the formType gate deciding whether any
	//    automatic fill is allowed.
	function selectPasswordField(passwordInputs) {
		const explicit = passwordInputs.find(
			(input) =>
				(input.getAttribute("autocomplete") || "").toLowerCase() ===
				"current-password",
		);
		return explicit || passwordInputs[0];
	}

	function findLoginForm() {
		const passwordInputs = Array.from(
			document.querySelectorAll('input[type="password"]'),
		);

		if (passwordInputs.length === 0) {
			return null;
		}

		const passwordInput = selectPasswordField(passwordInputs);

		const form = passwordInput.closest("form");
		const container =
			form || passwordInput.closest("div, section, article") || document.body;

		// Detect form type — the chosen password field carries the
		// autocomplete hard signal into the classifier.
		const formType = detectFormType(container, passwordInput);

		// Look for username field
		const textInputs = Array.from(container.querySelectorAll("input")).filter(
			(input) =>
				USERNAME_INPUT_TYPES.includes(input.type) && input !== passwordInput,
		);

		// Sort by position (above the password field)
		const passwordRect = passwordInput.getBoundingClientRect();

		const usernameCandidates = textInputs.filter((input) => {
			const rect = input.getBoundingClientRect();
			return rect.top < passwordRect.top + 50; // Within 50px above
		});

		// Score by patterns
		let usernameField = null;
		let bestScore = -1;

		for (const input of usernameCandidates) {
			const score = scoreInput(input, USERNAME_PATTERNS);
			if (score > bestScore) {
				bestScore = score;
				usernameField = input;
			}
		}

		// Find submit button
		const submitButton = findSubmitButton(container);

		return {
			passwordField: passwordInput,
			usernameField,
			submitButton,
			form,
			formType,
			container,
		};
	}

	function scoreInput(input, patterns) {
		let score = 0;

		const name = input.name || "";
		const id = input.id || "";
		const placeholder = input.placeholder || "";
		const ariaLabel = input.getAttribute("aria-label") || "";
		const label = findLabelForInput(input);
		const dataTestid = input.getAttribute("data-testid") || "";

		const text =
			`${name} ${id} ${placeholder} ${ariaLabel} ${label} ${dataTestid}`.toLowerCase();

		for (const pattern of patterns) {
			if (pattern.test(text)) {
				score += 10;
			}
		}

		// Bonus for autocomplete attributes
		const autocomplete = input.getAttribute("autocomplete") || "";
		if (patterns.some((p) => p.test(autocomplete))) {
			score += 5;
		}

		// Bonus for specific autocomplete values
		if (autocomplete === "username" || autocomplete === "email") {
			score += 15;
		}

		// Bonus for autofocus
		if (input.hasAttribute("autofocus")) {
			score += 5;
		}

		return score;
	}

	function findLabelForInput(input) {
		// Check for label with 'for' attribute
		if (input.id) {
			const label = document.querySelector(`label[for="${input.id}"]`);
			if (label) return label.textContent || "";
		}

		// Check for parent label
		const parentLabel = input.closest("label");
		if (parentLabel) {
			return parentLabel.textContent || "";
		}

		// Check for aria-labelledby
		const labelledBy = input.getAttribute("aria-labelledby");
		if (labelledBy) {
			const labelEl = document.getElementById(labelledBy);
			if (labelEl) return labelEl.textContent || "";
		}

		return "";
	}

	function findSubmitButton(container) {
		const buttons = Array.from(
			container.querySelectorAll(
				'button, input[type="submit"], input[type="button"], [role="button"]',
			),
		);

		// First try to find by patterns
		for (const button of buttons) {
			const text = (
				button.textContent ||
				button.value ||
				button.getAttribute("aria-label") ||
				""
			).toLowerCase();
			for (const pattern of SUBMIT_PATTERNS) {
				if (pattern.test(text)) {
					return button;
				}
			}
		}

		// Fall back to first submit button
		const submitBtn = container.querySelector(
			'button[type="submit"], input[type="submit"]',
		);
		if (submitBtn) return submitBtn;

		return null;
	}

	// ============================================================================
	// Auto-fill
	// ============================================================================

	function fillField(field, value) {
		if (!field) return false;

		// Focus the field
		field.focus();

		// Clear existing value
		field.value = "";

		// Set new value using native setter
		const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
			window.HTMLInputElement.prototype,
			"value",
		).set;
		nativeInputValueSetter.call(field, value);

		// Dispatch events to trigger validation
		field.dispatchEvent(new Event("input", { bubbles: true }));
		field.dispatchEvent(new Event("change", { bubbles: true }));
		field.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true }));
		field.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));

		// Highlight the field briefly
		highlightField(field);

		return true;
	}

	function highlightField(field) {
		const originalOutline = field.style.outline;
		const originalTransition = field.style.transition;

		field.style.transition = "outline 0.15s ease-out";
		field.style.outline = "2px solid #16a34a";

		setTimeout(() => {
			field.style.outline = originalOutline;
			setTimeout(() => {
				field.style.transition = originalTransition;
			}, 150);
		}, 300);
	}

	function autofillLogin(username, password) {
		// SF-P1 defense in depth: an empty password must never reach the form.
		// The background and popup guard their own paths, but a future caller
		// that forgets would otherwise fill a blank credential and still get
		// the "filled successfully" toast.
		if (!password) {
			showNotification("No password received — fill cancelled", "error");
			return false;
		}

		const loginForm = findLoginForm();

		if (!loginForm) {
			showNotification("No login form detected on this page", "error");
			return false;
		}

		// Fill username
		if (loginForm.usernameField) {
			fillField(loginForm.usernameField, username);
		}

		// Fill password
		fillField(loginForm.passwordField, password);

		showNotification("Credentials filled successfully", "success");

		// Focus submit button if available
		if (loginForm.submitButton) {
			loginForm.submitButton.focus();
		}

		return true;
	}

	function insertPassword(password) {
		const activeElement = document.activeElement;

		if (activeElement && activeElement.tagName === "INPUT") {
			fillField(activeElement, password);
			showNotification("Password inserted", "success");
			return true;
		}

		showNotification("Please focus on a password field first", "error");
		return false;
	}

	// ============================================================================
	// Clipboard with auto-clear
	// ============================================================================

	// Handle of the pending clear timer. Copying again cancels the previous
	// timer so the 30s window restarts from the most recent copy instead of an
	// old timer wiping the fresh value early.
	let activeClearTimer = null;
	// SF-P2a: most sites deny the timer-context clipboard read, so the
	// auto-clear failure is the common case — notify once per page, not per copy.
	let clipboardClearFailureNotified = false;

	async function digestText(text) {
		const bytes = new TextEncoder().encode(text);
		const digest = await crypto.subtle.digest("SHA-256", bytes);
		return Array.from(new Uint8Array(digest), (byte) =>
			byte.toString(16).padStart(2, "0"),
		).join("");
	}

	async function copyWithTimeout(text, timeoutMs = 30000) {
		try {
			await navigator.clipboard.writeText(text);

			if (activeClearTimer) clearTimeout(activeClearTimer);
			// Compare digests instead of plaintext so the copied secret never
			// lingers in a closure (same approach as the popup script).
			const expectedDigest = await digestText(text);
			activeClearTimer = setTimeout(async () => {
				try {
					const current = await navigator.clipboard.readText();
					if ((await digestText(current)) === expectedDigest) {
						await navigator.clipboard.writeText("");
					}
				} catch (e) {
					// Clipboard access denied or text already changed. SF-P2a: a
					// failed auto-clear must not be invisible — warn and tell the
					// user to clear manually (showNotification is hoisted in this
					// IIFE and safe from a timer callback). The digest guard
					// above keeps "already changed" silent; only real failures
					// notify, and just once (see clipboardClearFailureNotified).
					console.warn("clipboard auto-clear failed", e);
					if (!clipboardClearFailureNotified) {
						clipboardClearFailureNotified = true;
						showNotification(
							"Clipboard auto-clear failed — please clear it manually",
							"error",
						);
					}
				}
			}, timeoutMs);

			return true;
		} catch {
			return false;
		}
	}

	// ============================================================================
	// Shadow DOM mounting (style isolation)
	// ============================================================================

	// One shared stylesheet injected into every shadow root. A shadow tree
	// cannot read the host page's CSS custom properties, so the design tokens
	// are pinned in the :host block below — they mirror the desktop Light
	// theme (src/styles/themes.css); resync both when the palette changes.
	// The four @keyframes live here too: shadow-scoped, so the page can neither
	// clobber nor reuse them.
	const SHADOW_CSS = `
    :host {
      /* Design tokens — mirror of the desktop Light theme (themes.css). */
      --pv-primary: #1E3A5F;
      --pv-primary-hover: #153050;
      --pv-accent: #0D9488;
      --pv-success: #059669;
      --pv-danger: #DC2626;
      --pv-bg: #F8FAFC;
      --pv-surface: #FFFFFF;
      --pv-input: #EDEEF2;
      --pv-text: #0F172A;
      --pv-text-secondary: #475569;
      --pv-text-muted: #5B6B80;
      --pv-border: rgba(0, 0, 0, 0.06);
      --pv-border-strong: rgba(0, 0, 0, 0.10);
      /* Cut inheritance from the host element so a page rule targeting our
         wrapper div cannot restyle the widgets through inheritable
         properties. Custom properties survive the all shorthand, and the
         two declarations below re-pin what the widgets rely on. */
      all: initial;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: var(--pv-text);
    }

    /* --- Auto-fill prompt bar (position/z-index live on the host) --- */
    #pwdvault-autofill-bar {
      width: 100%;
      background: var(--pv-surface);
      padding: 12px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 14px;
      color: var(--pv-text);
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15);
      animation: slideDown 0.3s ease-out;
    }
    @keyframes slideDown {
      from { transform: translateY(-100%); }
      to { transform: translateY(0); }
    }
    #pwdvault-autofill-bar .pv-bar-content {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    #pwdvault-autofill-bar .pv-icon {
      width: 28px;
      height: 28px;
      background: var(--pv-primary);
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 600;
      color: #fff;
      font-size: 12px;
    }
    #pwdvault-autofill-bar .pv-text {
      display: flex;
      flex-direction: column;
    }
    #pwdvault-autofill-bar .pv-title {
      font-weight: 500;
    }
    #pwdvault-autofill-bar .pv-subtitle {
      font-size: 12px;
      color: var(--pv-text-muted);
    }
    #pwdvault-autofill-bar .pv-error {
      font-size: 12px;
      color: var(--pv-danger);
    }
    #pwdvault-autofill-bar .pv-actions {
      display: flex;
      gap: 8px;
    }
    #pwdvault-autofill-bar .pv-btn {
      padding: 8px 16px;
      border-radius: 6px;
      border: none;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      font-family: inherit;
    }
    #pwdvault-autofill-bar .pv-btn-primary {
      background: var(--pv-primary);
      color: #fff;
    }
    #pwdvault-autofill-bar .pv-btn-primary:hover {
      background: var(--pv-primary-hover);
    }
    #pwdvault-autofill-bar .pv-btn-secondary {
      background: var(--pv-input);
      color: var(--pv-text-secondary);
    }
    #pwdvault-autofill-bar .pv-btn-secondary:hover {
      background: var(--pv-border-strong);
      color: var(--pv-text);
    }

    /* --- Overlay (backdrop fills the fixed host) --- */
    #pwdvault-overlay {
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: flex-start;
      justify-content: center;
      padding-top: 100px;
      font-size: 14px;
      color: var(--pv-text);
      animation: fadeIn 0.2s ease-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    #pwdvault-modal {
      background: var(--pv-surface);
      border-radius: 12px;
      padding: 20px;
      min-width: 320px;
      max-width: 400px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      color: var(--pv-text);
    }
    #pwdvault-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }
    #pwdvault-header h3 {
      font-size: 16px;
      font-weight: 600;
      margin: 0;
    }
    #pwdvault-close {
      background: none;
      border: none;
      color: var(--pv-text-muted);
      font-size: 20px;
      cursor: pointer;
      padding: 4px;
      font-family: inherit;
    }
    #pwdvault-close:hover {
      color: var(--pv-text);
    }
    #pwdvault-search {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid var(--pv-border-strong);
      border-radius: 8px;
      background: var(--pv-input);
      color: var(--pv-text);
      font-size: 14px;
      margin-bottom: 12px;
      box-sizing: border-box;
      font-family: inherit;
    }
    #pwdvault-search:focus {
      outline: none;
      border-color: var(--pv-primary);
    }
    #pwdvault-list {
      max-height: 280px;
      overflow-y: auto;
    }
    .pwdvault-item {
      display: flex;
      align-items: center;
      padding: 12px;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.2s;
    }
    .pwdvault-item:hover {
      background: var(--pv-input);
    }
    .pwdvault-icon {
      width: 36px;
      height: 36px;
      border-radius: 8px;
      background: var(--pv-primary);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 600;
      color: #fff;
      margin-right: 12px;
      text-transform: uppercase;
      flex-shrink: 0;
    }
    .pwdvault-info {
      flex: 1;
      min-width: 0;
    }
    .pwdvault-info h4 {
      font-size: 14px;
      font-weight: 500;
      margin: 0 0 4px 0;
    }
    .pwdvault-info p {
      font-size: 12px;
      color: var(--pv-text-muted);
      margin: 0;
    }
    .pwdvault-item-actions {
      display: flex;
      gap: 4px;
      opacity: 0;
      transition: opacity 0.2s;
    }
    .pwdvault-item:hover .pwdvault-item-actions {
      opacity: 1;
    }
    .pwdvault-action-btn {
      width: 28px;
      height: 28px;
      border-radius: 6px;
      border: none;
      background: var(--pv-input);
      color: var(--pv-text-muted);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s;
    }
    .pwdvault-action-btn:hover {
      background: var(--pv-border-strong);
      color: var(--pv-text);
    }
    .pwdvault-action-btn svg {
      width: 14px;
      height: 14px;
    }
    #pwdvault-empty {
      text-align: center;
      padding: 32px 16px;
      color: var(--pv-text-muted);
    }
    #pwdvault-status {
      text-align: center;
      padding: 32px 16px;
    }
    #pwdvault-status.error {
      color: var(--pv-danger);
    }

    /* --- Toast (bottom-right; position lives on the host) --- */
    #pwdvault-notification {
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 14px;
      animation: slideIn 0.3s ease-out;
      color: #fff;
    }
    #pwdvault-notification.error { background: var(--pv-danger); }
    #pwdvault-notification.success { background: var(--pv-success); }
    #pwdvault-notification.info { background: var(--pv-primary); }
    @keyframes slideIn {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    /* --- Floating button (position/top live on the host) --- */
    #pwdvault-floating-btn {
      position: relative;
      width: 40px;
      height: 40px;
      background: linear-gradient(135deg, var(--pv-primary) 0%, var(--pv-accent) 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      box-shadow: 0 2px 8px rgba(30, 58, 95, 0.4);
      transition: transform 0.2s, opacity 0.3s;
      animation: fadeInFloat 0.3s ease-out;
      opacity: 0;
    }
    @keyframes fadeInFloat {
      from { opacity: 0; transform: scale(0.8); }
      to { opacity: 1; transform: scale(1); }
    }
    #pwdvault-floating-btn:hover {
      transform: scale(1.1);
    }
    #pwdvault-floating-btn svg {
      width: 20px;
      height: 20px;
      fill: white;
    }
    #pwdvault-badge {
      position: absolute;
      top: -4px;
      right: -4px;
      min-width: 18px;
      height: 18px;
      background: var(--pv-success);
      border-radius: 9px;
      font-size: 11px;
      font-weight: 600;
      color: white;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0 4px;
      display: none;
    }
  `;

	// Creates a position:fixed host element carrying one closed shadow root
	// pre-seeded with the shared stylesheet. `hostCss` holds the positioning
	// that used to live on the injected roots (inline styles beat page CSS,
	// so the page cannot move or unstack the widgets). closed mode keeps the
	// page from reaching the root via el.shadowRoot — this script only ever
	// uses the reference returned here.
	function mountShadowHost(hostCss) {
		const host = document.createElement("div");
		host.style.cssText = hostCss;
		const shadowRoot = host.attachShadow({ mode: "closed" });
		const style = document.createElement("style");
		style.textContent = SHADOW_CSS;
		shadowRoot.appendChild(style);
		return { host, shadowRoot };
	}

	// ============================================================================
	// Notification Bar (for auto-fill prompt)
	// ============================================================================

	let notificationBar = null;
	let notificationBarShadow = null;

	// Renders an error inside the existing prompt bar without dismissing it,
	// so the user can retry Fill after e.g. unlocking the vault.
	function showAutoFillPromptError(message) {
		if (!notificationBarShadow) return;
		const text = notificationBarShadow.querySelector(".pv-text");
		if (!text) return;

		let errorEl = notificationBarShadow.querySelector(".pv-error");
		if (!errorEl) {
			errorEl = document.createElement("span");
			errorEl.className = "pv-error";
			text.appendChild(errorEl);
		}
		errorEl.textContent = message;
	}

	// entry is a summary (id/title/username) — never a decrypted entry.
	function showAutoFillPrompt(entry) {
		hideNotificationBar();

		const { host, shadowRoot } = mountShadowHost(
			"position: fixed; top: 0; left: 0; right: 0; z-index: 2147483646;",
		);

		const bar = document.createElement("div");
		bar.id = "pwdvault-autofill-bar";

		const barContent = document.createElement("div");
		barContent.className = "pv-bar-content";

		const icon = document.createElement("div");
		icon.className = "pv-icon";
		icon.textContent = entry.title.charAt(0).toUpperCase();
		barContent.appendChild(icon);

		const text = document.createElement("div");
		text.className = "pv-text";
		const titleSpan = document.createElement("span");
		titleSpan.className = "pv-title";
		titleSpan.textContent = "Fill credentials for " + entry.title + "?";
		text.appendChild(titleSpan);
		const subtitleSpan = document.createElement("span");
		subtitleSpan.className = "pv-subtitle";
		subtitleSpan.textContent = entry.username;
		text.appendChild(subtitleSpan);
		barContent.appendChild(text);

		bar.appendChild(barContent);

		const actions = document.createElement("div");
		actions.className = "pv-actions";

		const dismissBtn = document.createElement("button");
		dismissBtn.className = "pv-btn pv-btn-secondary";
		dismissBtn.id = "pv-dismiss";
		dismissBtn.textContent = "Dismiss";
		actions.appendChild(dismissBtn);

		const fillBtn = document.createElement("button");
		fillBtn.className = "pv-btn pv-btn-primary";
		fillBtn.id = "pv-fill";
		fillBtn.textContent = "Fill";
		actions.appendChild(fillBtn);

		bar.appendChild(actions);

		// The bar only ever receives an entry summary (title/username, no
		// password). The secret is fetched here, at click time, through the
		// background's URL-scoped gate, and dropped after autofill — so a page
		// load never pulls plaintext credentials into the content script.
		bar.querySelector("#pv-fill").addEventListener("click", async (e) => {
			// Synthetic events dispatched by page scripts must never pull
			// credentials (isTrusted is false for script-made events).
			if (!e.isTrusted) return;
			const fillBtn = shadowRoot.querySelector("#pv-fill");
			if (fillBtn) fillBtn.disabled = true;

			try {
				const full = await chrome.runtime.sendMessage({
					type: "GET_ENTRY",
					id: entry.id,
				});

				if (!full || full.error) {
					showAutoFillPromptError(
						full && full.error && /lock/i.test(full.error)
							? "Vault is locked — unlock PwdVault and try again"
							: (full && full.error) ||
									"Failed to fetch the entry. Try again.",
					);
					return;
				}

				hideNotificationBar();
				autofillLogin(full.username, full.password);
			} catch (error) {
				const message = error && error.message ? error.message : "";
				showAutoFillPromptError(
					/lock/i.test(message)
						? "Vault is locked — unlock PwdVault and try again"
						: "Failed to fetch the entry. Try again.",
				);
			} finally {
				// No-op once the bar is hidden; keeps Fill usable after an error.
				if (fillBtn && notificationBarShadow) fillBtn.disabled = false;
			}
		});

		bar.querySelector("#pv-dismiss").addEventListener("click", () => {
			hideNotificationBar();
		});

		notificationBar = host;
		notificationBarShadow = shadowRoot;
		document.body.appendChild(host);

		// Auto-dismiss after 10 seconds
		setTimeout(() => {
			hideNotificationBar();
		}, 10000);
	}

	function hideNotificationBar() {
		if (notificationBar && notificationBar.parentNode) {
			notificationBar.parentNode.removeChild(notificationBar);
			notificationBar = null;
			notificationBarShadow = null;
		}
	}

	// ============================================================================
	// UI Overlay
	// ============================================================================

	let overlay = null;
	let overlayShadow = null;
	let cachedEntries = null;

	function createOverlay() {
		if (overlay) return overlay;

		const { host, shadowRoot } = mountShadowHost(
			"position: fixed; top: 0; left: 0; right: 0; bottom: 0; z-index: 2147483647;",
		);

		// The backdrop fills the fixed host; the modal is centered by the
		// backdrop's flex layout. Created once and re-shown by showOverlay.
		const backdrop = document.createElement("div");
		backdrop.id = "pwdvault-overlay";
		backdrop.innerHTML = `
      <div id="pwdvault-modal">
        <div id="pwdvault-header">
          <h3>PwdVault</h3>
          <button id="pwdvault-close">x</button>
        </div>
        <input id="pwdvault-search" type="text" placeholder="Search passwords...">
        <div id="pwdvault-content"></div>
      </div>
    `;
		shadowRoot.appendChild(backdrop);

		backdrop
			.querySelector("#pwdvault-close")
			.addEventListener("click", hideOverlay);
		// Listener on the backdrop (inside the shadow tree): e.target is the
		// real inner element here, so only clicks on the scrim itself close.
		backdrop.addEventListener("click", (e) => {
			if (e.target === backdrop) hideOverlay();
		});

		// Keyboard shortcut to close (bubbles up from the search input)
		backdrop.addEventListener("keydown", (e) => {
			if (e.key === "Escape") hideOverlay();
		});

		overlay = host;
		overlayShadow = shadowRoot;
		return host;
	}

	function showOverlay() {
		const overlayEl = createOverlay();
		document.body.appendChild(overlayEl);
		loadEntries();
		overlayShadow.querySelector("#pwdvault-search").focus();
	}

	function hideOverlay() {
		if (overlay && overlay.parentNode) {
			overlay.parentNode.removeChild(overlay);
		}
	}

	async function loadEntries() {
		const content = overlayShadow.querySelector("#pwdvault-content");

		try {
			const response = await chrome.runtime.sendMessage({
				type: "GET_ENTRIES_FOR_URL",
				url: window.location.href,
			});

			if (response.error) {
				content.innerHTML = "";
				const statusEl = document.createElement("div");
				statusEl.id = "pwdvault-status";
				statusEl.className = "error";
				// textContent never parses markup — no escaping wanted (a plain
				// escapeHtml here would show literal &amp; entities).
				statusEl.textContent = response.error;
				content.appendChild(statusEl);
				return;
			}

			cachedEntries = response;
			renderEntries(response);
		} catch (error) {
			content.innerHTML = "";
			const statusEl = document.createElement("div");
			statusEl.id = "pwdvault-status";
			statusEl.className = "error";
			statusEl.textContent =
				"Failed to load entries: " + (error.message || "Unknown error");
			content.appendChild(statusEl);
		}
	}

	function renderEntries(entries) {
		const content = overlayShadow.querySelector("#pwdvault-content");

		if (!entries || entries.length === 0) {
			content.innerHTML = "";
			const emptyEl = document.createElement("div");
			emptyEl.id = "pwdvault-empty";
			emptyEl.textContent = "No passwords found for this site";
			content.appendChild(emptyEl);
			return;
		}

		const list = document.createElement("div");
		list.id = "pwdvault-list";

		entries.forEach((entry) => {
			const item = document.createElement("div");
			item.className = "pwdvault-item";

			const icon = document.createElement("div");
			icon.className = "pwdvault-icon";
			// Use first character safely - textContent is safe
			icon.textContent = entry.title ? entry.title.charAt(0) : "?";

			const info = document.createElement("div");
			info.className = "pwdvault-info";
			const h4 = document.createElement("h4");
			h4.textContent = entry.title || "Untitled";
			const p = document.createElement("p");
			p.textContent = entry.username || "No username";
			info.appendChild(h4);
			info.appendChild(p);

			const actionsDiv = document.createElement("div");
			actionsDiv.className = "pwdvault-item-actions";

			const copyBtn = document.createElement("button");
			copyBtn.className = "pwdvault-action-btn";
			copyBtn.setAttribute("data-action", "copy");
			// setAttribute is assignment, not parsing — the raw ID is safe here.
			copyBtn.setAttribute("data-id", entry.id);
			copyBtn.title = "Copy password";
			copyBtn.innerHTML =
				'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
			actionsDiv.appendChild(copyBtn);

			item.appendChild(icon);
			item.appendChild(info);
			item.appendChild(actionsDiv);

			// Click to fill
			item.addEventListener("click", (e) => {
				// Synthetic click guard: selectEntry pulls the entry's secret.
				if (!e.isTrusted) return;
				if (!e.target.closest(".pwdvault-action-btn")) {
					selectEntry(entry.id);
				}
			});

			// Copy button
			copyBtn.addEventListener("click", async (e) => {
				// Synthetic click guard: copyEntryPassword pulls the secret.
				if (!e.isTrusted) return;
				e.stopPropagation();
				await copyEntryPassword(entry.id);
			});

			list.appendChild(item);
		});

		content.innerHTML = "";
		content.appendChild(list);

		// Setup search
		const searchInput = overlayShadow.querySelector("#pwdvault-search");
		searchInput.oninput = () => filterEntries(entries, searchInput.value);
	}

	function filterEntries(entries, query) {
		const lowerQuery = query.toLowerCase();
		const filtered = entries.filter(
			(entry) =>
				entry.title.toLowerCase().includes(lowerQuery) ||
				entry.username.toLowerCase().includes(lowerQuery),
		);
		renderEntries(filtered);
	}

	async function selectEntry(id) {
		try {
			const entry = await chrome.runtime.sendMessage({
				type: "GET_ENTRY",
				id,
			});

			if (entry.error) {
				showNotification(entry.error, "error");
				return;
			}

			hideOverlay();
			autofillLogin(entry.username, entry.password);
		} catch (error) {
			showNotification(
				"Failed to get entry: " + (error.message || "Unknown error"),
				"error",
			);
		}
	}

	async function copyEntryPassword(id) {
		try {
			const entry = await chrome.runtime.sendMessage({
				type: "GET_ENTRY",
				id,
			});

			if (entry.error) {
				showNotification(entry.error, "error");
				return;
			}

			const success = await copyWithTimeout(entry.password);
			if (success) {
				showNotification("Password copied (auto-clears in 30s)", "success");
			} else {
				showNotification("Failed to copy password", "error");
			}
		} catch (error) {
			showNotification(
				"Failed to copy password: " + (error.message || "Unknown error"),
				"error",
			);
		}
	}

	// ============================================================================
	// Notifications
	// ============================================================================

	// Current toast's host element — the dedupe anchor. The old
	// document.getElementById lookup stopped working once the toast moved into
	// a closed shadow root (page-wide ids are no longer reachable).
	let activeToastHost = null;

	function showNotification(message, type = "info") {
		if (activeToastHost) activeToastHost.remove();

		const { host, shadowRoot } = mountShadowHost(
			"position: fixed; bottom: 20px; right: 20px; z-index: 2147483647;",
		);

		const notification = document.createElement("div");
		notification.id = "pwdvault-notification";
		notification.className =
			type === "error" || type === "success" ? type : "info";
		notification.textContent = message;
		shadowRoot.appendChild(notification);

		activeToastHost = host;
		document.body.appendChild(host);

		setTimeout(() => {
			if (activeToastHost === host) activeToastHost = null;
			host.remove();
		}, 3000);
	}

	// ============================================================================
	// Floating Button
	// ============================================================================

	let floatingButton = null;
	let floatingButtonShadow = null;
	let entryCount = 0;

	function createFloatingButton(entries = null) {
		if (floatingButton) {
			updateFloatingButtonBadge(entries);
			return;
		}

		const loginForm = findLoginForm();
		if (!loginForm || !loginForm.passwordField) return;
		// Register pages never get the floating button. Gating here (not at the
		// call sites) covers all three callers: checkForAutoFillPrompt, the init
		// ready callback, and the MutationObserver callback. Explicit user
		// actions (popup fill, overlay, context menu) are unaffected.
		if (loginForm.formType === FORM_TYPES.REGISTER) return;

		entryCount = entries ? entries.length : 0;

		const { host, shadowRoot } = mountShadowHost(
			"position: fixed; z-index: 2147483646;",
		);

		const button = document.createElement("div");
		button.id = "pwdvault-floating-btn";
		button.innerHTML = `
      <svg viewBox="0 0 24 24">
        <path d="M12 2C9.24 2 7 4.24 7 7v2H6c-1.1 0-2 .9-2 2v9c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2v-9c0-1.1-.9-2-2-2h-1V7c0-2.76-2.24-5-5-5zm0 2c1.66 0 3 1.34 3 3v2H9V7c0-1.66 1.34-3 3-3zm0 10c1.1 0 2 .9 2 2s-.9 2-2 2-2-.9-2-2 .9-2 2-2z"/>
      </svg>
      <span id="pwdvault-badge"></span>
    `;
		shadowRoot.appendChild(button);

		// Position near password field. The host is position:fixed, so it
		// takes viewport coordinates — adding window.scrollY would push it
		// off-screen below the fold on scrolled pages.
		const rect = loginForm.passwordField.getBoundingClientRect();
		host.style.top = `${rect.top - 50}px`;
		host.style.right = "20px";

		host.addEventListener("click", (e) => {
			e.preventDefault();
			showOverlay();
		});

		floatingButton = host;
		floatingButtonShadow = shadowRoot;
		document.body.appendChild(host);

		// Trigger fade-in animation (the animated element sits inside the
		// shadow tree — the host only carries positioning)
		requestAnimationFrame(() => {
			if (floatingButtonShadow === shadowRoot) {
				const inner = shadowRoot.querySelector("#pwdvault-floating-btn");
				if (inner) inner.style.opacity = "1";
			}
		});

		updateFloatingButtonBadge(entries);
	}

	function updateFloatingButtonBadge(entries) {
		if (!floatingButtonShadow) return;

		const badge = floatingButtonShadow.querySelector("#pwdvault-badge");
		if (!badge) return;

		const count = entries ? entries.length : 0;
		entryCount = count;

		if (count > 1) {
			badge.textContent = count;
			badge.style.display = "flex";
		} else {
			badge.style.display = "none";
		}
	}

	function removeFloatingButton() {
		if (floatingButton) {
			floatingButton.remove();
			floatingButton = null;
			floatingButtonShadow = null;
		}
	}

	// Re-anchor the button to the current password field (scroll/resize/SPA
	// navigation) and remove it entirely once no login form remains. The
	// register gate is rechecked here so an SPA navigation from a login page
	// to a register page also removes an already-visible button.
	function positionFloatingButton() {
		if (!floatingButton) return;

		const loginForm = findLoginForm();
		if (!loginForm || !loginForm.passwordField) {
			removeFloatingButton();
			return;
		}
		if (loginForm.formType === FORM_TYPES.REGISTER) {
			removeFloatingButton();
			return;
		}

		const rect = loginForm.passwordField.getBoundingClientRect();
		floatingButton.style.top = `${rect.top - 50}px`;
	}

	// Simple timestamp throttle — no library, no timer leak; trailing calls
	// within the window are dropped because the next event will reposition.
	function throttle(fn, waitMs) {
		let lastRun = 0;
		return () => {
			const now = Date.now();
			if (now - lastRun >= waitMs) {
				lastRun = now;
				fn();
			}
		};
	}

	const repositionFloatingButton = throttle(positionFloatingButton, 200);
	window.addEventListener("scroll", repositionFloatingButton, {
		passive: true,
	});
	window.addEventListener("resize", repositionFloatingButton, {
		passive: true,
	});

	// ============================================================================
	// Keyboard Shortcuts
	// ============================================================================

	document.addEventListener("keydown", (e) => {
		// Synthetic key guard: this path opens the credential overlay.
		if (!e.isTrusted) return;
		// Ctrl+Shift+L (Cmd+Shift+L on Mac) to trigger manual fill
		if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === "l") {
			e.preventDefault();
			showOverlay();
		}
	});

	// ============================================================================
	// Auto-fill Prompt Logic
	// ============================================================================

	async function checkForAutoFillPrompt() {
		const loginForm = findLoginForm();
		if (!loginForm || !loginForm.passwordField) return;

		// Register pages never get the automatic prompt bar. Explicit fill paths
		// (popup, overlay, context menu) stay available; the floating button has
		// its own register gate, so skipping both calls here is safe.
		if (loginForm.formType === FORM_TYPES.REGISTER) return;

		try {
			const entries = await chrome.runtime.sendMessage({
				type: "GET_ENTRIES_FOR_URL",
				url: window.location.href,
			});

			if (entries && !entries.error && entries.length === 1) {
				// Exactly one matching entry - show the prompt from the summary only
				// (title/username, no password). The plaintext secret is fetched at
				// Fill-click time inside showAutoFillPrompt, not on page load.
				showAutoFillPrompt(entries[0]);
			}

			// Update floating button with entry count
			createFloatingButton(entries);
		} catch (error) {
			console.warn("Auto-fill check failed:", error);
		}
	}

	// ============================================================================
	// Message Handling
	// ============================================================================

	chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
		switch (message.type) {
			case "AUTOFILL":
				// Authoritative gate (semantics: sender-auth.js
				// entryMatchesPageUrl). The message must carry the entry's
				// stored URL: a missing (non-string) entryUrl is a protocol
				// violation and is rejected fail-closed. An empty string means
				// a generic entry (no URL) — the popup's explicit fill stays
				// allowed. A rejected fill never touches any credential field.
				if (
					typeof message.entryUrl !== "string" ||
					!entryMatchesPageUrl(message.entryUrl, window.location.href)
				) {
					sendResponse({ ok: false, reason: "domain-mismatch" });
					break;
				}
				autofillLogin(message.username, message.password);
				sendResponse({ ok: true });
				break;

			case "INSERT_PASSWORD":
				insertPassword(message.password);
				sendResponse({ success: true });
				break;

			case "VAULT_LOCKED":
				cachedEntries = null;
				hideOverlay();
				hideNotificationBar();
				sendResponse({ success: true });
				break;

			case "SHOW_NOTIFICATION":
				// M12: feedback channel for the background service worker (it has
				// no toast mechanism of its own). Reuses the on-page notifier.
				showNotification(
					typeof message.message === "string" ? message.message : "",
					typeof message.notificationType === "string"
						? message.notificationType
						: "info",
				);
				sendResponse({ success: true });
				break;

			default:
				// Unknown type: stay silent and close synchronously (return false
				// = no response). chrome.runtime.sendMessage broadcasts never
				// reach content scripts, but silence costs nothing and keeps this
				// listener from racing any future broadcast's intended receiver.
				return false;
		}
	});

	// ============================================================================
	// Initialization
	// ============================================================================

	let initialized = false;

	function init() {
		if (initialized) return;
		initialized = true;

		// Wait for page to be ready
		const ready = () => {
			setTimeout(() => {
				createFloatingButton();
				checkForAutoFillPrompt();
			}, 500);
		};

		if (document.readyState === "loading") {
			document.addEventListener("DOMContentLoaded", ready);
		} else {
			ready();
		}
	}

	// Re-check for forms on dynamic page changes
	let debounceTimer = null;
	const observer = new MutationObserver(() => {
		clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => {
			if (floatingButton) {
				// SPA navigation can move or remove the form while the button is
				// already on screen — re-anchor it, or remove it when the form is
				// gone.
				positionFloatingButton();
			} else {
				createFloatingButton();
				checkForAutoFillPrompt();
			}
		}, 250);
	});

	// Start observing when body is available
	if (document.body) {
		observer.observe(document.body, {
			childList: true,
			subtree: true,
		});
		init();
	} else {
		document.addEventListener("DOMContentLoaded", () => {
			observer.observe(document.body, {
				childList: true,
				subtree: true,
			});
			init();
		});
	}
})();
