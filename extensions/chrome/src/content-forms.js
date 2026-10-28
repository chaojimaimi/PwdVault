// PwdVault Content Script — form detection, auto-fill, clipboard (file 2/6).
// Classic content script: no import surface, so cross-file functions and
// mutable state travel only through the globalThis.PwdVaultContent namespace
// (full-name references only, contract-tested in content-namespace.test.js).
// The frozen domain-match names from domain-match.js (loaded first) are
// referenced as bare identifiers, exactly as in the pre-split content.js.

(function () {
	"use strict";

	globalThis.PwdVaultContent ??= {};

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

		const { usernameField, formType } = inspectLoginForm(
			container,
			passwordInput,
		);

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

	// Username lookup + form classification shared by findLoginForm (page
	// scan) and the v1.6.0 save-prompt submit capture (scoped to the
	// container the user actually submitted). The chosen password field
	// carries the autocomplete hard signal into the classifier.
	function inspectLoginForm(container, passwordInput) {
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

		return {
			usernameField,
			formType: detectFormType(container, passwordInput),
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
			globalThis.PwdVaultContent.showNotification(
				"No password received — fill cancelled",
				"error",
			);
			return false;
		}

		const loginForm = findLoginForm();

		if (!loginForm) {
			globalThis.PwdVaultContent.showNotification(
				"No login form detected on this page",
				"error",
			);
			return false;
		}

		// Fill username
		if (loginForm.usernameField) {
			fillField(loginForm.usernameField, username);
		}

		// Fill password
		fillField(loginForm.passwordField, password);

		globalThis.PwdVaultContent.showNotification(
			"Credentials filled successfully",
			"success",
		);

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
			globalThis.PwdVaultContent.showNotification(
				"Password inserted",
				"success",
			);
			return true;
		}

		globalThis.PwdVaultContent.showNotification(
			"Please focus on a password field first",
			"error",
		);
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
					// user to clear manually (showNotification resolves through the shared
					// namespace and is mounted by the time any timer fires). The digest guard
					// above keeps "already changed" silent; only real failures
					// notify, and just once (see clipboardClearFailureNotified).
					console.warn("clipboard auto-clear failed", e);
					if (!clipboardClearFailureNotified) {
						clipboardClearFailureNotified = true;
						globalThis.PwdVaultContent.showNotification(
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
	// Namespace exports (file 2/6) — consumed by the later content files.
	// ============================================================================
	globalThis.PwdVaultContent.findLoginForm = findLoginForm;
	globalThis.PwdVaultContent.selectPasswordField = selectPasswordField;
	globalThis.PwdVaultContent.inspectLoginForm = inspectLoginForm;
	globalThis.PwdVaultContent.SUBMIT_PATTERNS = SUBMIT_PATTERNS;
	globalThis.PwdVaultContent.FORM_TYPES = FORM_TYPES;
	globalThis.PwdVaultContent.autofillLogin = autofillLogin;
	globalThis.PwdVaultContent.insertPassword = insertPassword;
	globalThis.PwdVaultContent.digestText = digestText;
	globalThis.PwdVaultContent.copyWithTimeout = copyWithTimeout;
})();
