// PwdVault Content Script
// Detects login forms and handles auto-fill

// === BEGIN VERBATIM DOMAIN-MATCH BLOCK ===
// Everything between the BEGIN/END markers is carried as a byte-identical
// copy in content.js (classic content scripts cannot import ES modules; a
// dynamic import would require web_accessible_resources = a manifest change
// plus a fingerprint surface). The guard test in sender-auth.test.js fails
// when the two drift apart. Only difference: the declarations below carry the
// `export` keyword, which is stripped in the content.js copy.
//
// Curated multi-label public suffix constants (v1.4.0 eTLD+1 matching):
// 126 two-label suffixes picked from the ICANN section of the Mozilla Public
// Suffix List (excerpted 2026-10-25). This is a SELECTION, not the full PSL —
// the 250KB list is not worth the bundle for an auto-fill matcher. Under
// these suffixes the registrable domain is three labels (example.co.uk is
// one registrable domain; evil.co.uk must never collapse into it).
const MULTI_LABEL_SUFFIXES = new Set([
	// uk
	"co.uk",
	"org.uk",
	"me.uk",
	"ac.uk",
	"gov.uk",
	"net.uk",
	"sch.uk",
	"ltd.uk",
	"plc.uk",
	// jp
	"co.jp",
	"ne.jp",
	"or.jp",
	"ac.jp",
	"ad.jp",
	"ed.jp",
	"go.jp",
	"gr.jp",
	"lg.jp",
	// au
	"com.au",
	"net.au",
	"org.au",
	"edu.au",
	"gov.au",
	"asn.au",
	"id.au",
	// nz
	"co.nz",
	"net.nz",
	"org.nz",
	"govt.nz",
	"ac.nz",
	"school.nz",
	// br
	"com.br",
	"net.br",
	"org.br",
	"gov.br",
	"edu.br",
	// mx
	"com.mx",
	"net.mx",
	"org.mx",
	"gob.mx",
	"edu.mx",
	// in
	"co.in",
	"net.in",
	"org.in",
	"firm.in",
	"gen.in",
	"ind.in",
	"ac.in",
	"edu.in",
	"gov.in",
	// za
	"co.za",
	"net.za",
	"org.za",
	"web.za",
	"ac.za",
	"gov.za",
	// sg
	"com.sg",
	"net.sg",
	"org.sg",
	"gov.sg",
	"edu.sg",
	// hk
	"com.hk",
	"net.hk",
	"org.hk",
	"gov.hk",
	"edu.hk",
	"idv.hk",
	// tw
	"com.tw",
	"net.tw",
	"org.tw",
	"gov.tw",
	"edu.tw",
	"idv.tw",
	// cn
	"com.cn",
	"net.cn",
	"org.cn",
	"gov.cn",
	"edu.cn",
	"ac.cn",
	"mil.cn",
	// kr
	"co.kr",
	"ne.kr",
	"or.kr",
	"go.kr",
	"ac.kr",
	"pe.kr",
	// tr
	"com.tr",
	"net.tr",
	"org.tr",
	"gov.tr",
	"edu.tr",
	// ua
	"com.ua",
	"net.ua",
	"org.ua",
	"gov.ua",
	"edu.ua",
	// il
	"co.il",
	"org.il",
	"net.il",
	"ac.il",
	"gov.il",
	// co
	"com.co",
	"net.co",
	"org.co",
	"edu.co",
	"gov.co",
	// id
	"co.id",
	"net.id",
	"or.id",
	"web.id",
	"ac.id",
	// my
	"com.my",
	"net.my",
	"org.my",
	"edu.my",
	"gov.my",
	// ae
	"co.ae",
	"net.ae",
	"org.ae",
	"ac.ae",
	"gov.ae",
	// pl
	"com.pl",
	"net.pl",
	"org.pl",
	"gov.pl",
	// ca
	"gc.ca",
]);

// Registrable domain (eTLD+1) of `host` (expected lowercase, www already
// stripped by the caller). Fail-closed by design — "prefer a missed fill
// over a leaked credential":
//  - last two labels hit the suffix table → eTLD+1 is three labels
//    (login.example.co.uk and example.co.uk share one registrable domain);
//  - last label is a 2-letter ccTLD NOT covered by the table → fall back to
//    the FULL hostname as the match key. The tail-2 heuristic alone would
//    treat login.site.co.xx and attacker-registered evil.co.xx as the same
//    "registrable domain" — exactly the leak the table exists to prevent;
//  - the host IS itself a table suffix (e.g. `co.uk`) or has too few labels
//    → full hostname, so only an exact host match passes.
// Single-letter / exotic TLDs behave as plain eTLD+1 via the tail-2 path.
function registeredDomain(host) {
	if (!host) return null;
	const labels = host.split(".");
	if (labels.length <= 2) return host;
	const lastTwo = labels.slice(-2).join(".");
	if (MULTI_LABEL_SUFFIXES.has(lastTwo)) {
		return labels.slice(-3).join(".");
	}
	const lastLabel = labels[labels.length - 1];
	if (lastLabel.length === 2) return host;
	return lastTwo;
}

function normalizedDomain(rawUrl) {
	try {
		return registeredDomain(
			new URL(rawUrl).hostname.toLowerCase().replace(/^www\./, ""),
		);
	} catch {
		return null;
	}
}

// v1.5.0 WP4 per-entry URL match override. Anything unrecognized —
// including a MISSING field (pre-v1.5.0 desktop/extension payloads) —
// degrades to "auto" (the v1.4.0 status quo): never an error, never a
// silent tightening of the gate.
function entryMatchMode(entry) {
	return entry?.url_match_mode === "exact" || entry?.url_match_mode === "domain"
		? entry.url_match_mode
		: "auto";
}

// Full hostname of a stored or page URL for "exact" mode. `new URL()` already
// case-folds and punycodes IDN into .hostname and keeps the port OUT of it,
// so hosts compare for equality without further normalization. Scheme-less
// entry URLs get the same https:// padding as the domain paths. A parse
// failure returns null (cannot judge → both gates reject).
function exactHost(rawUrl) {
	try {
		const withScheme = /^https?:\/\//i.test(rawUrl)
			? rawUrl
			: `https://${rawUrl}`;
		return new URL(withScheme).hostname;
	} catch {
		return null;
	}
}

function entryMatchesSenderUrl(entry, senderUrl) {
	const senderDomain = normalizedDomain(senderUrl);
	// Empty entryUrl is REJECTED here — INTENTIONALLY different from
	// entryMatchesPageUrl below (which allows generic entries on an explicit
	// popup fill): the content-script path auto-fills without a per-entry user
	// click, so a stored URL must exist to compare against the sender frame.
	// v1.5.0: the rejection holds in ALL three match modes.
	const rawEntryUrl = typeof entry?.url === "string" ? entry.url : "";
	if (!senderDomain || !rawEntryUrl) return false;
	// v1.5.0 per-entry override: "exact" pins FULL hostname equality.
	if (entryMatchMode(entry) === "exact") {
		const entryHost = exactHost(rawEntryUrl);
		return Boolean(entryHost) && entryHost === exactHost(senderUrl);
	}
	// "auto" (v1.4.0 status quo) and "domain" (the same comparison pinned by
	// contract) both compare registrable domains. Entries are often stored
	// scheme-less ("github.com/acme"); pad https:// exactly like
	// entryMatchesPageUrl before parsing, otherwise such entries would be
	// invisible to the content-script path while the popup could still fill
	// them — a pointless semantics split.
	const withScheme = /^https?:\/\//i.test(rawEntryUrl)
		? rawEntryUrl
		: `https://${rawEntryUrl}`;
	const entryDomain = normalizedDomain(withScheme);
	return Boolean(entryDomain) && entryDomain === senderDomain;
}

// Single source of truth for "may this entry be filled on this page?".
// Takes the full entry (v1.5.0 WP4: the per-entry url_match_mode override
// rides along with the stored URL). Compares registrable domains (eTLD+1 via
// registeredDomain, lowercase + strip a leading "www."), matching the
// semantics of entryMatchesSenderUrl and the background fill gate. DIVERGENCE
// IS INTENTIONAL: entryMatchesSenderUrl rejects an empty entryUrl (see its
// comment); this function allows it — an explicit popup fill is a deliberate
// user action on a generic entry. Do NOT "unify" the two.
// NOTE: content.js carries a verbatim copy of this whole block — content
// scripts are classic scripts and cannot import ES modules. Keep the copies
// byte-identical; the guard test in sender-auth.test.js enforces it.
function entryMatchesPageUrl(entry, pageUrl) {
	// Empty entryUrl = generic entry (no stored URL); an explicit popup fill is
	// a deliberate user action, so allow it — in ALL match modes. Empty
	// pageUrl = cannot judge.
	const entryUrl = typeof entry?.url === "string" ? entry.url : "";
	if (!entryUrl) return true;
	if (!pageUrl) return false;
	// v1.5.0 per-entry override: "exact" pins FULL hostname equality.
	if (entryMatchMode(entry) === "exact") {
		const entryHost = exactHost(entryUrl);
		const pageHost = exactHost(pageUrl);
		return Boolean(entryHost && pageHost) && entryHost === pageHost;
	}
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
// === END VERBATIM DOMAIN-MATCH BLOCK ===

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
	// The five @keyframes live here too: shadow-scoped, so the page can neither
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
    #pwdvault-autofill-bar .pv-btn,
    #pwdvault-save-bar .pv-btn {
      padding: 8px 16px;
      border-radius: 6px;
      border: none;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      font-family: inherit;
    }
    #pwdvault-autofill-bar .pv-btn-primary,
    #pwdvault-save-bar .pv-btn-primary {
      background: var(--pv-primary);
      color: #fff;
    }
    #pwdvault-autofill-bar .pv-btn-primary:hover,
    #pwdvault-save-bar .pv-btn-primary:hover {
      background: var(--pv-primary-hover);
    }
    #pwdvault-autofill-bar .pv-btn-secondary,
    #pwdvault-save-bar .pv-btn-secondary {
      background: var(--pv-input);
      color: var(--pv-text-secondary);
    }
    #pwdvault-autofill-bar .pv-btn-secondary:hover,
    #pwdvault-save-bar .pv-btn-secondary:hover {
      background: var(--pv-border-strong);
      color: var(--pv-text);
    }

    /* --- Save/update prompt bar (bottom; position lives on the host) --- */
    #pwdvault-save-bar {
      width: 100%;
      box-sizing: border-box;
      background: var(--pv-surface);
      padding: 12px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      font-size: 14px;
      color: var(--pv-text);
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15);
      animation: slideUp 0.3s ease-out;
    }
    @keyframes slideUp {
      from { transform: translateY(100%); }
      to { transform: translateY(0); }
    }
    #pwdvault-save-bar .pv-save-text {
      font-weight: 500;
      min-width: 0;
    }
    #pwdvault-save-bar .pv-actions {
      display: flex;
      gap: 8px;
      flex-shrink: 0;
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
							: (full && full.error) || "Failed to fetch the entry. Try again.",
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
	// Save/Update Prompt (v1.6.0): submit capture + page-side confirm bar
	// ============================================================================
	//
	// After a plausible login submit, the typed username+password are captured
	// into a closure here; only a SHA-256 digest leaves the page for the
	// save/update CHECK, and the plaintext itself leaves ONLY on a trusted
	// click of Save/Update (SAVE_LOGIN_CONFIRMED). The plaintext is never
	// sent anywhere else, never logged, and dies with the closure on dismiss,
	// the 60s timeout, or page navigation.

	// Is this clicked element a plausible submit trigger? An explicit or
	// implicit type="submit" is authoritative; anything else falls back to
	// the same text heuristics the form scanner uses (JS-submit pages often
	// wire type="button" with login text).
	function isPlausibleSubmitButton(button) {
		const type = (button.getAttribute("type") || "").toLowerCase();
		if (type === "submit") return true;
		const text = (
			button.textContent ||
			button.value ||
			button.getAttribute("aria-label") ||
			""
		).toLowerCase();
		return SUBMIT_PATTERNS.some((pattern) => pattern.test(text));
	}

	// One capture per form per short window: the button click, the implicit
	// Enter-click and the submit event land on the same form within
	// milliseconds — only the first may open a capture.
	const SUBMIT_DEDUPE_MS = 1500;
	const recentSubmitAt = new WeakMap();

	function submitRecentlyHandled(keyEl) {
		const last = recentSubmitAt.get(keyEl);
		return typeof last === "number" && Date.now() - last < SUBMIT_DEDUPE_MS;
	}

	// Shared sink for the three trusted capture paths at the bottom of this
	// section. `anchor` is the submitted form, the clicked submit button, or
	// the Enter'd password field.
	async function handlePossibleSubmit(anchor) {
		const form = anchor instanceof Element ? anchor.closest("form") : null;
		const dedupeKey = form || document.body;
		if (submitRecentlyHandled(dedupeKey)) return;
		recentSubmitAt.set(dedupeKey, Date.now());

		// Secure-context gate BEFORE any plaintext is read or digested:
		// crypto.subtle is undefined on plain-http pages — silently skip
		// (no prompt, no toast; inner-network/device pages gain nothing
		// from a prompt they cannot act on).
		if (!crypto?.subtle) return;

		const creds = form
			? credentialsInForm(form)
			: pageCredentialsForAnchor(anchor);
		if (!creds || !creds.passwordInput) return;
		const username = creds.usernameField
			? creds.usernameField.value.trim()
			: "";
		const password = creds.passwordInput.value;
		// Conservative: no usable username+password pair → no prompt at all.
		if (!username || !password) return;
		await offerSavePrompt(username, password, window.location.href);
	}

	// Submit-time credential capture scoped to a real form.
	function credentialsInForm(form) {
		const passwordInputs = Array.from(
			form.querySelectorAll('input[type="password"]'),
		);
		const passwordInput = selectPasswordField(passwordInputs);
		if (!passwordInput) return null;
		return {
			passwordInput,
			usernameField: inspectLoginForm(form, passwordInput).usernameField,
		};
	}

	// Formless layouts: the page-level scan answers only for anchors that
	// belong to it — the clicked button must BE its submit button, Enter
	// must hit its password field. Anything else is not a plausible submit.
	function pageCredentialsForAnchor(anchor) {
		const pageForm = findLoginForm();
		if (!pageForm) return null;
		if (anchor !== pageForm.submitButton && anchor !== pageForm.passwordField) {
			return null;
		}
		return {
			passwordInput: pageForm.passwordField,
			usernameField: pageForm.usernameField,
		};
	}

	// Candidates for the save check: the cached GET_ENTRIES_FOR_URL summaries
	// when present, else one fresh fetch pinned to the submitted URL.
	async function candidatesForSubmit(pageUrl) {
		if (Array.isArray(cachedEntries)) return cachedEntries;
		try {
			const response = await chrome.runtime.sendMessage({
				type: "GET_ENTRIES_FOR_URL",
				url: pageUrl,
			});
			if (!response || response.error || !Array.isArray(response)) return [];
			cachedEntries = response;
			return response;
		} catch {
			return [];
		}
	}

	// Decision round: with matching candidates the typed password's digest
	// is checked against the STORED passwords desktop-side
	// (verify_entry_password answers a boolean — no plaintext crosses, and
	// the stored password never leaves the vault). Without candidates the
	// decision is "save" right away.
	async function offerSavePrompt(username, password, submittedUrl) {
		const candidates = await candidatesForSubmit(submittedUrl);
		// Candidate filter: trim-normalized and case-folded. The authoritative
		// equal/not-equal verdict is the desktop verify below; the fold here
		// only widens the shortlist so an email-case mismatch cannot turn an
		// existing entry into a duplicate-save prompt.
		const matches = candidates.filter(
			(entry) =>
				typeof entry?.username === "string" &&
				entry.username.trim().toLowerCase() === username.toLowerCase(),
		);

		let decision = { action: "save" };
		if (matches.length > 0) {
			try {
				decision = await checkSaveDecision(password, matches);
			} catch {
				// A failed check (locked vault, unreachable desktop) prompts
				// nothing — same posture as the VAULT_LOCKED paths.
				return;
			}
		}
		if (!decision || decision.error || decision.action === "none") return;
		presentSavePrompt(decision, {
			username,
			password,
			submittedUrl,
			candidates: matches,
		});
	}

	// The outbound CHECK carries the digest and candidate id/title/username
	// triples only — the message body has no password field.
	async function checkSaveDecision(password, matches) {
		return chrome.runtime.sendMessage({
			type: "CHECK_SAVE_CREDENTIALS",
			password_sha256: await digestText(password),
			candidates: matches.map((entry) => ({
				id: entry.id,
				title: entry.title,
				username: entry.username,
			})),
		});
	}

	// Wire payload for the confirmed save — the ONLY place the captured
	// plaintext enters a message. For "update", the entry's own metadata is
	// echoed (the desktop replaces title/url/tags/group/mode wholesale);
	// for "create", the background derives the title from the URL.
	function buildSavePayload(decision, creds) {
		const base = {
			url: creds.submittedUrl,
			username: creds.username,
			password: creds.password,
		};
		if (decision.action !== "update") {
			return { type: "SAVE_LOGIN_CONFIRMED", mode: "create", ...base };
		}
		const chosen = (creds.candidates || []).find(
			(entry) => entry.id === decision.entry_id,
		);
		if (!chosen) return null;
		return {
			type: "SAVE_LOGIN_CONFIRMED",
			mode: "update",
			entry_id: decision.entry_id,
			entry: {
				title: chosen.title,
				username: chosen.username,
				url: chosen.url,
				tags: chosen.tags,
				group_id: chosen.group_id,
				url_match_mode: chosen.url_match_mode,
			},
			...base,
		};
	}

	async function confirmSave(payload) {
		if (!payload) {
			showNotification("Failed to save login — no matching entry", "error");
			return;
		}
		try {
			const result = await chrome.runtime.sendMessage(payload);
			if (result && result.ok) {
				showNotification(
					payload.mode === "update"
						? "Password updated in PwdVault"
						: "Login saved to PwdVault",
					"success",
				);
			} else {
				showNotification(
					(result && result.error) || "Failed to save login to PwdVault",
					"error",
				);
			}
		} catch (error) {
			showNotification(
				"Failed to save login: " + (error.message || "Unknown error"),
				"error",
			);
		}
	}

	// Module-level in-flight reference — at most ONE pending save/update
	// prompt per tab; a new prompt removes the previous one (the same
	// single-instance pattern as activeToastHost).
	let pendingSaveBar = null;
	let pendingSaveTimeout = null;

	function dismissSavePrompt() {
		if (pendingSaveTimeout) {
			clearTimeout(pendingSaveTimeout);
			pendingSaveTimeout = null;
		}
		if (pendingSaveBar) {
			pendingSaveBar.remove();
			pendingSaveBar = null;
		}
	}

	function createSavePromptButton(className, label, onClick) {
		const btn = document.createElement("button");
		btn.className = className;
		btn.textContent = label;
		btn.addEventListener("click", onClick);
		return btn;
	}

	// DOM scaffolding for the prompt bar (text + the two buttons). The
	// confirm handler arrives pre-built; its isTrusted guard lives inside it.
	function buildSavePromptBar(decision, confirmHandler, dismissHandler) {
		const bar = document.createElement("div");
		bar.id = "pwdvault-save-bar";
		const text = document.createElement("span");
		text.className = "pv-save-text";
		text.textContent =
			decision.action === "update"
				? `Update password for ${decision.entry_title}?`
				: "Save this login to PwdVault?";
		bar.appendChild(text);
		const actions = document.createElement("div");
		actions.className = "pv-actions";
		actions.appendChild(
			createSavePromptButton(
				"pv-btn pv-btn-secondary",
				"Not now",
				dismissHandler,
			),
		);
		actions.appendChild(
			createSavePromptButton(
				"pv-btn pv-btn-primary",
				decision.action === "update" ? "Update" : "Save",
				confirmHandler,
			),
		);
		bar.appendChild(actions);
		return bar;
	}

	function presentSavePrompt(decision, credentials) {
		// In-flight single instance: a new prompt replaces the old one.
		dismissSavePrompt();
		const { host, shadowRoot } = mountShadowHost(
			"position: fixed; bottom: 0; left: 0; right: 0; z-index: 2147483646;",
		);
		// The plaintext lives ONLY in this closure and every exit drops it:
		// the confirm send, Not now, the 60s timer, real navigation.
		let creds = credentials;
		const dropPlaintext = () => {
			if (creds) creds.password = "";
			creds = null;
		};
		// The only path where the captured plaintext may leave the page: a
		// trusted click on Save/Update. A synthetic click never gets here.
		const confirmHandler = (e) => {
			if (!e.isTrusted) return;
			const payload = creds ? buildSavePayload(decision, creds) : null;
			dropPlaintext();
			dismissSavePrompt();
			confirmSave(payload);
		};
		const dismissHandler = () => {
			dropPlaintext();
			dismissSavePrompt();
		};
		shadowRoot.appendChild(
			buildSavePromptBar(decision, confirmHandler, dismissHandler),
		);
		pendingSaveBar = host;
		document.body.appendChild(host);
		// 60s self-destruct (the autofill-bar page-side setTimeout
		// precedent) — the plaintext closure dies with it.
		pendingSaveTimeout = setTimeout(() => {
			pendingSaveTimeout = null;
			dropPlaintext();
			dismissSavePrompt();
		}, 60000);
	}

	// Path 1 - the form submit event, captured at document level so
	// dynamically inserted forms are covered too.
	document.addEventListener(
		"submit",
		(e) => {
			if (!e.isTrusted) return;
			handlePossibleSubmit(e.target);
		},
		true,
	);

	// Path 2 - a click on a plausible submit button (covers pages that
	// submit through JS without a native submit event).
	document.addEventListener(
		"click",
		(e) => {
			if (!e.isTrusted) return;
			const target = e.target instanceof Element ? e.target : null;
			const button = target
				? target.closest(
						'button, input[type="submit"], input[type="button"], [role="button"]',
					)
				: null;
			if (!button || !isPlausibleSubmitButton(button)) return;
			handlePossibleSubmit(button);
		},
		true,
	);

	// Path 3 - Enter pressed in a password box (implicit submission).
	document.addEventListener(
		"keydown",
		(e) => {
			if (!e.isTrusted) return;
			if (e.key !== "Enter") return;
			const field = e.target instanceof HTMLInputElement ? e.target : null;
			if (!field || field.type !== "password") return;
			handlePossibleSubmit(field);
		},
		true,
	);

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
				// v1.5.0 WP4: the message also carries the entry's URL match
				// override; a missing match_mode (pre-v1.5.0 sender) falls
				// back to "auto" — not an error.
				if (
					typeof message.entryUrl !== "string" ||
					!entryMatchesPageUrl(
						{
							url: message.entryUrl,
							url_match_mode: message.match_mode || "auto",
						},
						window.location.href,
					)
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
				// A locked vault must not keep a pending save/update prompt
				// alive (v1.6.0: no prompt, no save on a locked vault).
				dismissSavePrompt();
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
