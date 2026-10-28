// PwdVault Content Script — save/update prompt capture (file 5/6).
// The three isTrusted-gated submit capture paths plus the page-side confirm
// bar (v1.6.0; guarded by content-save-prompt.test.js and
// content-is-trusted.test.js). Same namespace rules as content-forms.js.

(function () {
	"use strict";

	globalThis.PwdVaultContent ??= {};

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
		return globalThis.PwdVaultContent.SUBMIT_PATTERNS.some((pattern) =>
			pattern.test(text),
		);
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
		const passwordInput = globalThis.PwdVaultContent.selectPasswordField(
			passwordInputs,
		);
		if (!passwordInput) return null;
		return {
			passwordInput,
			usernameField: globalThis.PwdVaultContent.inspectLoginForm(
				form,
				passwordInput,
			).usernameField,
		};
	}

	// Formless layouts: the page-level scan answers only for anchors that
	// belong to it — the clicked button must BE its submit button, Enter
	// must hit its password field. Anything else is not a plausible submit.
	function pageCredentialsForAnchor(anchor) {
		const pageForm = globalThis.PwdVaultContent.findLoginForm();
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
		if (Array.isArray(globalThis.PwdVaultContent.cachedEntries)) {
			return globalThis.PwdVaultContent.cachedEntries;
		}
		try {
			const response = await chrome.runtime.sendMessage({
				type: "GET_ENTRIES_FOR_URL",
				url: pageUrl,
			});
			if (!response || response.error || !Array.isArray(response)) return [];
			globalThis.PwdVaultContent.cachedEntries = response;
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
			password_sha256: await globalThis.PwdVaultContent.digestText(
				password,
			),
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
			globalThis.PwdVaultContent.showNotification(
				"Failed to save login — no matching entry",
				"error",
			);
			return;
		}
		try {
			const result = await chrome.runtime.sendMessage(payload);
			if (result && result.ok) {
				globalThis.PwdVaultContent.showNotification(
					payload.mode === "update"
						? "Password updated in PwdVault"
						: "Login saved to PwdVault",
					"success",
				);
			} else {
				globalThis.PwdVaultContent.showNotification(
					(result && result.error) || "Failed to save login to PwdVault",
					"error",
				);
			}
		} catch (error) {
			globalThis.PwdVaultContent.showNotification(
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
		const { host, shadowRoot } = globalThis.PwdVaultContent.mountShadowHost(
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
	// Namespace exports (file 5/6) — the entry file tears any pending prompt
	// down on VAULT_LOCKED through this handle.
	// ============================================================================
	globalThis.PwdVaultContent.dismissSavePrompt = dismissSavePrompt;
})();
