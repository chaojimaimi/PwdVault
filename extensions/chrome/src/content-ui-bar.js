// PwdVault Content Script — injected UI (file 4/6): prompt bar, overlay,
// toast, floating button, auto-fill prompt logic. Same namespace rules as
// content-forms.js. Assembled from two segments of the pre-split content.js
// (1090-1622 and 1638-1669) around the keyboard handler, which moved to the
// entry file (content.js).

(function () {
	"use strict";

	globalThis.PwdVaultContent ??= {};

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

		const { host, shadowRoot } = globalThis.PwdVaultContent.mountShadowHost(
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
				globalThis.PwdVaultContent.autofillLogin(full.username, full.password);
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
	// cachedEntries rides the shared namespace: the save-prompt capture and
	// the entry file's VAULT_LOCKED teardown touch it across the split.
	globalThis.PwdVaultContent.cachedEntries = null;

	function createOverlay() {
		if (overlay) return overlay;

		const { host, shadowRoot } = globalThis.PwdVaultContent.mountShadowHost(
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

			globalThis.PwdVaultContent.cachedEntries = response;
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
			globalThis.PwdVaultContent.autofillLogin(entry.username, entry.password);
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

			const success = await globalThis.PwdVaultContent.copyWithTimeout(
				entry.password,
			);
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

		const { host, shadowRoot } = globalThis.PwdVaultContent.mountShadowHost(
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

	// floatingButton rides the shared namespace: the entry file's
	// MutationObserver reads it across the split. The shadow-root handle
	// and the badge count stay file-local.
	globalThis.PwdVaultContent.floatingButton = null;
	let floatingButtonShadow = null;
	let entryCount = 0;

	function createFloatingButton(entries = null) {
		if (globalThis.PwdVaultContent.floatingButton) {
			updateFloatingButtonBadge(entries);
			return;
		}

		const loginForm = globalThis.PwdVaultContent.findLoginForm();
		if (!loginForm || !loginForm.passwordField) return;
		// Register pages never get the floating button. Gating here (not at the
		// call sites) covers all three callers: checkForAutoFillPrompt, the init
		// ready callback, and the MutationObserver callback. Explicit user
		// actions (popup fill, overlay, context menu) are unaffected.
		if (loginForm.formType === globalThis.PwdVaultContent.FORM_TYPES.REGISTER)
			return;

		entryCount = entries ? entries.length : 0;

		const { host, shadowRoot } = globalThis.PwdVaultContent.mountShadowHost(
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

		globalThis.PwdVaultContent.floatingButton = host;
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
		if (globalThis.PwdVaultContent.floatingButton) {
			globalThis.PwdVaultContent.floatingButton.remove();
			globalThis.PwdVaultContent.floatingButton = null;
			floatingButtonShadow = null;
		}
	}

	// Re-anchor the button to the current password field (scroll/resize/SPA
	// navigation) and remove it entirely once no login form remains. The
	// register gate is rechecked here so an SPA navigation from a login page
	// to a register page also removes an already-visible button.
	function positionFloatingButton() {
		if (!globalThis.PwdVaultContent.floatingButton) return;

		const loginForm = globalThis.PwdVaultContent.findLoginForm();
		if (!loginForm || !loginForm.passwordField) {
			removeFloatingButton();
			return;
		}
		if (loginForm.formType === globalThis.PwdVaultContent.FORM_TYPES.REGISTER) {
			removeFloatingButton();
			return;
		}

		const rect = loginForm.passwordField.getBoundingClientRect();
		globalThis.PwdVaultContent.floatingButton.style.top = `${rect.top - 50}px`;
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
	// Auto-fill Prompt Logic
	// ============================================================================

	async function checkForAutoFillPrompt() {
		const loginForm = globalThis.PwdVaultContent.findLoginForm();
		if (!loginForm || !loginForm.passwordField) return;

		// Register pages never get the automatic prompt bar. Explicit fill paths
		// (popup, overlay, context menu) stay available; the floating button has
		// its own register gate, so skipping both calls here is safe.
		if (loginForm.formType === globalThis.PwdVaultContent.FORM_TYPES.REGISTER)
			return;

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
	// Namespace exports (file 4/6) — consumed by the entry file (content.js).
	// ============================================================================
	globalThis.PwdVaultContent.showNotification = showNotification;
	globalThis.PwdVaultContent.showOverlay = showOverlay;
	globalThis.PwdVaultContent.hideOverlay = hideOverlay;
	globalThis.PwdVaultContent.hideNotificationBar = hideNotificationBar;
	globalThis.PwdVaultContent.createFloatingButton = createFloatingButton;
	globalThis.PwdVaultContent.positionFloatingButton = positionFloatingButton;
	globalThis.PwdVaultContent.checkForAutoFillPrompt = checkForAutoFillPrompt;
})();
