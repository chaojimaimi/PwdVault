// PwdVault Content Script — entry (file 6/6, loads last).
// Keyboard shortcut, the chrome.runtime message handler, and the
// MutationObserver/init assembly. The other five files (loaded before this
// one, in manifest order) publish their cross-file surface on the
// globalThis.PwdVaultContent namespace; the frozen domain-match names from
// domain-match.js are referenced as bare identifiers.

(function () {
	"use strict";

	globalThis.PwdVaultContent ??= {};

	// ============================================================================
	// Keyboard Shortcuts
	// ============================================================================

	document.addEventListener("keydown", (e) => {
		// Synthetic key guard: this path opens the credential overlay.
		if (!e.isTrusted) return;
		// Ctrl+Shift+L (Cmd+Shift+L on Mac) to trigger manual fill
		if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === "l") {
			e.preventDefault();
			globalThis.PwdVaultContent.showOverlay();
		}
	});

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
				globalThis.PwdVaultContent.autofillLogin(
					message.username,
					message.password,
				);
				sendResponse({ ok: true });
				break;

			case "INSERT_PASSWORD":
				globalThis.PwdVaultContent.insertPassword(message.password);
				sendResponse({ success: true });
				break;

			case "VAULT_LOCKED":
				globalThis.PwdVaultContent.cachedEntries = null;
				globalThis.PwdVaultContent.hideOverlay();
				globalThis.PwdVaultContent.hideNotificationBar();
				// A locked vault must not keep a pending save/update prompt
				// alive (v1.6.0: no prompt, no save on a locked vault).
				globalThis.PwdVaultContent.dismissSavePrompt();
				sendResponse({ success: true });
				break;

			case "SHOW_NOTIFICATION":
				// M12: feedback channel for the background service worker (it has
				// no toast mechanism of its own). Reuses the on-page notifier.
				globalThis.PwdVaultContent.showNotification(
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
				globalThis.PwdVaultContent.createFloatingButton();
				globalThis.PwdVaultContent.checkForAutoFillPrompt();
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
			if (globalThis.PwdVaultContent.floatingButton) {
				// SPA navigation can move or remove the form while the button is
				// already on screen — re-anchor it, or remove it when the form is
				// gone.
				globalThis.PwdVaultContent.positionFloatingButton();
			} else {
				globalThis.PwdVaultContent.createFloatingButton();
				globalThis.PwdVaultContent.checkForAutoFillPrompt();
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
