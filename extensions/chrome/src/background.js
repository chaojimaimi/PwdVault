// PwdVault Background Service Worker — entry (listeners + command routing).
// Handles communication between content scripts, popup, and desktop app via
// Native Messaging (the browser spawns a host binary that bridges to the
// desktop app's local HTTP API on 127.0.0.1:17429).
//
// v1.6.3 split: the NM transport layer and connection state live in
// background-native.js; the per-command desktop handlers live in
// background-commands.js. This entry keeps every top-level listener
// registration (an MV3 requirement — listeners registered asynchronously are
// lost on service-worker restart) and the handleMessage router. Mutable
// transport state is deliberately NOT re-exported from here: import the live
// bindings from background-native.js instead.

import { authorizeMessage } from "./sender-auth.js";
import {
	armClipboardClear,
	createClipboardArmStorage,
	handleClipboardClearAlarm,
} from "./clipboard-clear.js";
import {
	checkConnection,
	connectionStatus,
	lastConnectionError,
	pairConfirm,
	pendingPairingFresh,
	restorePendingPairNonce,
	restoreToken,
	saveToken,
	startPairing,
} from "./background-native.js";
import {
	checkSaveCredentials,
	createEntry,
	generatePassword,
	getEntries,
	getEntriesForUrl,
	getEntry,
	getEntryForSender,
	getGroups,
	getSettings,
	isVaultInitialized,
	isVaultUnlocked,
	lockVault,
	titleForUrl,
	unlockVault,
	updateEntryFromPrompt,
} from "./background-commands.js";

// The clipboard auto-clear arm record (digest + deadline) is also
// session-backed so the deadline alarm can still verify the clipboard after
// this service worker was killed and restarted in the meantime.
const clipboardArmStoragePromise = createClipboardArmStorage(chrome.storage);

// Injected browser APIs for the clipboard-clear engine. `offscreen` exists
// only on Chrome (109+); Firefox takes the event-page execCommand path.
// `document` exists only in the Firefox event page, not in a Chrome service
// worker.
function offscreenApiOrNull() {
	// Bracket access is deliberate: web-ext's static UNSUPPORTED_API check
	// cannot resolve computed members, and it would otherwise flag this as
	// unsupported in Firefox even though the runtime feature-detection below
	// is what actually keeps Firefox off the API (it takes the event-page
	// path via `document` instead).
	const ns = chrome["offscreen"];
	return typeof ns?.createDocument === "function" ? ns : null;
}

function clipboardClearDeps() {
	return clipboardArmStoragePromise.then((storage) => ({
		storage,
		alarms: chrome.alarms,
		runtime: chrome.runtime,
		offscreen: offscreenApiOrNull(),
		document: typeof document === "undefined" ? null : document,
	}));
}

// ============================================================================
// Context Menu
// ============================================================================

function setupContextMenu() {
	// Wrap in try/catch: the contextMenus API can throw if the extension
	// isn't yet fully initialized or if the API is unavailable in a given
	// context. A thrown error here would abort the entire onInstalled /
	// onStartup / SW-startup handler, preventing token restoration and
	// other initialization from running.
	try {
		chrome.contextMenus.removeAll(() => {
			try {
				chrome.contextMenus.create({
					id: "pwdvault-fill",
					title: "Fill with PwdVault",
					contexts: ["editable"],
				});

				chrome.contextMenus.create({
					id: "pwdvault-generate",
					title: "Generate Password",
					contexts: ["editable"],
				});
			} catch (e) {
				// contextMenus.create can throw if an entry already exists or if
				// the API is temporarily unavailable — non-fatal.
			}
		});
	} catch (e) {
		// contextMenus API unavailable — non-fatal; the popup still works.
	}
}

// M12: deliver user-facing feedback through the page's content script — the
// MV3 service worker has no toast mechanism, and chrome.notifications would
// require a new manifest permission (intentionally not added).
function notifyTab(tabId, message, notificationType = "info") {
	chrome.tabs.sendMessage(
		tabId,
		{ type: "SHOW_NOTIFICATION", message, notificationType },
		() => {
			// Pages without a content script (chrome://, store pages, discarded
			// tabs) reject the message; a warning is the best available signal.
			if (chrome.runtime.lastError) {
				console.warn(
					"PwdVault: context-menu notification not delivered:",
					chrome.runtime.lastError.message,
				);
			}
		},
	);
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
	// Wrap everything: a throw inside this listener would only surface as a
	// silent unhandled rejection in the service worker console.
	try {
		if (
			info.menuItemId !== "pwdvault-fill" &&
			info.menuItemId !== "pwdvault-generate"
		) {
			return;
		}

		// Without a URL there is nothing to filter entries against (fill), and
		// even generate needs a live tab to report into.
		if (!tab || !tab.url || !tab.id) {
			console.warn(
				"PwdVault: context-menu action skipped — active tab has no URL/id",
			);
			return;
		}

		const unlocked = await isVaultUnlocked().catch(() => false);
		if (!unlocked) {
			notifyTab(tab.id, "Vault is locked", "error");
			return;
		}

		if (info.menuItemId === "pwdvault-fill") {
			const entries = await getEntriesForUrl(tab.url);
			if (entries.length > 0) {
				const entry = await getEntry(entries[0].id);
				if (!entry) {
					// The entry was deleted between listing and fetching.
					notifyTab(tab.id, "Entry no longer available", "error");
					return;
				}
				// SF-P1: never send an empty password — a blank AUTOFILL used to
				// fill the form and still report success to the user.
				if (!entry.password) {
					notifyTab(
						tab.id,
						"Failed to fetch password (is the desktop app unlocked?)",
						"error",
					);
					return;
				}
				chrome.tabs.sendMessage(tab.id, {
					type: "AUTOFILL",
					username: entry.username,
					password: entry.password,
					// The content script's domain gate rejects AUTOFILL without the
					// entry URL (fail closed). getEntriesForUrl above guarantees a
					// non-empty entry.url on this path.
					entryUrl: entry.url,
					// v1.5.0: the entry's per-URL match override rides along; the
					// content script falls back to "auto" when absent.
					match_mode: entry.url_match_mode,
				});
			}
		} else {
			const password = await generatePassword();
			chrome.tabs.sendMessage(tab.id, {
				type: "INSERT_PASSWORD",
				password,
			});
		}
	} catch (error) {
		// M12: never silent — but the SW has no UI channel, so log and stop.
		console.error("PwdVault: context-menu action failed:", error);
		if (tab && tab.id) {
			// SF-P1: getEntry throws the typed SECRET_FETCH_FAILED error when
			// the secret fetch fails (e.g. the vault locked between the unlock
			// check and the fetch) — give it the same actionable copy as the
			// empty-password guard instead of the generic "see app logs".
			notifyTab(
				tab.id,
				error?.message?.startsWith("SECRET_FETCH_FAILED")
					? "Failed to fetch password (is the desktop app unlocked?)"
					: "PwdVault action failed — see app logs",
				"error",
			);
		}
	}
});

// ============================================================================
// Message Handling
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
	handleMessage(message, sender)
		.then(sendResponse)
		.catch((error) => sendResponse({ error: error.message }));
	return true; // Keep channel open for async response
});

async function handleMessage(message, sender) {
	const authorization = authorizeMessage(message, sender, chrome.runtime.id);

	switch (message.type) {
		case "GET_STATUS": {
			// The three probes are independent — run them concurrently instead
			// of paying three serial native-messaging round-trips.
			const [status, initialized, unlocked] = await Promise.all([
				checkConnection(),
				isVaultInitialized().catch(() => false),
				isVaultUnlocked().catch(() => false),
			]);
			return { status, initialized, unlocked, error: lastConnectionError };
		}

		case "UNLOCK_VAULT":
			return unlockVault(message.password);

		case "LOCK_VAULT":
			return lockVault();

		case "CREATE_ENTRY":
			return createEntry(message.entry);

		case "GET_ENTRIES":
			return getEntries();

		case "GET_ENTRIES_FOR_URL":
			return getEntriesForUrl(
				authorization.senderKind === "content"
					? authorization.senderUrl
					: message.url,
			);

		case "GET_ENTRY":
			return authorization.senderKind === "content"
				? getEntryForSender(message.id, authorization.senderUrl)
				: getEntry(message.id);

		case "CHECK_SAVE_CREDENTIALS":
			// v1.6.0 save prompt: digest-only desktop verification. The
			// whitelist (sender-auth.js) gates content senders; this case
			// never sees plaintext.
			return checkSaveCredentials(message);

		case "SAVE_LOGIN_CONFIRMED": {
			// v1.6.0 save prompt: the user clicked Save/Update on the in-page
			// bar. mode=create stores a fresh entry; mode=update whole-replaces
			// with the entry's own metadata echoed. Errors surface through the
			// listener's {error: message} catch (SF-P1 pattern).
			if (message.mode === "update") {
				await updateEntryFromPrompt(message);
				return { ok: true };
			}
			await createEntry({
				title: titleForUrl(message.url),
				url: message.url,
				username: message.username,
				password: message.password,
				notes: null,
				tags: [],
				group_id: null,
			});
			return { ok: true };
		}

		case "GENERATE_PASSWORD":
			return generatePassword(message.options);

		case "GET_GROUPS":
			return getGroups();

		case "GET_SETTINGS":
			return getSettings();

		case "AUTOFILL": {
			// Dead code (verified 2026-09, re-verified 2026-10 v1.5.0): every
			// AUTOFILL sender targets the tab directly via
			// chrome.tabs.sendMessage (popup.js autofill, the context-menu
			// handler and the keyboard command below) — nothing relays through
			// the background. Kept deliberately: removing it is out of scope
			// here. If it is ever revived, it MUST forward message.entryUrl —
			// the content script rejects AUTOFILL without it (fail closed) —
			// and message.match_mode (v1.5.0; the content script defaults its
			// absence to "auto", forwarded here as-is).
			const [tab] = await chrome.tabs.query({
				active: true,
				currentWindow: true,
			});
			if (tab) {
				chrome.tabs.sendMessage(tab.id, {
					type: "AUTOFILL",
					username: message.username,
					password: message.password,
					match_mode: message.match_mode,
				});
			}
			return { success: true };
		}

		case "START_PAIRING": {
			const pairResult = await startPairing();
			return {
				result: pairResult,
				status: connectionStatus,
				error: lastConnectionError,
			};
		}

		case "PAIR_CONFIRM": {
			const ok = await pairConfirm(message.code);
			if (ok) {
				return { success: true };
			}
			// Surface the classified reason (wrong code vs. connection problem)
			// through the popup's existing result.error channel.
			return {
				success: false,
				error: lastConnectionError || "Invalid or expired code",
			};
		}

		case "GET_PAIRING_PENDING":
			return {
				pending: !!(await restorePendingPairNonce()),
				fresh: await pendingPairingFresh(),
			};

		case "CLIPBOARD_ARM_CLEAR": {
			// Purely internal message from the popup: schedule the 30s
			// digest-checked clipboard clear in this background context. It
			// must never touch the desktop native-messaging channel. Popup-only
			// senders are enforced by sender-auth.js (content scripts cannot
			// reach this case).
			return armClipboardClear(await clipboardClearDeps(), {
				digest: message.digest,
				deadline: message.deadline,
			});
		}

		case "CONSUME_CLIPBOARD_CLEAR_FAILURE": {
			// Notify-once read-and-clear of the sticky "last auto-clear failed"
			// marker; the popup toasts when `failed` is true.
			const storage = await clipboardArmStoragePromise;
			return { failed: await storage.consumeClearFailed() };
		}

		default:
			throw new Error(`Unknown message type: ${message.type}`);
	}
}

// ============================================================================
// Clipboard Auto-Clear Alarm
// ============================================================================

// Wakes for both the 30s deadline and the 5s single retry (see
// clipboard-clear.js). The alarm listener is what keeps the clear alive
// across service-worker suspensions — an alarm firing wakes this worker.
chrome.alarms.onAlarm.addListener((alarm) => {
	clipboardClearDeps()
		.then((deps) => handleClipboardClearAlarm(deps, alarm?.name))
		.catch((error) =>
			console.error("PwdVault: clipboard auto-clear failed:", error),
		);
});

// ============================================================================
// Keyboard Shortcuts
// ============================================================================

chrome.commands.onCommand.addListener(async (command) => {
	if (command === "autofill") {
		const [tab] = await chrome.tabs.query({
			active: true,
			currentWindow: true,
		});
		if (tab) {
			try {
				const entries = await getEntriesForUrl(tab.url);
				if (entries.length > 0) {
					const entry = await getEntry(entries[0].id);
					// SF-P1: guard before sending — a null entry used to crash on
					// `entry.username` (TypeError silently swallowed by this catch)
					// and an empty password filled a blank credential while still
					// reporting success.
					if (!entry || !entry.password) {
						notifyTab(
							tab.id,
							"Failed to fetch password (is the desktop app unlocked?)",
							"error",
						);
						return;
					}
					chrome.tabs.sendMessage(tab.id, {
						type: "AUTOFILL",
						username: entry.username,
						password: entry.password,
						// Content script rejects AUTOFILL without the entry URL
						// (fail closed). getEntriesForUrl guarantees non-empty.
						entryUrl: entry.url,
						// v1.5.0: the entry's per-URL match override rides along.
						match_mode: entry.url_match_mode,
					});
				}
			} catch (error) {
				console.error("Autofill failed:", error);
				// SF-P1: getEntry throws the typed SECRET_FETCH_FAILED error when
				// the secret fetch fails (e.g. vault locked) — surface it on the
				// page instead of staying console-only.
				if (
					tab &&
					tab.id &&
					error?.message?.startsWith("SECRET_FETCH_FAILED")
				) {
					notifyTab(
						tab.id,
						"Failed to fetch password (is the desktop app unlocked?)",
						"error",
					);
				}
			}
		}
	}
});

// ============================================================================
// Initialization
// ============================================================================

// NOTE: Do NOT call checkConnection() on service worker startup. In MV3 the
// service worker is terminated and restarted frequently; each restart would
// trigger `pair` (via checkConnection → pairWithApp), creating a new session
// and invalidating any code the desktop app is currently displaying. Pairing
// is initiated explicitly by the popup via START_PAIRING when the user is
// ready to enter the code.

chrome.runtime.onInstalled.addListener((details) => {
	setupContextMenu();
	// Only clear the token on a genuine first install. Clearing on every
	// `onInstalled` (which also fires for updates and Chrome updates) would
	// force the user to re-pair after every extension upgrade, even though
	// the persisted token is still valid.
	if (details.reason === "install") {
		saveToken(null);
	}
});

chrome.runtime.onStartup.addListener(() => {
	setupContextMenu();
	// Restore when the selected browser storage area supports it. Session
	// storage normally starts empty after a full browser restart.
	restoreToken();
});

// Service worker startup (including restarts after being killed by Chrome
// for idleness): restore the token before serving any popup requests.
// restoreToken is async but we don't await here — the popup will retry
// GET_STATUS and checkConnection will handle the not-yet-restored case.
setupContextMenu();
restoreToken();
