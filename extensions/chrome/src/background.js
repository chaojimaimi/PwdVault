// PwdVault Background Service Worker
// Handles communication between content scripts, popup, and desktop app via
// Native Messaging (the browser spawns a host binary that bridges to the
// desktop app's local HTTP API on 127.0.0.1:17429).

import { authorizeMessage, entryMatchesSenderUrl } from "./sender-auth.js";
import { createTokenStorage } from "./token-storage.js";
import { createPairNonceStorage } from "./pair-nonce-storage.js";
import {
	friendlyConnectionError,
	isAuthenticationError,
} from "./connection-errors.js";

// The native messaging host name; must match the "name" field in the manifest
// registered by the desktop app (native_host_setup.rs).
const NATIVE_HOST = "com.pwdvault.app";
const PROTOCOL_VERSION = 1;

// Storage key for retaining the pairing token across MV3 service-worker
// suspension. The preferred session area intentionally clears on a full
// browser restart.
const TOKEN_STORAGE_KEY = "pwdvault_api_token";
const tokenStoragePromise = createTokenStorage(
	chrome.storage,
	TOKEN_STORAGE_KEY,
);

// The pending pairing nonce is also persisted to session storage so
// `pair_confirm` still works after the service worker is killed while the
// user is typing the 6-digit code displayed by the desktop app.
const PAIR_NONCE_STORAGE_KEY = "pwdvault_pair_nonce";
const pairNonceStoragePromise = createPairNonceStorage(
	chrome.storage,
	PAIR_NONCE_STORAGE_KEY,
);

let connectionStatus = "disconnected";
let requestId = 0;
let apiToken = null;
let pendingPairNonce = null;
let lastConnectionError = null;

// Memory cache stays the fast path; session storage is the suspension-proof
// backing store (same pattern as saveToken/restoreToken above).
function savePendingPairNonce(nonce) {
	pendingPairNonce = nonce || null;
	void pairNonceStoragePromise
		.then((storage) => storage.save(nonce))
		.catch(() => {});
}

async function restorePendingPairNonce() {
	if (pendingPairNonce) return pendingPairNonce;
	try {
		const storage = await pairNonceStoragePromise;
		pendingPairNonce = await storage.load();
	} catch {
		// ignore — memory-only fallback
	}
	return pendingPairNonce;
}

// Persist in trusted-context-only storage. Session storage survives MV3 worker
// suspension but intentionally clears on browser restart. If a browser cannot
// enforce trusted-context access, the token remains memory-only.
function saveToken(token) {
	apiToken = token;
	void tokenStoragePromise
		.then((storage) => storage.save(token))
		.catch(() => {});
}

async function restoreToken() {
	try {
		const storage = await tokenStoragePromise;
		const token = await storage.load();
		if (token) {
			apiToken = token;
			return true;
		}
	} catch (e) {
		// ignore
	}
	return false;
}

// ============================================================================
// Native Messaging Communication
// ============================================================================

// sendNativeMessage is promise-based in Firefox (chrome.runtime.sendMessage is
// promise-based too in MV3). We wrap it to normalize the response shape and
// apply a timeout so a hung host doesn't block the caller indefinitely.
const NM_TIMEOUT_MS = 30000;

function sendNativeMessageP(message) {
	return new Promise((resolve, reject) => {
		let settled = false;
		const timer = setTimeout(() => {
			if (!settled) {
				settled = true;
				chrome.runtime.lastError; // clear any pending error
				reject(new Error("Native messaging host timed out"));
			}
		}, NM_TIMEOUT_MS);

		try {
			chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);

				if (chrome.runtime.lastError) {
					reject(new Error(chrome.runtime.lastError.message));
					return;
				}
				resolve(response);
			});
		} catch (e) {
			if (!settled) {
				settled = true;
				clearTimeout(timer);
				reject(e);
			}
		}
	});
}

// Pairing flow: pair → desktop app shows 6-digit code → user enters code
// in popup → pair_confirm → server returns API token.
// Returns 'paired' | 'needs_code' | 'failed'.
async function pairWithApp() {
	try {
		// X1: three distinct handshake outcomes. Throwing (host failed to
		// launch / timed out / connection refused) falls through to the catch
		// below, which maps via the shared friendlyConnectionError copy.
		const handshake = await sendNativeMessageP({
			id: 0,
			protocol_version: PROTOCOL_VERSION,
			command: "handshake",
		});
		if (!handshake) {
			// Host answered with no payload — treat as a connection failure,
			// not a version mismatch. A synthetic error is fed through the
			// existing mapping so the wording stays in one place.
			lastConnectionError = friendlyConnectionError(
				new Error("failed to connect to the PwdVault desktop app"),
			);
			return "failed";
		}
		if (!handshake.success) {
			// The host is alive and rejected the request — prefer the
			// desktop-provided reason (NativeResponse carries
			// error_message/error) over the version-mismatch copy.
			lastConnectionError = friendlyConnectionError(
				handshake.error_message ||
					handshake.error ||
					"PwdVault protocol versions do not match. Update the desktop app and extension.",
			);
			return "failed";
		}
		if (handshake.data?.protocol_version !== PROTOCOL_VERSION) {
			lastConnectionError =
				"PwdVault protocol versions do not match. Update the desktop app and extension.";
			return "failed";
		}
		const data = await sendNativeMessageP({
			id: 0,
			protocol_version: PROTOCOL_VERSION,
			command: "pair",
		});
		if (data && data.success && data.data) {
			if (data.data.token) {
				saveToken(data.data.token);
				lastConnectionError = null;
				return "paired";
			}
			if (data.data.pending) {
				savePendingPairNonce(data.data.session_nonce || null);
				if (!pendingPairNonce) return "failed";
				return "needs_code";
			}
		}
		lastConnectionError = friendlyConnectionError(
			data?.error_message || data?.error || "Pairing request failed",
		);
		return "failed";
	} catch (error) {
		lastConnectionError = friendlyConnectionError(error);
		return "failed";
	}
}

// Submit the user-entered 6-digit code to complete pairing. The nonce is
// re-read from storage so a suspended-and-restarted service worker can still
// finish a pairing session. A failed attempt keeps the nonce so the user can
// retry the same code; only success clears it. Every failure leaves a
// coherent `lastConnectionError` behind so the popup can distinguish "wrong
// code" from "cannot reach the desktop app" instead of always blaming the code.
async function pairConfirm(code) {
	const nonce = await restorePendingPairNonce();
	if (!nonce) return false;
	// Clear the sticky error first: a stale "cannot reach the app" from an
	// earlier attempt must not masquerade as this attempt's outcome.
	lastConnectionError = null;
	try {
		const data = await sendNativeMessageP({
			id: 0,
			protocol_version: PROTOCOL_VERSION,
			command: "pair_confirm",
			code,
			session_nonce: nonce,
		});
		if (data && data.success && data.data && data.data.token) {
			saveToken(data.data.token);
			savePendingPairNonce(null);
			return true;
		}
		// Host answered but refused — prefer the desktop-provided reason.
		lastConnectionError = friendlyConnectionError(
			data?.error_message || data?.error || "Invalid or expired code",
		);
		return false;
	} catch (error) {
		// Host failed to launch / timed out / unreachable — classify via the
		// shared connection copy so the popup reports a connection problem
		// instead of blaming the code.
		lastConnectionError = friendlyConnectionError(error);
		return false;
	}
}

// Fresh window matches the server's 30s pairing-session TTL with a safety
// margin: within it the desktop app may still be displaying the code, so an
// implicit new `pair` (which overwrites that code) must not be sent.
const PAIRING_FRESH_MS = 25_000;

// True when a pairing session was started recently and not yet consumed —
// the popup must not auto-request a competing code, only offer "Get New Code".
async function pendingPairingFresh() {
	try {
		const storage = await pairNonceStoragePromise;
		const entry = await storage.loadEntry();
		if (!entry) return false;
		return Date.now() - entry.savedAt <= PAIRING_FRESH_MS;
	} catch {
		return false;
	}
}

async function sendToApp(command, params = {}) {
	const id = ++requestId;

	// Pairing commands bypass auth; all other commands require a token.
	if (!apiToken && command !== "pair" && command !== "pair_confirm") {
		throw new Error("Not paired with desktop app");
	}

	// Native Messaging has no HTTP headers, so the Bearer token travels in the
	// body as `auth_token`. The host binary lifts it into an Authorization header
	// before forwarding to the desktop app's HTTP API.
	const message = {
		id,
		protocol_version: PROTOCOL_VERSION,
		command,
		...params,
	};
	if (apiToken) {
		message.auth_token = apiToken;
	}

	try {
		const data = await sendNativeMessageP(message);

		if (data && data.success) {
			connectionStatus = "connected";
			lastConnectionError = null;
			return data.data;
		} else {
			throw new Error(
				(data && (data.error_message || data.error)) || "Unknown error",
			);
		}
	} catch (error) {
		const msg = error.message || "";
		if (
			msg.includes("native messaging") ||
			msg.includes("not found") ||
			msg.includes("timed out") ||
			msg.includes("connect")
		) {
			connectionStatus = "disconnected";
			throw new Error(friendlyConnectionError(error));
		}
		throw error;
	}
}

async function checkConnection() {
	// Ensure the persisted token is restored before evaluating connection
	// state. The service worker may have just been spun up by Chrome and
	// `restoreToken()` (called fire-and-forget at SW startup) may not have
	// completed yet. Without this await, the popup would see `apiToken === null`
	// and wrongly force the user back into the pairing flow.
	await restoreToken();

	// If we have a token, verify it still works.
	if (apiToken) {
		try {
			await sendToApp("is_vault_initialized");
			connectionStatus = "connected";
			lastConnectionError = null;
			return connectionStatus;
		} catch (error) {
			lastConnectionError = friendlyConnectionError(error);
			// Only authentication rejection invalidates a pairing token. A stopped
			// desktop app or a temporary host failure must not force re-pairing.
			if (isAuthenticationError(error)) {
				saveToken(null);
			} else {
				connectionStatus = "disconnected";
				return connectionStatus;
			}
		}
	}
	// No token — needs pairing. Do NOT call `pair` here: each `pair` call
	// creates a new session and overwrites the previous code, invalidating
	// any code the desktop app is currently displaying. The popup must
	// trigger pairing explicitly via START_PAIRING when the user is ready
	// to enter the code.
	connectionStatus = "needs_pairing";
	return connectionStatus;
}

// Explicitly initiate pairing: asks the desktop app to display a 6-digit
// code. Should be called only when the user is on the pairing screen and
// ready to enter the code, to avoid creating competing sessions.
async function startPairing() {
	const result = await pairWithApp();
	if (result === "paired") {
		connectionStatus = "connected";
	} else if (result === "needs_code") {
		connectionStatus = "needs_pairing";
	} else {
		connectionStatus = "disconnected";
	}
	return result;
}

// ============================================================================
// API Wrappers
// ============================================================================

async function isVaultInitialized() {
	return sendToApp("is_vault_initialized");
}

async function isVaultUnlocked() {
	return sendToApp("is_vault_unlocked");
}

async function initVault(password) {
	return sendToApp("init_vault", { password });
}

async function unlockVault(password) {
	return sendToApp("unlock_vault", { password });
}

async function lockVault() {
	const result = await sendToApp("lock_vault");
	let tabs = [];
	try {
		tabs = await chrome.tabs.query({});
	} catch {
		// Locking the desktop vault succeeded; tab cleanup is best effort.
	}
	await Promise.allSettled(
		tabs.map((tab) =>
			typeof tab.id === "number"
				? chrome.tabs.sendMessage(tab.id, { type: "VAULT_LOCKED" })
				: Promise.resolve(),
		),
	);
	return result;
}

async function createEntry(entry) {
	return sendToApp("create_entry", {
		title: entry.title,
		url: entry.url,
		username: entry.username,
		password: entry.password,
		notes: entry.notes,
		tags: entry.tags || [],
		group_id: entry.group_id || null,
	});
}

// Group API wrappers
async function getGroups() {
	return sendToApp("list_all_groups");
}

async function createGroup(name) {
	return sendToApp("create_group", { name });
}

async function updateGroup(id, name) {
	return sendToApp("update_group", { id_param: id, name });
}

async function deleteGroup(id) {
	return sendToApp("remove_group", { id_param: id });
}

async function getSettings() {
	return sendToApp("get_settings");
}

async function updateSettings(settings) {
	return sendToApp("update_settings", { settings });
}

async function exportVault(exportPassword) {
	return sendToApp("export_vault", { export_password: exportPassword });
}

async function importVault(backup, importPassword) {
	return sendToApp("import_vault", { backup, import_password: importPassword });
}

async function getEntries() {
	return sendToApp("list_all_entries");
}

async function getEntry(id) {
	// B4 split get_entry into get_entry_meta (no password) and get_entry_secret
	// (password/notes/last_used_at). Fetch both and merge so callers keep
	// getting the full entry shape they expect.
	//
	// Use allSettled so a secret-fetch failure (e.g. transient backend error)
	// does not take down the meta fetch — the user still sees title/username/url,
	// and password simply falls back to empty.
	const [metaRes, secretRes] = await Promise.allSettled([
		sendToApp("get_entry_meta", { id_param: id }),
		sendToApp("get_entry_secret", { id_param: id }),
	]);
	if (metaRes.status !== "fulfilled" || !metaRes.value) return null;
	const secret = secretRes.status === "fulfilled" ? secretRes.value : null;
	return {
		...metaRes.value,
		password: secret ? secret.password : "",
		notes: secret ? secret.notes : null,
		last_used_at: secret ? secret.last_used_at : null,
	};
}

async function getEntryForSender(id, senderUrl) {
	// Fetch metadata first. Never request the secret until the entry URL has
	// been proven to match the content script's browser-supplied tab URL.
	const meta = await sendToApp("get_entry_meta", { id_param: id });
	if (!meta || !entryMatchesSenderUrl(meta, senderUrl)) {
		throw new Error("Entry is not authorized for this site");
	}
	const secret = await sendToApp("get_entry_secret", { id_param: id });
	return {
		...meta,
		password: secret?.password || "",
		notes: secret?.notes ?? null,
		last_used_at: secret?.last_used_at ?? null,
	};
}

async function getEntriesForUrl(url) {
	const entries = await getEntries();
	const urlObj = new URL(url);
	// Anchored so only a leading "www." is stripped (matches sender-auth.js).
	const domain = urlObj.hostname.replace(/^www\./, "");

	return entries.filter((entry) => {
		if (!entry.url) return false;
		try {
			const entryDomain = new URL(entry.url).hostname.replace(/^www\./, "");
			return entryDomain === domain;
		} catch {
			return false;
		}
	});
}

async function generatePassword(options = {}) {
	return sendToApp("generate_password", {
		options: {
			length: options.length || 16,
			include_uppercase: options.uppercase !== false,
			include_lowercase: options.lowercase !== false,
			include_numbers: options.numbers !== false,
			include_symbols: options.symbols !== false,
		},
	});
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
		if (info.menuItemId !== "pwdvault-fill" && info.menuItemId !== "pwdvault-generate") {
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
				chrome.tabs.sendMessage(tab.id, {
					type: "AUTOFILL",
					username: entry.username,
					password: entry.password,
					// The content script's domain gate rejects AUTOFILL without the
					// entry URL (fail closed). getEntriesForUrl above guarantees a
					// non-empty entry.url on this path.
					entryUrl: entry.url,
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
			notifyTab(tab.id, "PwdVault action failed — see app logs", "error");
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
		case "GET_STATUS":
			const status = await checkConnection();
			return {
				status,
				initialized: await isVaultInitialized().catch(() => false),
				unlocked: await isVaultUnlocked().catch(() => false),
				error: lastConnectionError,
			};

		case "INIT_VAULT":
			return initVault(message.password);

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

		case "GENERATE_PASSWORD":
			return generatePassword(message.options);

		case "GET_GROUPS":
			return getGroups();

		case "CREATE_GROUP":
			return createGroup(message.name);

		case "UPDATE_GROUP":
			return updateGroup(message.id, message.name);

		case "DELETE_GROUP":
			return deleteGroup(message.id);

		case "GET_SETTINGS":
			return getSettings();

		case "UPDATE_SETTINGS":
			return updateSettings(message.settings);

		case "EXPORT_VAULT":
			return exportVault(message.exportPassword);

		case "IMPORT_VAULT":
			return importVault(message.backup, message.importPassword);

		case "AUTOFILL":
			// Dead code (verified 2026-09): every AUTOFILL sender targets the
			// tab directly via chrome.tabs.sendMessage (popup.js autofill, the
			// context-menu handler and the keyboard command below) — nothing
			// relays through the background. Kept deliberately: removing it is
			// out of scope here. If it is ever revived, it MUST forward
			// message.entryUrl — the content script rejects AUTOFILL without
			// it (fail closed).
			const [tab] = await chrome.tabs.query({
				active: true,
				currentWindow: true,
			});
			if (tab) {
				chrome.tabs.sendMessage(tab.id, {
					type: "AUTOFILL",
					username: message.username,
					password: message.password,
				});
			}
			return { success: true };

		case "CONNECT":
			return { status: await checkConnection(), error: lastConnectionError };

		case "START_PAIRING":
			const pairResult = await startPairing();
			return {
				result: pairResult,
				status: connectionStatus,
				error: lastConnectionError,
			};

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

		default:
			throw new Error(`Unknown message type: ${message.type}`);
	}
}

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
					chrome.tabs.sendMessage(tab.id, {
						type: "AUTOFILL",
						username: entry.username,
						password: entry.password,
						// Content script rejects AUTOFILL without the entry URL
						// (fail closed). getEntriesForUrl guarantees non-empty.
						entryUrl: entry.url,
					});
				}
			} catch (error) {
				console.error("Autofill failed:", error);
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
// CONNECT and checkConnection will handle the not-yet-restored case.
setupContextMenu();
restoreToken();
