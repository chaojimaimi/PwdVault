// PwdVault Background — Native Messaging transport + connection state.
// Imported by background.js (the service-worker entry) and
// background-commands.js. Owns the module-level transport state
// (connectionStatus / requestId / apiToken / pendingPairNonce /
// lastConnectionError): every WRITE stays in this module, and importers read
// the exported live bindings directly — the entry must never re-export them.

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

export let connectionStatus = "disconnected";
let requestId = 0;
let apiToken = null;
let pendingPairNonce = null;
export let lastConnectionError = null;

// Memory cache stays the fast path; session storage is the suspension-proof
// backing store (same pattern as saveToken/restoreToken above).
function savePendingPairNonce(nonce) {
	pendingPairNonce = nonce || null;
	void pairNonceStoragePromise
		.then((storage) => storage.save(nonce))
		.catch((e) => console.warn("pairing nonce save failed", e));
}

export async function restorePendingPairNonce() {
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
export function saveToken(token) {
	apiToken = token;
	void tokenStoragePromise
		.then((storage) => storage.save(token))
		.catch((e) => console.warn("token save failed", e));
}

export async function restoreToken() {
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
				reject(new Error("Native messaging host timed out"));
			}
		}, NM_TIMEOUT_MS);

		try {
			chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
				// Read lastError even on the timeout-abandoned path: leaving it
				// unread makes Chrome log an "Unchecked runtime.lastError"
				// warning for the abandoned callback.
				const asyncError = chrome.runtime.lastError;
				if (settled) return;
				settled = true;
				clearTimeout(timer);

				if (asyncError) {
					reject(new Error(asyncError.message));
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
export async function pairConfirm(code) {
	const nonce = await restorePendingPairNonce();
	if (!nonce) {
		// No persisted nonce means the pairing session cannot be resumed —
		// leave a coherent error instead of a bare failure the popup would
		// misreport as a wrong code.
		lastConnectionError = "Pairing session lost — restart pairing";
		return false;
	}
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
export async function pendingPairingFresh() {
	try {
		const storage = await pairNonceStoragePromise;
		const entry = await storage.loadEntry();
		if (!entry) return false;
		return Date.now() - entry.savedAt <= PAIRING_FRESH_MS;
	} catch {
		return false;
	}
}

export async function sendToApp(command, params = {}) {
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
			throw new Error(friendlyConnectionError(error), { cause: error });
		}
		throw error;
	}
}

export async function checkConnection() {
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
export async function startPairing() {
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
