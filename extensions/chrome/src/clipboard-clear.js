// Clipboard auto-clear engine for the extension background.
//
// The popup used to own the 30s auto-clear with a local setTimeout, but an
// MV3 popup is destroyed the moment it closes — the timer died with it and
// the promised clear never fired. The clear now lives here: the popup arms a
// single pending window (digest + deadline), an alarm wakes the background at
// the deadline, and the clipboard is verified against the digest before being
// overwritten so a secret the user copied afterwards is never destroyed.
//
// Clear execution is platform-split:
//   Chrome — an offscreen document (reason "CLIPBOARD") reads the clipboard
//            and writes "" after a digest match.
//   Firefox — no offscreen API; the background event page has a DOM, so a
//            hidden textarea + execCommand paste/copy does the same.
//
// All browser APIs arrive injected via `deps` (same pattern as
// createTokenStorage taking the storage area), which keeps the engine unit
// testable without a real extension context.

// Alarm names are namespaced like the storage keys below. A distinct retry
// alarm survives service-worker restarts (setTimeout would not).
export const CLIPBOARD_CLEAR_ALARM = "pwdvault-clipboard-clear";
export const CLIPBOARD_CLEAR_RETRY_ALARM = "pwdvault-clipboard-clear-retry";

// Matches the desktop app's 30s clipboard window (src/utils/clipboard.ts).
export const CLIPBOARD_CLEAR_DELAY_MS = 30_000;
// Single bounded retry for transient failures (offscreen document creation
// races, a momentarily unreachable message port). Chrome 120+ clamps alarm
// delays below 30s up to 30s, so the retry may fire late — acceptable: the
// arm record persists and the digest check keeps any late clear safe.
export const CLIPBOARD_CLEAR_RETRY_DELAY_MS = 5_000;

// Trusted-context-only session storage keys (same trust level as the API
// token: content scripts cannot read them).
export const ARM_STORAGE_KEY = "pwdvault_clipboard_arm";
export const CLEAR_FAILED_STORAGE_KEY = "pwdvault_clipboard_clear_failed";

// The popup arms with a SHA-256 hex digest; anything else is a protocol
// violation and must be refused rather than stored.
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
// Sane upper bound on an accepted deadline — far beyond the 30s window, tight
// enough that a hostile or buggy arm cannot park a clipboard overwrite far in
// the future.
const MAX_ARM_HORIZON_MS = 10 * 60_000;

const OFFSCREEN_URL = "src/offscreen/clipboard.html";
const CLIPBOARD_CLEAR_PING = "CLIPBOARD_CLEAR_PING";

// ============================================================================
// Arm record storage (pair-nonce-storage.js pattern: session area preferred,
// in-memory closure fallback so a single service-worker lifetime still works).
// ============================================================================

export async function createClipboardArmStorage(
	storageApi,
	armKey = ARM_STORAGE_KEY,
	failedKey = CLEAR_FAILED_STORAGE_KEY,
) {
	let area = null;

	if (storageApi?.session) {
		try {
			// Match token-storage.js: keep the values trusted-context-only where
			// the API is supported so content scripts cannot read them.
			if (typeof storageApi.session.setAccessLevel === "function") {
				await storageApi.session.setAccessLevel({
					accessLevel: "TRUSTED_CONTEXTS",
				});
			}
			area = storageApi.session;
		} catch {
			area = null;
		}
	}

	// Memory fallback mirrors the token/pair-nonce trade-off: no cross-restart
	// persistence, but arm → clear still works within this worker's lifetime.
	let memoryArm = null;
	let memoryFailed = false;

	return {
		kind: area ? "session" : "memory",
		async loadArm() {
			if (!area) return memoryArm;
			try {
				const result = await area.get(armKey);
				const value = result?.[armKey];
				if (!value || typeof value !== "object") return null;
				return { digest: value.digest, deadline: Number(value.deadline) };
			} catch {
				// Unreadable record behaves like a missing one (orphan-safe skip).
				return null;
			}
		},
		async saveArm(arm) {
			if (!area) {
				memoryArm = arm;
				return;
			}
			try {
				await area.set({ [armKey]: arm });
			} catch {
				// Best effort: the alarm handler treats a missing record as an
				// orphan and skips — it never touches the clipboard blindly.
			}
		},
		async clearArm() {
			if (!area) {
				memoryArm = null;
				return;
			}
			try {
				await area.remove(armKey);
			} catch {
				// Best effort: a stale record is orphan-safe on the next alarm.
			}
		},
		async markClearFailed() {
			if (!area) {
				memoryFailed = true;
				return;
			}
			try {
				await area.set({ [failedKey]: { at: Date.now() } });
			} catch {
				// The popup toast is best-effort; the failed clear itself was
				// already logged by the alarm handler.
			}
		},
		// Read-and-remove in one step: the popup consumes the marker exactly
		// once (notify-once, same contract as the desktop's clipboard utility).
		async consumeClearFailed() {
			if (!area) {
				const had = memoryFailed;
				memoryFailed = false;
				return had;
			}
			try {
				const result = await area.get(failedKey);
				const had = Boolean(result?.[failedKey]);
				if (had) await area.remove(failedKey);
				return had;
			} catch {
				return false;
			}
		},
	};
}

// ============================================================================
// Digest
// ============================================================================

// Shared SHA-256 hex digest (same construction as the desktop and the old
// popup-local helper) — popup arms with it, offscreen/event-page verifies it.
export async function digestText(text) {
	const bytes = new TextEncoder().encode(text);
	const digest = await crypto.subtle.digest("SHA-256", bytes);
	return Array.from(new Uint8Array(digest), (byte) =>
		byte.toString(16).padStart(2, "0"),
	).join("");
}

// ============================================================================
// Arm / alarm lifecycle
// ============================================================================

// Schedule the clear for one copied secret. Re-arming overwrites the previous
// arm entirely (single pending window): new record, recreated main alarm, and
// any leftover retry alarm from an earlier failed cycle is cancelled so a
// stale retry cannot fire early against the NEW secret.
export async function armClipboardClear(deps, { digest, deadline }) {
	if (typeof digest !== "string" || !DIGEST_PATTERN.test(digest)) {
		throw new Error("CLIPBOARD_ARM_CLEAR requires a SHA-256 hex digest");
	}
	const when = Number(deadline);
	const now = Date.now();
	if (
		!Number.isFinite(when) ||
		when <= now ||
		when > now + MAX_ARM_HORIZON_MS
	) {
		throw new Error("CLIPBOARD_ARM_CLEAR requires a near-future deadline");
	}

	await deps.storage.saveArm({ digest, deadline: when });
	await Promise.resolve(deps.alarms.create(CLIPBOARD_CLEAR_ALARM, { when }));
	await Promise.resolve(deps.alarms.clear(CLIPBOARD_CLEAR_RETRY_ALARM));
	return { armed: true };
}

// chrome.alarms.onAlarm entry point. Transient clear failures get exactly one
// bounded retry; a second failure records the popup-visible marker and gives
// up (notify-once, matching the desktop's clipboard utility).
export async function handleClipboardClearAlarm(deps, alarmName) {
	if (
		alarmName !== CLIPBOARD_CLEAR_ALARM &&
		alarmName !== CLIPBOARD_CLEAR_RETRY_ALARM
	) {
		return;
	}

	const arm = await deps.storage.loadArm();
	// Orphan / malformed (record consumed earlier, lost to a browser restart,
	// or missing digest/deadline): never touch the clipboard blindly — drop
	// the record and let the alarm die.
	if (
		!arm ||
		typeof arm.digest !== "string" ||
		!arm.digest ||
		!Number.isFinite(arm.deadline)
	) {
		await deps.storage.clearArm();
		return;
	}

	const isRetry = alarmName === CLIPBOARD_CLEAR_RETRY_ALARM;
	let outcome;
	try {
		outcome = await performClear(deps, arm.digest);
	} catch (error) {
		console.warn("PwdVault: clipboard auto-clear attempt failed:", error);
		if (!isRetry) {
			await Promise.resolve(
				deps.alarms.create(CLIPBOARD_CLEAR_RETRY_ALARM, {
					when: Date.now() + CLIPBOARD_CLEAR_RETRY_DELAY_MS,
				}),
			);
			return;
		}
		await deps.storage.markClearFailed();
		await deps.storage.clearArm();
		return;
	}

	// Either cleared, or the clipboard no longer holds our secret (digest
	// mismatch — the user copied something else and must keep it). The window
	// is done either way.
	await deps.storage.clearArm();
	return outcome;
}

// ============================================================================
// Platform clear paths
// ============================================================================

async function performClear(deps, digest) {
	if (deps.offscreen) {
		return clearViaOffscreenDocument(deps, digest);
	}
	return clearViaBackgroundDom(deps, digest);
}

// Chrome: verify + clear inside an offscreen document, which has the DOM and
// clipboard permissions a service worker lacks.
async function clearViaOffscreenDocument(deps, digest) {
	await ensureOffscreenDocument(deps);
	const response = await deps.runtime.sendMessage({
		type: CLIPBOARD_CLEAR_PING,
		digest,
	});
	if (!response || typeof response !== "object") {
		throw new Error("clipboard offscreen document did not respond");
	}
	if (response.cleared === true) {
		return { cleared: true };
	}
	if (response.reason === "digest-mismatch") {
		// Clipboard holds newer user content — leaving it alone is the
		// intended outcome, not a failure.
		return { cleared: false };
	}
	throw new Error(
		typeof response.reason === "string" && response.reason
			? response.reason
			: "clipboard clear failed inside offscreen document",
	);
}

// Create the offscreen document exactly once. chrome.runtime.getContexts
// (Chrome 116+) answers authoritatively; on 109–115 it does not exist, so the
// benign duplicate-creation error from createDocument is tolerated. Chrome's
// actual message is "Only a single offscreen document may be created per
// extension"; "already exists" is kept as a defensive alias.
async function ensureOffscreenDocument(deps) {
	if (typeof deps.runtime.getContexts === "function") {
		const contexts = await deps.runtime.getContexts({
			contextTypes: ["OFFSCREEN_DOCUMENT"],
		});
		if (Array.isArray(contexts) && contexts.length > 0) return;
		await deps.offscreen.createDocument({
			url: OFFSCREEN_URL,
			reasons: ["CLIPBOARD"],
			justification:
				"Verify and clear the PwdVault clipboard after its 30s auto-clear window",
		});
		return;
	}
	try {
		await deps.offscreen.createDocument({
			url: OFFSCREEN_URL,
			reasons: ["CLIPBOARD"],
			justification:
				"Verify and clear the PwdVault clipboard after its 30s auto-clear window",
		});
	} catch (error) {
		if (!/single offscreen document|already exists/i.test(error?.message || ""))
			throw error;
	}
}

// Firefox: the background event page has a DOM. Paste into a hidden textarea
// (requires clipboardRead), digest-check, then overwrite the clipboard with
// an empty copy. jsdom does not implement execCommand — tests stub it.
async function clearViaBackgroundDom(deps, digest) {
	const doc = deps.document;
	if (!doc || !doc.body) {
		throw new Error("background page DOM unavailable for clipboard clear");
	}

	const textarea = doc.createElement("textarea");
	textarea.setAttribute("aria-hidden", "true");
	textarea.value = "";
	// Offscreen and non-focusable-looking, but still a valid execCommand target.
	textarea.style.position = "fixed";
	textarea.style.top = "0";
	textarea.style.left = "0";
	textarea.style.opacity = "0";
	doc.body.appendChild(textarea);

	try {
		textarea.focus();
		textarea.select();
		if (!doc.execCommand("paste")) {
			throw new Error("execCommand paste was rejected");
		}
		const current = textarea.value;
		if ((await digestText(current)) !== digest) {
			// User copied something else inside the window — never overwrite it.
			return { cleared: false };
		}
		textarea.value = "";
		textarea.select();
		if (!doc.execCommand("copy")) {
			throw new Error("execCommand copy was rejected");
		}
		return { cleared: true };
	} finally {
		textarea.remove();
	}
}
