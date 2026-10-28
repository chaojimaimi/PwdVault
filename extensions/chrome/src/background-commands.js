// PwdVault Background — per-command desktop handlers.
// Imported by background.js (the service-worker entry). One exported handler
// per desktop command, every one funnelling through sendToApp
// (background-native.js). The v1.6.0 save/update cluster — including the
// session-sticky verifyUnsupported degradation flag — is kept WHOLE here:
// background-fill-gate.test.js and content-save-prompt.test.js assert on
// this file's source text.

import { entryMatchesSenderUrl } from "./sender-auth.js";
import { sendToApp } from "./background-native.js";

// ============================================================================
// API Wrappers
// ============================================================================

export async function isVaultInitialized() {
	return sendToApp("is_vault_initialized");
}

export async function isVaultUnlocked() {
	return sendToApp("is_vault_unlocked");
}

export async function unlockVault(password) {
	return sendToApp("unlock_vault", { password });
}

export async function lockVault() {
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

export async function createEntry(entry) {
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
export async function getGroups() {
	return sendToApp("list_all_groups");
}

export async function getSettings() {
	return sendToApp("get_settings");
}

export async function getEntries() {
	return sendToApp("list_all_entries");
}

export async function getEntry(id) {
	// B4 split get_entry into get_entry_meta (no password) and get_entry_secret
	// (password/notes/last_used_at). Fetch both and merge so callers keep
	// getting the full entry shape they expect.
	//
	// allSettled keeps the two fetches independent: a meta failure (or a falsy
	// meta — entry deleted between listing and fetching) still returns null.
	// A secret failure must NOT fall back to an empty password — that fallback
	// made autofill look successful with a blank credential (audit SF-P1), so
	// it throws a typed error that the UI paths translate into an actionable
	// "vault may be locked" message instead.
	const [metaRes, secretRes] = await Promise.allSettled([
		sendToApp("get_entry_meta", { id_param: id }),
		sendToApp("get_entry_secret", { id_param: id }),
	]);
	if (metaRes.status !== "fulfilled" || !metaRes.value) return null;
	if (secretRes.status === "rejected") {
		const reason = secretRes.reason;
		throw new Error(
			"SECRET_FETCH_FAILED: " + (reason?.message || "secret fetch failed"),
		);
	}
	const secret = secretRes.value;
	return {
		...metaRes.value,
		password: secret ? secret.password : "",
		notes: secret ? secret.notes : null,
		last_used_at: secret ? secret.last_used_at : null,
	};
}

export async function getEntryForSender(id, senderUrl) {
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

export async function getEntriesForUrl(url) {
	const entries = await getEntries();
	// v1.4.0: the third hand-rolled hostname comparison is gone — this filter
	// delegates to the STRICT gate (entryMatchesSenderUrl), not the wide one.
	// The strict gate rejects an empty entry.url, so generic entries (no
	// stored URL) can never appear in an auto-fill list — the invariant the
	// callers below rely on ("non-empty URL, fail closed") — and non-empty
	// URLs compare by registrable domain (eTLD+1) exactly like the
	// content-script path.
	return entries.filter((entry) => entryMatchesSenderUrl(entry, url));
}

// ============================================================================
// Save/Update Prompt (v1.6.0 WP4)
// ============================================================================

// Old desktop without verify_entry_password: the dispatcher answers
// "Unknown command" — the save-prompt feature silently disables for this
// service-worker session (no error toast, no retry storm). New-extension +
// old-desktop stays a working combination: auto-fill is unaffected.
let verifyUnsupported = false;

function isUnknownCommandError(error) {
	return (
		typeof error?.message === "string" &&
		error.message.trim().toLowerCase() === "unknown command"
	);
}

// Desktop-side verdict only: the stored password never leaves the vault and
// this worker never sees it — verify answers a single boolean. (The entry id
// rides in `id_param`, the protocol's established channel — `id` on the wire
// is the u32 request-correlation field.)
async function verifyEntryPassword(id, passwordSha256) {
	const result = await sendToApp("verify_entry_password", {
		id_param: id,
		password_sha256: passwordSha256,
	});
	return Boolean(result && result.matches);
}

// Judge the save/update decision for one submitted digest. Candidates arrive
// in the content script's username-match order; the FIRST candidate whose
// stored password does NOT match decides "update" (its title names the
// prompt). No plaintext crosses this boundary — digest + ids/titles only.
export async function checkSaveCredentials(message) {
	if (verifyUnsupported) return { action: "none" };
	const candidates = Array.isArray(message.candidates)
		? message.candidates
		: [];
	if (candidates.length === 0) return { action: "save" };
	if (typeof message.password_sha256 !== "string") {
		throw new Error("CHECK_SAVE_CREDENTIALS requires password_sha256");
	}
	try {
		// Serial on purpose: short-circuit on the first non-match keeps the
		// common "one candidate" and "all match" cases at ≤ candidate-count
		// verify round-trips.
		for (const candidate of candidates) {
			if (!candidate || typeof candidate.id !== "string") continue;
			const matches = await verifyEntryPassword(
				candidate.id,
				message.password_sha256,
			);
			if (!matches) {
				return {
					action: "update",
					entry_id: candidate.id,
					entry_title:
						typeof candidate.title === "string"
							? candidate.title
							: "the existing entry",
				};
			}
		}
		return { action: "none" };
	} catch (error) {
		if (isUnknownCommandError(error)) {
			verifyUnsupported = true;
			return { action: "none" };
		}
		throw error;
	}
}

// Whole-replace update from the page prompt. The desktop replaces
// title/url/username/tags/group_id/url_match_mode WHOLESALE, so each is
// echoed from the candidate summary captured at submit time; only the
// password is new. notes/custom_fields are omitted (tri-state = unchanged)
// and TOTP is desktop-only for the extension (the dispatcher pins None).
export async function updateEntryFromPrompt(message) {
	// Fail closed on a malformed payload (v1.6.0 review follow-up): this
	// command whole-replaces the entry metadata, so an absent metadata
	// object (undefined title/username on the wire) would blank the stored
	// fields, and an absent entry_id has no update address at all. The
	// error propagates through the listener's {error} catch to the in-page
	// bar (SF-P1 pattern). The echoed-field fallbacks below only run once
	// the shape is proven.
	if (
		!message.entry ||
		typeof message.entry !== "object" ||
		Array.isArray(message.entry)
	) {
		throw new Error("SAVE_LOGIN_CONFIRMED update is missing entry metadata");
	}
	if (typeof message.entry_id !== "string" || !message.entry_id) {
		throw new Error("SAVE_LOGIN_CONFIRMED update is missing entry_id");
	}
	const meta = message.entry;
	const matchMode = meta.url_match_mode;
	return sendToApp("update_entry", {
		id_param: message.entry_id,
		title: meta.title,
		username: meta.username,
		url: typeof meta.url === "string" ? meta.url : null,
		tags: Array.isArray(meta.tags) ? meta.tags : [],
		group_id: typeof meta.group_id === "string" ? meta.group_id : null,
		url_match_mode:
			matchMode === "exact" || matchMode === "domain" ? matchMode : undefined,
		password: message.password,
	});
}

// Create-mode title: the submitted URL's hostname (the content message
// intentionally carries no title — the page the credential was typed on is
// the honest label).
export function titleForUrl(rawUrl) {
	if (typeof rawUrl !== "string" || !rawUrl) return "Saved login";
	try {
		return new URL(rawUrl).hostname || rawUrl;
	} catch {
		return rawUrl;
	}
}

export async function generatePassword(options = {}) {
	// v1.4.0: the same command now dispatches on `mode` (password default —
	// old callers that never send a mode keep the historical behavior).
	// Passphrase/PIN-specific fields are forwarded when present; the desktop
	// applies its own serde defaults for anything absent.
	const generatorOptions = {
		length: options.length || 16,
		include_uppercase: options.uppercase !== false,
		include_lowercase: options.lowercase !== false,
		include_numbers: options.numbers !== false,
		include_symbols: options.symbols !== false,
	};
	if (options.mode) {
		generatorOptions.mode = options.mode;
	}
	if (options.words !== undefined) {
		generatorOptions.words = options.words;
	}
	if (options.separator !== undefined) {
		generatorOptions.separator = options.separator;
	}
	if (options.capitalize !== undefined) {
		generatorOptions.capitalize = options.capitalize;
	}
	if (options.appendNumber !== undefined) {
		generatorOptions.append_number = options.appendNumber;
	}
	return sendToApp("generate_password", { options: generatorOptions });
}
