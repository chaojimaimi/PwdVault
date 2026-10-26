const CONTENT_SCRIPT_COMMANDS = new Set(["GET_ENTRIES_FOR_URL", "GET_ENTRY"]);

// Commands that only the popup may send. They schedule clipboard destruction
// or control its failure reporting, so a content script (i.e. page-reachable
// code) must never reach them; the check below is fail-closed and kept
// explicit so the invariant survives future command additions.
const POPUP_ONLY_COMMANDS = new Set([
	"CLIPBOARD_ARM_CLEAR",
	"CONSUME_CLIPBOARD_CLEAR_FAILURE",
]);

export function classifySender(sender, runtimeId) {
	if (!sender || sender.id !== runtimeId) return "untrusted";
	if (sender.tab && typeof sender.tab.url === "string") return "content";

	if (typeof sender.url === "string") {
		try {
			const url = new URL(sender.url);
			const isExtensionPage =
				url.protocol === "chrome-extension:" ||
				url.protocol === "moz-extension:";
			if (isExtensionPage && url.pathname.endsWith("/src/popup/popup.html"))
				return "popup";
		} catch {
			// Fall through to untrusted.
		}
	}
	return "untrusted";
}

export function authorizeMessage(message, sender, runtimeId) {
	const senderKind = classifySender(sender, runtimeId);
	if (senderKind === "popup") return { senderKind, senderUrl: null };
	if (
		senderKind === "content" &&
		!POPUP_ONLY_COMMANDS.has(message?.type) &&
		CONTENT_SCRIPT_COMMANDS.has(message?.type)
	) {
		// Authorize against the frame URL (sender.url) — the document that
		// actually sent the message. For top-level frames it equals tab.url, and
		// if all_frames is ever enabled the authorization stays on the right
		// frame instead of the top-level page.
		return { senderKind, senderUrl: sender.url || sender.tab.url };
	}
	throw new Error("Message sender is not authorized for this operation");
}

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
export function registeredDomain(host) {
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

export function normalizedDomain(rawUrl) {
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

export function entryMatchesSenderUrl(entry, senderUrl) {
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
export function entryMatchesPageUrl(entry, pageUrl) {
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
