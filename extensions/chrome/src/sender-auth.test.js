import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	authorizeMessage,
	entryMatchesPageUrl,
	entryMatchesSenderUrl,
	normalizedDomain,
	registeredDomain,
} from "./sender-auth.js";

const RUNTIME_ID = "abcdefghijklmnopabcdefghijklmnop";

describe("extension sender authorization", () => {
	it("derives content URL from sender and allows only scoped read commands", () => {
		const sender = {
			id: RUNTIME_ID,
			tab: { url: "https://example.com/login" },
		};
		expect(
			authorizeMessage(
				{ type: "GET_ENTRIES_FOR_URL", url: "https://evil.test" },
				sender,
				RUNTIME_ID,
			),
		).toEqual({
			senderKind: "content",
			senderUrl: "https://example.com/login",
		});
		expect(() =>
			authorizeMessage({ type: "GET_ENTRIES" }, sender, RUNTIME_ID),
		).toThrow();
		expect(() =>
			authorizeMessage({ type: "EXPORT_VAULT" }, sender, RUNTIME_ID),
		).toThrow();
	});

	it("prefers the frame URL (sender.url) over the top-level tab URL", () => {
		const sender = {
			id: RUNTIME_ID,
			url: "https://login.example.com/inline-frame",
			tab: { url: "https://top.example.com/page" },
		};
		expect(
			authorizeMessage(
				{ type: "GET_ENTRY", id: "entry-1" },
				sender,
				RUNTIME_ID,
			),
		).toEqual({
			senderKind: "content",
			senderUrl: "https://login.example.com/inline-frame",
		});
	});

	it("rejects cross-domain entry IDs before secret retrieval", () => {
		expect(
			entryMatchesSenderUrl(
				{ url: "https://example.com/account" },
				"https://www.example.com/login",
			),
		).toBe(true);
		expect(
			entryMatchesSenderUrl(
				{ url: "https://other.test/login" },
				"https://example.com/login",
			),
		).toBe(false);
		expect(
			entryMatchesSenderUrl({ url: null }, "https://example.com/login"),
		).toBe(false);
	});

	it("matches subdomains of the same registrable domain (v1.4.0 eTLD+1)", () => {
		expect(
			entryMatchesSenderUrl(
				{ url: "https://example.com/account" },
				"https://accounts.example.com/login",
			),
		).toBe(true);
		expect(
			entryMatchesSenderUrl(
				{ url: "https://accounts.example.com" },
				"https://example.com/login",
			),
		).toBe(true);
	});

	it("keeps registrable domains under a multi-label suffix separate (co.uk)", () => {
		expect(
			entryMatchesSenderUrl(
				{ url: "https://example.co.uk" },
				"https://evil.co.uk/login",
			),
		).toBe(false);
		expect(
			entryMatchesSenderUrl(
				{ url: "https://login.example.co.uk" },
				"https://example.co.uk/login",
			),
		).toBe(true);
	});

	it("fails closed under an unlisted 2-letter ccTLD (exact host match only)", () => {
		// co.xx is NOT in the suffix table: tail-2 alone would treat these two
		// as one registrable domain — the leak the fail-closed rule prevents.
		expect(
			entryMatchesSenderUrl(
				{ url: "https://login.site.co.xx" },
				"https://evil.co.xx/login",
			),
		).toBe(false);
		expect(
			entryMatchesSenderUrl(
				{ url: "https://site.co.xx/login" },
				"https://site.co.xx/x",
			),
		).toBe(true);
	});

	it("matches scheme-less stored entry URLs on the content path (v1.2.4)", () => {
		// Same scheme-padding semantics as entryMatchesPageUrl — a scheme-less
		// entry must not be invisible to auto-fill while the popup can fill it.
		expect(
			entryMatchesSenderUrl(
				{ url: "github.com/acme" },
				"https://github.com/login",
			),
		).toBe(true);
		expect(
			entryMatchesSenderUrl(
				{ url: "other.test/login" },
				"https://github.com/login",
			),
		).toBe(false);
		// Empty entryUrl stays REJECTED — intentional divergence from
		// entryMatchesPageUrl: auto-fill without a user click needs a URL to
		// compare against.
		expect(
			entryMatchesSenderUrl({ url: "" }, "https://example.com/login"),
		).toBe(false);
		expect(entryMatchesSenderUrl({}, "https://example.com/login")).toBe(false);
	});

	it("accepts the popup but rejects another extension identity", () => {
		const popup = {
			id: RUNTIME_ID,
			url: `chrome-extension://${RUNTIME_ID}/src/popup/popup.html`,
		};
		expect(
			authorizeMessage({ type: "EXPORT_VAULT" }, popup, RUNTIME_ID).senderKind,
		).toBe("popup");
		expect(() =>
			authorizeMessage(
				{ type: "GET_ENTRY" },
				{ ...popup, id: "attacker" },
				RUNTIME_ID,
			),
		).toThrow();
	});
});

describe("registeredDomain (eTLD+1 core, v1.4.0)", () => {
	it("collapses subdomains onto the registrable domain", () => {
		expect(registeredDomain("accounts.example.com")).toBe("example.com");
		expect(registeredDomain("a.b.example.com")).toBe("example.com");
		expect(registeredDomain("example.com")).toBe("example.com");
		expect(registeredDomain("localhost")).toBe("localhost");
	});

	it("treats a listed multi-label suffix as three-label eTLD+1", () => {
		expect(registeredDomain("example.co.uk")).toBe("example.co.uk");
		expect(registeredDomain("login.example.co.uk")).toBe("example.co.uk");
		expect(registeredDomain("deep.login.example.co.uk")).toBe("example.co.uk");
		expect(registeredDomain("shop.com.au")).toBe("shop.com.au");
		expect(registeredDomain("x.example.com.cn")).toBe("example.com.cn");
	});

	it("never merges two registrable domains under a multi-label suffix", () => {
		expect(registeredDomain("example.co.uk")).not.toBe(
			registeredDomain("evil.co.uk"),
		);
	});

	it("fails closed to the full hostname under an unlisted 2-letter ccTLD", () => {
		expect(registeredDomain("login.site.co.xx")).toBe("login.site.co.xx");
		expect(registeredDomain("evil.co.xx")).toBe("evil.co.xx");
		expect(registeredDomain("login.site.co.xx")).not.toBe(
			registeredDomain("evil.co.xx"),
		);
	});

	it("falls back to the full hostname when the host IS a table suffix (too few labels)", () => {
		expect(registeredDomain("co.uk")).toBe("co.uk");
		expect(registeredDomain("com.au")).toBe("com.au");
	});

	it("returns null for empty input", () => {
		expect(registeredDomain("")).toBeNull();
	});
});

describe("normalizedDomain", () => {
	it("strips a leading www and reduces to the registrable domain", () => {
		expect(normalizedDomain("https://www.login.example.com/x")).toBe(
			"example.com",
		);
		expect(normalizedDomain("https://WWW.Example.COM")).toBe("example.com");
		// Only a leading "www." is stripped — "www." inside is significant.
		expect(normalizedDomain("https://wwwexample.com")).toBe("wwwexample.com");
	});

	it("returns null when the URL cannot be parsed", () => {
		expect(normalizedDomain(":::bad:::")).toBeNull();
	});
});

describe("entryMatchesPageUrl", () => {
	// v1.5.0 WP4: the gate takes the full entry; the mode rides in
	// entry.url_match_mode (missing/unknown → auto).
	const PAGE = "https://signin.example.com/auth";

	it("accepts an exact domain match (auto mode)", () => {
		expect(
			entryMatchesPageUrl(
				{ url: "https://example.com/login" },
				"https://example.com/signin",
			),
		).toBe(true);
		expect(
			entryMatchesPageUrl(
				{ url: "https://example.com/login" },
				"https://example.com",
			),
		).toBe(true);
	});

	it("rejects a different domain (auto mode)", () => {
		expect(
			entryMatchesPageUrl(
				{ url: "https://example.com/account" },
				"https://evil.test/login",
			),
		).toBe(false);
	});

	it("matches subdomains of the same registrable domain (v1.4.0 semantic flip)", () => {
		// v1.3.x compared full hostnames and rejected this; eTLD+1 matching
		// (v1.4.0) accepts it — accounts.example.com and example.com are the
		// same registrable domain.
		expect(
			entryMatchesPageUrl(
				{ url: "https://sub.example.com" },
				"https://example.com",
			),
		).toBe(true);
		expect(
			entryMatchesPageUrl(
				{ url: "https://example.com" },
				"https://accounts.example.com/login",
			),
		).toBe(true);
	});

	it("keeps registrable domains under a multi-label suffix separate (co.uk)", () => {
		expect(
			entryMatchesPageUrl(
				{ url: "https://example.co.uk" },
				"https://www.example.co.uk/x",
			),
		).toBe(true);
		expect(
			entryMatchesPageUrl(
				{ url: "https://example.co.uk" },
				"https://evil.co.uk/login",
			),
		).toBe(false);
		expect(
			entryMatchesPageUrl(
				{ url: "https://login.example.co.uk" },
				"https://other-example.co.uk/login",
			),
		).toBe(false);
	});

	it("fails closed under an unlisted 2-letter ccTLD (exact host match only)", () => {
		expect(
			entryMatchesPageUrl(
				{ url: "https://site.co.xx" },
				"https://site.co.xx/login",
			),
		).toBe(true);
		expect(
			entryMatchesPageUrl(
				{ url: "https://login.site.co.xx" },
				"https://evil.co.xx/login",
			),
		).toBe(false);
	});

	it("pads a missing scheme with https:// like popup formatUrl", () => {
		expect(
			entryMatchesPageUrl(
				{ url: "github.com/acme" },
				"https://github.com/login",
			),
		).toBe(true);
		expect(
			entryMatchesPageUrl(
				{ url: "http://example.com" },
				"https://example.com/x",
			),
		).toBe(true);
		expect(
			entryMatchesPageUrl(
				{ url: "other.test/login" },
				"https://github.com/login",
			),
		).toBe(false);
	});

	it("rejects URLs that cannot be parsed (cannot judge)", () => {
		expect(
			entryMatchesPageUrl({ url: "https://" }, "https://example.com"),
		).toBe(false);
		expect(
			entryMatchesPageUrl({ url: "not a url" }, "https://example.com"),
		).toBe(false);
		expect(
			entryMatchesPageUrl({ url: "https://example.com" }, ":::bad:::"),
		).toBe(false);
	});

	it("allows an empty entryUrl but rejects an empty pageUrl", () => {
		// Generic entry (no stored URL): an explicit popup fill is deliberate.
		expect(entryMatchesPageUrl({ url: "" }, "https://example.com")).toBe(true);
		expect(entryMatchesPageUrl({ url: null }, "https://example.com")).toBe(
			true,
		);
		expect(entryMatchesPageUrl({}, "https://example.com")).toBe(true);
		// No page URL = cannot judge = reject.
		expect(entryMatchesPageUrl({ url: "https://example.com" }, "")).toBe(false);
		expect(entryMatchesPageUrl({ url: "https://example.com" }, null)).toBe(
			false,
		);
		expect(entryMatchesPageUrl({ url: "https://example.com" }, undefined)).toBe(
			false,
		);
	});

	it("normalizes www and letter case like the other domain gates", () => {
		expect(
			entryMatchesPageUrl(
				{ url: "https://www.example.com" },
				"https://example.com/x",
			),
		).toBe(true);
		expect(
			entryMatchesPageUrl(
				{ url: "https://example.com" },
				"https://www.example.com/x",
			),
		).toBe(true);
		expect(
			entryMatchesPageUrl(
				{ url: "https://WWW.Example.COM/login" },
				"https://www.EXAMPLE.com/x",
			),
		).toBe(true);
		// Only a leading "www." is stripped — "www." inside is significant.
		expect(
			entryMatchesPageUrl(
				{ url: "https://wwwexample.com" },
				"https://example.com",
			),
		).toBe(false);
	});

	// v1.5.0 WP4: per-entry url_match_mode — three-mode behavior matrix.
	describe("url_match_mode (v1.5.0)", () => {
		it("exact pins FULL hostname equality (no www folding, no registrable-domain collapse)", () => {
			expect(
				entryMatchesPageUrl(
					{ url: "https://example.com", url_match_mode: "exact" },
					PAGE.replace("signin.example.com", "example.com"),
				),
			).toBe(true);
			// www.example.com ≠ example.com in exact mode — that is the point.
			expect(
				entryMatchesPageUrl(
					{ url: "https://example.com", url_match_mode: "exact" },
					"https://www.example.com/x",
				),
			).toBe(false);
			expect(
				entryMatchesPageUrl(
					{ url: "https://www.example.com", url_match_mode: "exact" },
					"https://example.com/x",
				),
			).toBe(false);
			// Subdomains do NOT match in exact mode (auto/domain would).
			expect(
				entryMatchesPageUrl(
					{ url: "https://example.com", url_match_mode: "exact" },
					"https://accounts.example.com/login",
				),
			).toBe(false);
			expect(
				entryMatchesPageUrl(
					{ url: "https://accounts.example.com", url_match_mode: "exact" },
					PAGE.replace("signin.example.com", "example.com"),
				),
			).toBe(false);
		});

		it("exact normalizes case and IDN and EXCLUDES the port from the comparison", () => {
			// new URL().hostname case-folds and punycodes IDN; the port lives in
			// .port, never in .hostname.
			expect(
				entryMatchesPageUrl(
					{ url: "https://EXAMPLE.com/x", url_match_mode: "exact" },
					"https://example.com/y",
				),
			).toBe(true);
			expect(
				entryMatchesPageUrl(
					{ url: "https://münchen.de", url_match_mode: "exact" },
					"https://xn--mnchen-3ya.de/login",
				),
			).toBe(true);
			expect(
				entryMatchesPageUrl(
					{ url: "https://xn--mnchen-3ya.de", url_match_mode: "exact" },
					"https://münchen.de/login",
				),
			).toBe(true);
			expect(
				entryMatchesPageUrl(
					{ url: "https://example.com", url_match_mode: "exact" },
					"https://example.com:8443/login",
				),
			).toBe(true);
			expect(
				entryMatchesPageUrl(
					{ url: "https://example.com:8443", url_match_mode: "exact" },
					"https://example.com/login",
				),
			).toBe(true);
			expect(
				entryMatchesPageUrl(
					{ url: "https://example.com", url_match_mode: "exact" },
					"https://evil.com:8443/login",
				),
			).toBe(false);
		});

		it("domain compares registrable domains (same core as auto, pinned by contract)", () => {
			expect(
				entryMatchesPageUrl(
					{ url: "https://example.com", url_match_mode: "domain" },
					PAGE.replace("signin.example.com", "accounts.example.com"),
				),
			).toBe(true);
			expect(
				entryMatchesPageUrl(
					{ url: "https://example.co.uk", url_match_mode: "domain" },
					"https://evil.co.uk/login",
				),
			).toBe(false);
			expect(
				entryMatchesPageUrl(
					{ url: "https://example.com", url_match_mode: "domain" },
					"https://www.example.com/x",
				),
			).toBe(true);
		});

		it("missing or unknown match_mode falls back to auto (pre-v1.5.0 senders)", () => {
			expect(
				entryMatchesPageUrl(
					{ url: "https://sub.example.com" },
					PAGE.replace("signin.example.com", "example.com"),
				),
			).toBe(true);
			expect(
				entryMatchesPageUrl(
					{ url: "https://sub.example.com", url_match_mode: undefined },
					PAGE.replace("signin.example.com", "example.com"),
				),
			).toBe(true);
			expect(
				entryMatchesPageUrl(
					{ url: "https://sub.example.com", url_match_mode: "regex" },
					PAGE.replace("signin.example.com", "example.com"),
				),
			).toBe(true);
		});

		it("strict gate: empty entryUrl is rejected in ALL three modes", () => {
			// The sender gate keeps its fail-closed divergence from the popup gate.
			for (const mode of ["auto", "exact", "domain"]) {
				expect(
					entryMatchesSenderUrl(
						{ url: "", url_match_mode: mode },
						"https://example.com/login",
					),
				).toBe(false);
				expect(entryMatchesSenderUrl({}, "https://example.com/login")).toBe(
					false,
				);
			}
		});

		it("wide gate: empty entryUrl stays allowed in ALL three modes (generic entry)", () => {
			for (const mode of ["auto", "exact", "domain"]) {
				expect(
					entryMatchesPageUrl(
						{ url: "", url_match_mode: mode },
						"https://example.com",
					),
				).toBe(true);
				expect(entryMatchesPageUrl({}, "https://example.com")).toBe(true);
			}
		});

		it("strict gate honors exact mode too (matrix: exact × sender gate)", () => {
			expect(
				entryMatchesSenderUrl(
					{ url: "https://example.com", url_match_mode: "exact" },
					"https://example.com/login",
				),
			).toBe(true);
			expect(
				entryMatchesSenderUrl(
					{ url: "https://example.com", url_match_mode: "exact" },
					"https://www.example.com/login",
				),
			).toBe(false);
			expect(
				entryMatchesSenderUrl(
					{ url: "https://example.com", url_match_mode: "exact" },
					"https://accounts.example.com/login",
				),
			).toBe(false);
			expect(
				entryMatchesSenderUrl(
					{ url: "https://example.com", url_match_mode: "domain" },
					"https://accounts.example.com/login",
				),
			).toBe(true);
			expect(
				entryMatchesSenderUrl(
					{ url: "https://example.com", url_match_mode: "exact" },
					"https://example.com:8443/login",
				),
			).toBe(true);
			expect(
				entryMatchesSenderUrl(
					{ url: "https://example.com", url_match_mode: "domain" },
					"https://www.evil.dev/login",
				),
			).toBe(false);
		});
	});
});

describe("popup-only clipboard commands (v1.3.1)", () => {
	// The clipboard auto-clear arm and its failure-marker consumption schedule
	// clipboard destruction / reporting. They are internal popup↔background
	// messages: a content script (page-reachable code) must never reach them,
	// and they must never touch the desktop native-messaging channel.
	const popup = {
		id: RUNTIME_ID,
		url: `chrome-extension://${RUNTIME_ID}/src/popup/popup.html`,
	};
	const content = { id: RUNTIME_ID, tab: { url: "https://example.com/login" } };

	it("accepts both commands from the popup", () => {
		expect(
			authorizeMessage(
				{ type: "CLIPBOARD_ARM_CLEAR", digest: "ab".repeat(32), deadline: 123 },
				popup,
				RUNTIME_ID,
			).senderKind,
		).toBe("popup");
		expect(
			authorizeMessage(
				{ type: "CONSUME_CLIPBOARD_CLEAR_FAILURE" },
				popup,
				RUNTIME_ID,
			).senderKind,
		).toBe("popup");
	});

	it("fails closed when a content script sends them", () => {
		expect(() =>
			authorizeMessage({ type: "CLIPBOARD_ARM_CLEAR" }, content, RUNTIME_ID),
		).toThrow();
		expect(() =>
			authorizeMessage(
				{ type: "CONSUME_CLIPBOARD_CLEAR_FAILURE" },
				content,
				RUNTIME_ID,
			),
		).toThrow();
	});
});

describe("content.js verbatim copy guard", () => {
	// content.js is a classic script and cannot import this module; it carries
	// a hand-maintained copy of the ENTIRE domain-match block (suffix table +
	// registeredDomain + normalizedDomain + both gates). This test fails when
	// any of them drifts from the source of truth. The BEGIN/END marker
	// extraction deliberately replaces the old per-function regex: a
	// `[\s\S]*?\n\}` extraction would silently truncate at the first
	// column-0 closing brace, and the block approach covers every verbatim
	// symbol in one assertion.
	it("content.js carries a byte-identical copy of the whole domain-match block", () => {
		// node:url/node:path, NOT the global URL: under the jsdom test
		// environment `new URL(rel, import.meta.url)` resolves against the
		// jsdom document (http://localhost:3000), not the file base.
		const here = dirname(fileURLToPath(import.meta.url));
		const source = readFileSync(join(here, "sender-auth.js"), "utf8");
		const content = readFileSync(join(here, "content.js"), "utf8");
		const block = source.match(
			/\/\/ === BEGIN VERBATIM DOMAIN-MATCH BLOCK ===[\s\S]*?\/\/ === END VERBATIM DOMAIN-MATCH BLOCK ===/,
		);
		expect(block).not.toBeNull();
		expect(block[0]).toContain("MULTI_LABEL_SUFFIXES");
		expect(block[0]).toContain("registeredDomain");
		expect(block[0]).toContain("normalizedDomain");
		expect(block[0]).toContain("entryMatchesSenderUrl");
		expect(block[0]).toContain("entryMatchesPageUrl");
		// The only allowed difference between the two files is the `export`
		// keyword on the declarations.
		expect(content).toContain(
			block[0].replaceAll("export function ", "function "),
		);
	});
});
