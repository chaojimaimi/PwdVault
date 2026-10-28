import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// background.js is a service worker entry with top-level chrome.* listeners.
// Since the v1.6.3 split it imports the NM transport (background-native.js)
// and the per-command handlers (background-commands.js), so the source-text
// contract reads all three: cross-file counts (match_mode constructors) run
// on the JOIN of the three modules in a fixed order — union semantics, never
// per-file. The auto-fill list builder must delegate to the STRICT sender
// gate.
//
// Why the STRICT gate and not entryMatchesPageUrl: the strict gate rejects
// an empty entry.url, so generic entries (no stored URL) can never appear in
// an auto-fill list — every getEntriesForUrl consumer relies on that
// invariant ("non-empty URL, fail closed"). The wide gate would let a
// generic entry fill on ANY page.

const here = dirname(fileURLToPath(import.meta.url));
const background = readFileSync(join(here, "background.js"), "utf8");
const backgroundCommands = readFileSync(
	join(here, "background-commands.js"),
	"utf8",
);
const backgroundNative = readFileSync(
	join(here, "background-native.js"),
	"utf8",
);
const backgroundAll = [background, backgroundNative, backgroundCommands].join(
	"\n",
);
const senderAuth = readFileSync(join(here, "sender-auth.js"), "utf8");

function functionBody(source, name) {
	const start = source.indexOf(`async function ${name}(`);
	expect(start, `${name} found in the background modules`).toBeGreaterThanOrEqual(0);
	const bodyStart = source.indexOf("{", start);
	// Balanced-brace scan — robust regardless of indentation/nesting.
	let depth = 0;
	for (let i = bodyStart; i < source.length; i += 1) {
		if (source[i] === "{") depth += 1;
		if (source[i] === "}") {
			depth -= 1;
			if (depth === 0) return source.slice(bodyStart, i + 1);
		}
	}
	throw new Error(`unbalanced braces in ${name}`);
}

describe("background auto-fill list gate (v1.4.0)", () => {
	it("getEntriesForUrl delegates to the strict entryMatchesSenderUrl gate", () => {
		// The v1.6.3 split moved getEntriesForUrl (and with it the
		// sender-auth import) wholesale into background-commands.js — the
		// strict-gate delegation must live in the same file as the import.
		expect(backgroundCommands).toContain(
			'import { entryMatchesSenderUrl } from "./sender-auth.js"',
		);
		const body = functionBody(backgroundCommands, "getEntriesForUrl");
		expect(body).toContain("entryMatchesSenderUrl(entry, url)");
	});

	it("no third hand-rolled hostname comparison remains in getEntriesForUrl", () => {
		const body = functionBody(backgroundCommands, "getEntriesForUrl");
		// The v1.3.x implementation compared stripped hostnames inline; the
		// eTLD+1 semantics live in sender-auth.js alone now.
		expect(body).not.toContain("hostname.replace");
		expect(body).not.toContain("new URL(entry.url)");
	});

	it("the strict gate rejects generic entries (empty entry.url)", () => {
		// The invariant the delegation above depends on, re-asserted against the
		// live predicate: an entry without a URL never matches any sender URL.
		expect(senderAuth).toContain("!senderDomain || !rawEntryUrl) return false");
		// Quote-agnostic via backreference: the invariant under test is semantic,
		// not the quote style (the repo-wide formatter pass flips quotes freely).
		expect(senderAuth).toMatch(
			/const rawEntryUrl = typeof entry\?\.url === (['"])string\1 \? entry\.url : \1\1;/,
		);
	});
});

describe("generator mode passthrough (v1.4.0)", () => {
	it("generatePassword forwards the mode and passphrase fields to the app", () => {
		const start = backgroundCommands.indexOf("async function generatePassword(");
		expect(start).toBeGreaterThanOrEqual(0);
		const body = backgroundCommands.slice(start, start + 1200);
		// The dispatcher contract (#[serde(default)] GeneratorOptions.mode)
		// only pays off if the background actually relays the new fields.
		expect(body).toContain("options.mode");
		expect(body).toContain("generatorOptions.mode = options.mode");
		expect(body).toContain("generatorOptions.words = options.words");
		expect(body).toContain("generatorOptions.separator = options.separator");
		expect(body).toContain(
			"generatorOptions.append_number = options.appendNumber",
		);
	});

	it("the popup generator screen sends a mode with every generate call", () => {
		const popup = readFileSync(join(here, "popup", "popup.js"), "utf8");
		expect(popup).toContain("generatorMode");
		const genStart = popup.indexOf("async handleGenerate()");
		expect(genStart).toBeGreaterThanOrEqual(0);
		const genBody = popup.slice(genStart, genStart + 900);
		expect(genBody).toMatch(/mode:\s*mode|mode,\s*\.\.\./);
	});
});

describe("AUTOFILL match_mode passthrough (v1.5.0 WP4)", () => {
	// The desktop pins the per-entry override on every EntrySummary; it only
	// reaches the content script's authoritative gate if every AUTOFILL
	// constructor relays it. Source-text contract: popup/content scripts have
	// no importable surface (same rationale as the guards above). The content
	// read is the six-file manifest-order join (v1.6.3); the background read
	// is the three-module join.
	const content = [
		'domain-match.js',
		'content-forms.js',
		'content-ui-shadow.js',
		'content-ui-bar.js',
		'content-save-prompt.js',
		'content.js',
	]
		.map((name) => readFileSync(join(here, name), "utf8"))
		.join("\n");
	const popup = readFileSync(join(here, "popup", "popup.js"), "utf8");

	it("both live background constructors forward the entry's match override", () => {
		// Exactly two REAL constructor sites carry entry.url_match_mode; the
		// dead-code relay arm carries message.match_mode (next test). Counted
		// on the joined background modules: union semantics across the split.
		expect(
			backgroundAll.split("match_mode: entry.url_match_mode").length - 1,
		).toBe(2);
	});

	it("the dead-code relay arm forwards match_mode as-is and says so", () => {
		const start = background.indexOf('case "AUTOFILL":');
		expect(start).toBeGreaterThanOrEqual(0);
		const arm = background.slice(start, start + 1400);
		expect(arm).toContain("match_mode: message.match_mode");
		// The self-comment must keep declaring the arm dead AND document the
		// match_mode forward (the plan required one of forward-or-comment,
		// written down, never "decide later").
		expect(arm).toContain("Dead code");
		expect(arm).toContain("message.match_mode");
	});

	it("the popup constructor carries match_mode and passes the entry to the gate", () => {
		const start = popup.indexOf("async autofill(entry)");
		expect(start).toBeGreaterThanOrEqual(0);
		const body = popup.slice(start, start + 1800);
		expect(body).toContain("match_mode: entry.url_match_mode");
		expect(body).toContain("entryMatchesPageUrl(entry, tab.url)");
	});

	it("the content gate falls back to auto for a missing match_mode", () => {
		expect(content).toContain('url_match_mode: message.match_mode || "auto"');
		// The strict URL-shape check stays fail-closed: a missing entryUrl is
		// still a protocol violation even though a missing MODE is not.
		expect(content).toContain('typeof message.entryUrl !== "string"');
	});
});
