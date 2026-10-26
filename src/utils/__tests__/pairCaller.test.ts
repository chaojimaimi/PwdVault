import { describe, expect, it } from "vitest";
import { formatExtensionCaller } from "../pairCaller";

// v1.5.0 (WP5): the pairing toast shows a digest of the requesting
// extension's caller label. The label itself is forgeable on loopback —
// these tests pin DISPLAY formatting only, not any security property.

describe("formatExtensionCaller", () => {
	it("truncates a Chrome extension ID to first4…last4", () => {
		// Chrome native-messaging launchers pass the 32-char [a-p] origin
		// (main.rs validates exactly that alphabet — real IDs never contain
		// q-z, so the pattern must not accept them either).
		expect(
			formatExtensionCaller("chrome-extension://abcdefghijklmnopabcdefghijklmnop/"),
		).toBe("abcd…mnop");
	});

	it("accepts the Chrome label without the trailing slash", () => {
		expect(
			formatExtensionCaller(
				"chrome-extension://abcdefghijklmnopponmlkjihgfedcba",
			),
		).toBe("abcd…dcba");
	});

	it("shows the fixed Firefox add-on ID as-is", () => {
		expect(formatExtensionCaller("moz-extension://pwdvault@pwdvault.app")).toBe(
			"pwdvault@pwdvault.app",
		);
	});

	it("renders unknown caller shapes verbatim", () => {
		expect(formatExtensionCaller("weird-future-caller")).toBe(
			"weird-future-caller",
		);
	});

	it("does not mis-truncate a wrong-length chrome-extension label", () => {
		// 31 chars: not a valid Chrome ID shape — verbatim, no fabricated digest.
		const short = "chrome-extension://abcdefghijklmnopqrstuvwxyza/";
		expect(formatExtensionCaller(short)).toBe(short);
	});
});
