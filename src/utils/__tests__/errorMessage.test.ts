import { describe, expect, it } from "vitest";
import { errorMessage, isVaultError } from "../errorMessage";

describe("errorMessage", () => {
	it("reads standard Error and string rejections", () => {
		expect(errorMessage(new Error("disk full"), "fallback")).toBe("disk full");
		expect(errorMessage("permission denied", "fallback")).toBe(
			"permission denied",
		);
	});

	it("passes serialized unit-variant strings through unchanged (CQ-P2a)", () => {
		expect(errorMessage("VaultLocked", "fallback")).toBe("VaultLocked");
		expect(errorMessage("IntegrityCheckFailed", "fallback")).toBe(
			"IntegrityCheckFailed",
		);
	});

	it("reads serialized Rust error enum payloads", () => {
		expect(
			errorMessage(
				{ DatabaseError: "Deserialization error: settings record is corrupt" },
				"fallback",
			),
		).toBe("Deserialization error: settings record is corrupt");
		expect(
			errorMessage(
				{ DatabaseError: { DeserializationError: "entry record is corrupt" } },
				"fallback",
			),
		).toBe("entry record is corrupt");
	});

	it("renders the RateLimited retry window from its payload (M10)", () => {
		expect(errorMessage({ RateLimited: { retry_after_secs: 42 } }, "fallback")).toBe(
			"Too many attempts — retry in 42s",
		);
	});

	it("falls back for unknown rejection shapes", () => {
		expect(errorMessage({ code: 42 }, "Export failed")).toBe("Export failed");
	});

	// v1.6.1 F2: VaultError's single wire shape puts validation failures on
	// the wire as "CODE: human message" (public_message). The strip is the
	// frontend's half of CQ-P2a — the user reads the sentence, not the code.
	describe("code-prefix strip (v1.6.1 F2)", () => {
		it("strips an ALL_CAPS code prefix with a non-empty remainder", () => {
			expect(
				errorMessage(
					"DUPLICATE_CUSTOM_FIELD_LABEL: Duplicate custom field label",
					"fallback",
				),
			).toBe("Duplicate custom field label");
			// Digits belong to the code alphabet alongside underscores.
			expect(errorMessage("CODE_2: bad thing", "fallback")).toBe("bad thing");
		});

		it("keeps the whole string when nothing follows the separator", () => {
			expect(errorMessage("SOME_CODE: ", "fallback")).toBe("SOME_CODE: ");
			expect(errorMessage("SOME_CODE:", "fallback")).toBe("SOME_CODE:");
		});

		it("never strips sentence-style or lowercase prefixes", () => {
			// "Note" is not ALL_CAPS (lowercase after the first letter).
			expect(errorMessage("Note: this is fine", "fallback")).toBe(
				"Note: this is fine",
			);
			expect(errorMessage("dup label: x", "fallback")).toBe("dup label: x");
			// A mid-message colon does not make the head a code.
			expect(
				errorMessage(
					"Deserialization error: settings record is corrupt",
					"fallback",
				),
			).toBe("Deserialization error: settings record is corrupt");
		});

		it("strips the prefix from Error.message rejections too", () => {
			// Same wire string can arrive wrapped by an adapter — the strip
			// applies to the final message regardless of envelope.
			expect(
				errorMessage(new Error("WEAK_KDF: params below the floor"), "fallback"),
			).toBe("params below the floor");
		});
	});
});

describe("isVaultError (M10)", () => {
	it("accepts every unit-variant string shape", () => {
		expect(isVaultError("VaultLocked")).toBe(true);
		expect(isVaultError("IntegrityCheckFailed")).toBe(true);
		expect(isVaultError("BiometricLockedOut")).toBe(true);
	});

	it("accepts single-key payload object shapes", () => {
		expect(isVaultError({ DatabaseError: "boom" })).toBe(true);
		expect(
			isVaultError({ InvalidInput: { code: "WEAK", message: "short" } }),
		).toBe(true);
		expect(isVaultError({ RateLimited: { retry_after_secs: 60 } })).toBe(true);
	});

	it("rejects non-VaultError shapes", () => {
		expect(isVaultError("TotallyUnknown")).toBe(false);
		expect(isVaultError({ NotAVariant: "x" })).toBe(false);
		expect(isVaultError({ DatabaseError: "a", Extra: "b" })).toBe(false);
		expect(isVaultError(["VaultLocked"])).toBe(false);
		expect(isVaultError(null)).toBe(false);
		expect(isVaultError(42)).toBe(false);
	});
});
