import { describe, expect, it } from "vitest";
import { errorMessage, isVaultError } from "../errorMessage";

describe("errorMessage", () => {
	it("reads standard Error and string rejections", () => {
		expect(errorMessage(new Error("disk full"), "fallback")).toBe("disk full");
		expect(errorMessage("permission denied", "fallback")).toBe(
			"permission denied",
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
