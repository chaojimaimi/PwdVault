import { describe, expect, it } from "vitest";
import { errorMessage } from "../errorMessage";

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

	it("falls back for unknown rejection shapes", () => {
		expect(errorMessage({ code: 42 }, "Export failed")).toBe("Export failed");
	});
});
