import { describe, expect, test } from "vitest";
import { sameTags } from "../EntryScreen";

describe("sameTags", () => {
	test("same set in a different order is equal (not dirty)", () => {
		expect(sameTags(["work", "personal"], ["personal", "work"])).toBe(true);
		expect(sameTags([], [])).toBe(true);
	});

	// Regression guard for the old JSON.stringify comparison AND for a Set
	// based rewrite: duplicate multiplicity must be preserved, so ["a", "a"]
	// (user removed one of two identical tags) is a real change.
	test("duplicate multiplicity is preserved", () => {
		expect(sameTags(["a", "a"], ["a"])).toBe(false);
		expect(sameTags(["a", "a"], ["a", "b"])).toBe(false);
		expect(sameTags(["a"], ["b"])).toBe(false);
	});
});
