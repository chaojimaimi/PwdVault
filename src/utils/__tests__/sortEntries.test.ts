import { describe, expect, it } from "vitest";
import { sortEntries } from "../sortEntries";
import type { EntrySummary } from "../../types";

function entry(
	id: string,
	title: string,
	fields: Partial<EntrySummary> = {},
): EntrySummary {
	return {
		id,
		title,
		url: "",
		username: "u",
		tags: [],
		created_at: 0,
		updated_at: 100,
		...fields,
	};
}

describe("sortEntries (v1.4.0)", () => {
	const entries = [
		entry("a", "Alpha", { last_used_at: 500, updated_at: 100 }),
		entry("b", "Bravo", { last_used_at: null, updated_at: 900 }),
		entry("c", "Charlie", { last_used_at: 700, updated_at: 200 }),
		entry("d", "Delta", { last_used_at: 500, updated_at: 800 }),
	];

	it('"recent" orders by last_used_at desc with never-used entries sunk', () => {
		const titles = sortEntries(entries, "recent").map((e) => e.id);
		// Used entries first, newest usage first; among the 500-tie the higher
		// updated_at wins; never-used bravo sinks to the bottom.
		expect(titles).toEqual(["c", "d", "a", "b"]);
	});

	it('"recent" sinks every entry with a null/undefined last_used_at', () => {
		const mixed = [
			entry("x", "X", { last_used_at: undefined, updated_at: 500 }),
			entry("y", "Y", { last_used_at: 1, updated_at: 1 }),
			entry("z", "Z", { last_used_at: null, updated_at: 9999 }),
		];
		// Used first; the two never-used entries sink below and order by
		// updated_at among themselves (z: 9999 > x: 500).
		expect(sortEntries(mixed, "recent").map((e) => e.id)).toEqual([
			"y",
			"z",
			"x",
		]);
	});

	it('"updated" orders by updated_at desc', () => {
		expect(sortEntries(entries, "updated").map((e) => e.id)).toEqual([
			"b",
			"d",
			"c",
			"a",
		]);
	});

	it('"alpha" orders by title (locale-aware)', () => {
		expect(sortEntries(entries, "alpha").map((e) => e.title)).toEqual([
			"Alpha",
			"Bravo",
			"Charlie",
			"Delta",
		]);
	});

	it("is stable under full ties (id tiebreak) and never mutates the input", () => {
		const tied = [
			entry("same", "Same", { updated_at: 5 }),
			entry("aaa", "Same", { updated_at: 5 }),
		];
		const snapshot = [...tied];
		const out = sortEntries(tied, "alpha");
		expect(out.map((e) => e.id)).toEqual(["aaa", "same"]);
		expect(tied).toEqual(snapshot);
	});
});
