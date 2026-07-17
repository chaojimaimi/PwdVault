import { performance } from "perf_hooks";
import { describe, expect, it } from "vitest";
import { buildFuseIndex, searchWithIndex } from "../search";
import type { EntrySummary } from "../../types";

// §5.6.6-1: 10k entry search must respond in <100ms and the index build must
// not dominate per-keystroke cost. This benchmark runs in Node (no jsdom
// layout), so it measures the algorithmic cost only — Virtuoso and
// useDeferredValue cover the rendering side, verified separately.

function makeEntries(n: number): EntrySummary[] {
	const entries: EntrySummary[] = [];
	const domains = [
		"google",
		"github",
		"netflix",
		"amazon",
		"apple",
		"microsoft",
		"dropbox",
		"slack",
	];
	for (let i = 0; i < n; i++) {
		const domain = domains[i % domains.length];
		entries.push({
			id: `e${i}`,
			title: `${domain}-${i}`,
			url: `https://${domain}.com/path-${i}`,
			username: `user${i}@${domain}.com`,
			tags: [domain, `tag-${i % 10}`],
			created_at: i,
			updated_at: i,
			group_id: null,
		});
	}
	return entries;
}

describe("search performance (§5.6.6-1)", () => {
	it("substring fast-path searches 10k entries within the 100ms budget", () => {
		const entries = makeEntries(10_000);

		// Warm any JIT path.
		searchWithIndex(entries, "google");

		const queryMs: number[] = [];
		for (const q of ["google", "github-5", "user500", "amazon"]) {
			const start = performance.now();
			const result = searchWithIndex(entries, q);
			queryMs.push(performance.now() - start);
			expect(result.length).toBeGreaterThan(0);
		}
		const worstMs = Math.max(...queryMs);
		// The per-keystroke search budget is 100ms (§5.6.6-1).
		expect(worstMs).toBeLessThan(100);
	});

	it("returns all entries for an empty query without touching the index", () => {
		const entries = makeEntries(1000);
		const result = searchWithIndex(entries, "");
		expect(result).toHaveLength(1000);
	});

	it("falls back to fuzzy match only when the substring filter is empty", () => {
		const entries = makeEntries(1000);
		// 'githb' is a typo — substring filter finds nothing, fuse fuzzy returns github matches.
		const result = searchWithIndex(entries, "githb");
		expect(result.length).toBeGreaterThan(0);
	});

	it("caches the fuse index across calls with the same entries reference", () => {
		const entries = makeEntries(1000);
		const a = buildFuseIndex(entries);
		const b = buildFuseIndex(entries);
		expect(a).toBe(b);
	});
});
