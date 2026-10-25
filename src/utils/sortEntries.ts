import type { EntrySummary, SortMode } from "../types";

/**
 * Vault list ordering (v1.4.0). Pure and non-mutating; applied AFTER the
 * group filter and search in VaultScreen.
 *
 * - "recent": last_used_at descending, entries never used sunk to the bottom
 *   (ordered by updated_at among themselves so the sink is deterministic);
 * - "updated": updated_at descending;
 * - "alpha": title ascending (locale-aware).
 *
 * `id` is the final tiebreak everywhere so two entries with identical
 * timestamps keep a stable order across renders.
 */
export function sortEntries(
	entries: EntrySummary[],
	mode: SortMode,
): EntrySummary[] {
	const byTitle = (a: EntrySummary, b: EntrySummary) =>
		a.title.localeCompare(b.title) || a.id.localeCompare(b.id);

	const sorted = [...entries];
	switch (mode) {
		case "recent":
			sorted.sort((a, b) => {
				const aUsed = a.last_used_at ?? null;
				const bUsed = b.last_used_at ?? null;
				// Never-used entries sink below every used one.
				if (aUsed === null && bUsed === null) {
					return b.updated_at - a.updated_at || byTitle(a, b);
				}
				if (aUsed === null) return 1;
				if (bUsed === null) return -1;
				return bUsed - aUsed || b.updated_at - a.updated_at || byTitle(a, b);
			});
			break;
		case "updated":
			sorted.sort(
				(a, b) => b.updated_at - a.updated_at || byTitle(a, b),
			);
			break;
		case "alpha":
			sorted.sort(byTitle);
			break;
	}
	return sorted;
}
