import Fuse, { type FuseResult, type IFuseOptions } from 'fuse.js';
import type { EntrySummary } from '../types';

const fuseOptions: IFuseOptions<EntrySummary> = {
  keys: [
    { name: 'title', weight: 0.4 },
    { name: 'username', weight: 0.3 },
    { name: 'url', weight: 0.2 },
    { name: 'tags', weight: 0.1 },
  ],
  threshold: 0.3,
  includeScore: true,
  ignoreLocation: true,
};

// Cache the last-built index keyed by the array reference. When the caller
// memoizes on the entries array identity (the normal case), the index is
// reused across keystrokes and only rebuilt when entries actually change.
let cachedEntries: EntrySummary[] | null = null;
let cachedIndex: Fuse<EntrySummary> | null = null;

/**
 * Build (or reuse) a Fuse index over a set of entries. The index is rebuilt
 * only when the entries array identity changes, so callers that memoize the
 * entries benefit from O(1) reuse across keystrokes.
 *
 * §5.6.1: previously `searchEntries` constructed a new `Fuse` instance on
 * every query, which for 10k entries dominates the per-keystroke cost.
 */
export function buildFuseIndex(entries: EntrySummary[]): Fuse<EntrySummary> {
  if (cachedEntries === entries && cachedIndex) {
    return cachedIndex;
  }
  cachedEntries = entries;
  cachedIndex = new Fuse(entries, fuseOptions);
  return cachedIndex;
}

/**
 * Fast case-insensitive substring match across the searchable fields.
 * O(N · fields) per query with no index build — this is what handles the
 * common case (user types a prefix of the title) in single-digit ms even
 * for 10k entries.
 */
function substringFilter(entries: EntrySummary[], query: string): EntrySummary[] {
  const q = query.toLowerCase();
  const results: EntrySummary[] = [];
  for (const e of entries) {
    if (
      e.title.toLowerCase().includes(q) ||
      e.username.toLowerCase().includes(q) ||
      (e.url && e.url.toLowerCase().includes(q)) ||
      (e.tags && e.tags.some((t) => t.toLowerCase().includes(q)))
    ) {
      results.push(e);
    }
  }
  return results;
}

/**
 * Search entries with a two-tier strategy (§5.6.6-1):
 *   1. Substring filter — fast path, handles the vast majority of real
 *      queries (title/username prefixes) in O(N) with no index build.
 *   2. Fuse fuzzy match — fallback only when the substring filter returns
 *      nothing, so the fuzzy index cost is paid only on hard queries.
 *
 * Returns all entries unchanged when the query is empty.
 */
export function searchWithIndex(
  entries: EntrySummary[],
  query: string,
): EntrySummary[] {
  const trimmed = query.trim();
  if (!trimmed) return entries;

  const fast = substringFilter(entries, trimmed);
  if (fast.length > 0) return fast;

  // No exact substring hits — fall back to fuzzy matching for typos.
  const index = buildFuseIndex(entries);
  return index.search(trimmed).map((result: FuseResult<EntrySummary>) => result.item);
}

/**
 * Backward-compatible alias for {@link searchWithIndex}. Screens that build
 * their own memoized entries array should call `searchWithIndex` so the Fuse
 * index is reused across keystrokes; this wrapper exists for tests and any
 * caller that passes a fresh array.
 */
export const searchEntries = searchWithIndex;
