import Fuse, { type IFuseOptions } from 'fuse.js';
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

/**
 * Search entries using fuzzy matching (fuse.js).
 * Returns all entries when query is empty.
 */
export function searchEntries(entries: EntrySummary[], query: string): EntrySummary[] {
  if (!query.trim()) return entries;

  const fuse = new Fuse(entries, fuseOptions);
  return fuse.search(query).map((result) => result.item);
}
