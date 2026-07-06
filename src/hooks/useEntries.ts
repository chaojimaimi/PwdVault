import { useCallback, useRef } from 'react';
import { useVault } from '../context/VaultContext';
import type { EntrySummary } from '../types';

/**
 * Lightweight entry cache + optimistic update helper.
 *
 * Keeps an in-memory `Map<id, EntrySummary>` in sync with `VaultContext.entries`
 * so screens can do O(1) lookups and apply optimistic patches before the server
 * round-trip completes.
 *
 * Not a full data-fetching library (React Query etc.) — intentionally minimal
 * to keep the bundle small.
 */
export function useEntries() {
  const { state, dispatch, actions } = useVault();
  const cache = useRef<Map<string, EntrySummary>>(new Map());

  // Rebuild the cache whenever entries change.
  cache.current = new Map(state.entries.map((e) => [e.id, e]));

  const getById = useCallback(
    (id: string): EntrySummary | undefined => cache.current.get(id),
    [],
  );

  /** Apply a patch to a single entry optimistically (no server round-trip). */
  const optimisticUpdate = useCallback(
    (id: string, patch: Partial<EntrySummary>) => {
      const cached = cache.current.get(id);
      if (!cached) return;
      const updated = { ...cached, ...patch, updated_at: Date.now() };
      cache.current.set(id, updated);
      dispatch({
        type: 'SET_ENTRIES',
        payload: [...cache.current.values()],
      });
    },
    [dispatch],
  );

  /** Insert a new entry optimistically (e.g., after create returns). */
  const optimisticAdd = useCallback(
    (entry: EntrySummary) => {
      cache.current.set(entry.id, entry);
      dispatch({
        type: 'SET_ENTRIES',
        payload: [...cache.current.values()],
      });
    },
    [dispatch],
  );

  /** Remove an entry optimistically. */
  const optimisticRemove = useCallback(
    (id: string) => {
      cache.current.delete(id);
      dispatch({
        type: 'SET_ENTRIES',
        payload: [...cache.current.values()],
      });
    },
    [dispatch],
  );

  return {
    entries: state.entries,
    getById,
    refresh: actions.loadEntries,
    optimisticUpdate,
    optimisticAdd,
    optimisticRemove,
  };
}
