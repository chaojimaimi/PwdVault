import { createContext, useContext, useReducer, useMemo, type ReactNode } from 'react';
import type { EntrySummary, EntrySecretResponse, Group, VaultBackup, ImportResult } from '../types';
import * as api from '../api/vault';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

export interface VaultState {
  entries: EntrySummary[];
  groups: Group[];
  selectedGroupId: string | null;
  selectedEntry: EntrySummary | null;
  searchQuery: string;
}

type VaultAction =
  | { type: 'SET_ENTRIES'; payload: EntrySummary[] }
  | { type: 'SET_GROUPS'; payload: Group[] }
  | { type: 'SET_SELECTED_GROUP'; payload: string | null }
  | { type: 'SET_SELECTED_ENTRY'; payload: EntrySummary | null }
  | { type: 'SET_SEARCH_QUERY'; payload: string }
  | { type: 'RESET' };

const initialVaultState: VaultState = {
  entries: [],
  groups: [],
  selectedGroupId: null,
  selectedEntry: null,
  searchQuery: '',
};

function vaultReducer(state: VaultState, action: VaultAction): VaultState {
  switch (action.type) {
    case 'SET_ENTRIES':
      return { ...state, entries: action.payload };
    case 'SET_GROUPS':
      return { ...state, groups: action.payload };
    case 'SET_SELECTED_GROUP':
      return { ...state, selectedGroupId: action.payload };
    case 'SET_SELECTED_ENTRY':
      return { ...state, selectedEntry: action.payload };
    case 'SET_SEARCH_QUERY':
      return { ...state, searchQuery: action.payload };
    case 'RESET':
      return { ...initialVaultState };
    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

export interface VaultContextValue {
  state: VaultState;
  dispatch: React.Dispatch<VaultAction>;
  actions: {
    loadEntries: () => Promise<void>;
    loadGroups: () => Promise<void>;
    createGroup: (name: string) => Promise<void>;
    updateGroup: (id: string, name: string) => Promise<void>;
    deleteGroup: (id: string) => Promise<void>;
    selectGroup: (id: string | null) => void;
    selectEntry: (id: string | null) => Promise<void>;
    getEntrySecret: (id: string) => Promise<EntrySecretResponse | null>;
    createEntry: (data: Parameters<typeof api.createEntry>[0]) => Promise<EntrySummary>;
    updateEntry: (id: string, data: Parameters<typeof api.updateEntry>[1]) => Promise<EntrySummary>;
    deleteEntry: (id: string) => Promise<void>;
    setSearchQuery: (query: string) => void;
    exportVault: (password: string) => Promise<VaultBackup>;
    importVault: (backup: VaultBackup, password: string) => Promise<ImportResult>;
  };
}

export const VaultContext = createContext<VaultContextValue | null>(null);

export function VaultProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(vaultReducer, initialVaultState);

  const actions = useMemo(() => ({
    loadEntries: async () => {
      try {
        const entries = await api.listAllEntries();
        dispatch({ type: 'SET_ENTRIES', payload: entries });
      } catch (error) {
        throw error;
      }
    },

    loadGroups: async () => {
      try {
        const groups = await api.listAllGroups();
        dispatch({ type: 'SET_GROUPS', payload: groups || [] });
      } catch (error) {
        throw error;
      }
    },

    createGroup: async (name: string) => {
      try {
        await api.createGroup(name);
        await actions.loadGroups();
      } catch (error) {
        throw error;
      }
    },

    updateGroup: async (id: string, name: string) => {
      try {
        await api.updateGroup(id, name);
        await actions.loadGroups();
      } catch (error) {
        throw error;
      }
    },

    deleteGroup: async (id: string) => {
      try {
        await api.removeGroup(id);
        await actions.loadGroups();
      } catch (error) {
        throw error;
      }
    },

    selectGroup: (id: string | null) => {
      dispatch({ type: 'SET_SELECTED_GROUP', payload: id });
    },

    selectEntry: async (id: string | null) => {
      if (!id) {
        dispatch({ type: 'SET_SELECTED_ENTRY', payload: null });
        return;
      }
      try {
        const entry = await api.getEntryMeta(id);
        dispatch({ type: 'SET_SELECTED_ENTRY', payload: entry });
      } catch (error) {
        throw error;
      }
    },

    getEntrySecret: async (id: string) => {
      return api.getEntrySecret(id);
    },

    createEntry: async (data: Parameters<typeof api.createEntry>[0]) => {
      const entry = await api.createEntry(data);
      await actions.loadEntries();
      return entry;
    },

    updateEntry: async (id: string, data: Parameters<typeof api.updateEntry>[1]) => {
      const entry = await api.updateEntry(id, data);
      await actions.loadEntries();
      return entry;
    },

    deleteEntry: async (id: string) => {
      await api.removeEntry(id);
      dispatch({ type: 'SET_SELECTED_ENTRY', payload: null });
      await actions.loadEntries();
    },

    setSearchQuery: (query: string) => {
      dispatch({ type: 'SET_SEARCH_QUERY', payload: query });
    },

    exportVault: async (password: string) => {
      return api.exportVault(password);
    },

    importVault: async (backup: VaultBackup, password: string) => {
      const result = await api.importVault(backup, password);
      await actions.loadEntries();
      await actions.loadGroups();
      return result;
    },
  }), [dispatch]);

  const value = useMemo(() => ({ state, dispatch, actions }), [state, dispatch, actions]);
  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

export function useVault() {
  const ctx = useContext(VaultContext);
  if (!ctx) throw new Error('useVault must be used within VaultProvider');
  return ctx;
}
