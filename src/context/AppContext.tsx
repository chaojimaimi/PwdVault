import { createContext, useContext, useReducer, useEffect, type ReactNode } from 'react';
// debug: log module URL when loaded under test to help diagnose hook/duplicate-React issues
// eslint-disable-next-line no-console
console.log('LOADED AppContext module:', typeof import.meta !== 'undefined' ? String(import.meta.url) : 'no import.meta');
// debug react identity
// eslint-disable-next-line no-console
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  // @ts-ignore
  console.log('AppContext react.resolve ->', require.resolve('react'));
} catch (e) {
  // ignore
}
import type { EntrySummary, EntryResponse, VaultState, AppScreen } from '../types';
import * as api from '../api/vault';

function formatError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  try {
    return JSON.stringify(error);
  } catch {
    return 'Unknown error';
  }
}

interface AppState extends VaultState {
  screen: AppScreen;
  isLoading: boolean;
  error: string | null;
}

type Action =
  | { type: 'SET_INITIALIZED'; payload: boolean }
  | { type: 'SET_UNLOCKED'; payload: boolean }
  | { type: 'SET_ENTRIES'; payload: EntrySummary[] }
  | { type: 'SET_GROUPS'; payload: import('../types').Group[] }
  | { type: 'SET_SELECTED_GROUP'; payload: string | null }
  | { type: 'SET_SELECTED_ENTRY'; payload: EntryResponse | null }
  | { type: 'SET_SEARCH_QUERY'; payload: string }
  | { type: 'SET_SCREEN'; payload: AppScreen }
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'RESET' };

const initialState: AppState = {
  screen: 'setup',
  isInitialized: false,
  isUnlocked: false,
  entries: [],
  groups: [],
  selectedGroupId: null,
  selectedEntry: null,
  searchQuery: '',
  isLoading: true,
  error: null,
};

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'SET_INITIALIZED':
      return { ...state, isInitialized: action.payload };
    case 'SET_UNLOCKED':
      return { ...state, isUnlocked: action.payload };
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
    case 'SET_SCREEN':
      return { ...state, screen: action.payload };
    case 'SET_LOADING':
      return { ...state, isLoading: action.payload };
    case 'SET_ERROR':
      return { ...state, error: action.payload };
    case 'RESET':
      return { ...initialState, isLoading: false };
    default:
      return state;
  }
}

interface AppContextValue {
  state: AppState;
  dispatch: React.Dispatch<Action>;
  actions: {
    initialize: (password: string) => Promise<void>;
    unlock: (password: string) => Promise<boolean>;
    lock: () => void;
    loadEntries: () => Promise<void>;
    loadGroups: () => Promise<void>;
    createGroup: (name: string) => Promise<void>;
    updateGroup: (id: string, name: string) => Promise<void>;
    deleteGroup: (id: string) => Promise<void>;
    selectGroup: (id: string | null) => void;
    selectEntry: (id: string | null) => Promise<void>;
    getEntry: (id: string) => Promise<EntryResponse | null>;
    createEntry: (data: Parameters<typeof api.createEntry>[0]) => Promise<EntrySummary>;
    updateEntry: (id: string, data: Parameters<typeof api.updateEntry>[1]) => Promise<EntrySummary>;
    deleteEntry: (id: string) => Promise<void>;
    navigate: (screen: AppScreen) => void;
    setSearchQuery: (query: string) => void;
  };
}

export const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);

  // Initialize app on mount
  useEffect(() => {
    async function init() {
      try {
        const initialized = await api.setupVault();
        dispatch({ type: 'SET_INITIALIZED', payload: initialized });
        dispatch({ type: 'SET_SCREEN', payload: initialized ? 'unlock' : 'setup' });
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
      } finally {
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    }
    init();
  }, []);

  const actions = {
    initialize: async (password: string) => {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });
      try {
        await api.initVault(password);
        dispatch({ type: 'SET_INITIALIZED', payload: true });
        dispatch({ type: 'SET_UNLOCKED', payload: true });
        dispatch({ type: 'SET_SCREEN', payload: 'vault' });
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
        throw error;
      } finally {
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    },

    unlock: async (password: string) => {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });
      try {
        const success = await api.unlockVault(password);
        if (success) {
          dispatch({ type: 'SET_UNLOCKED', payload: true });
          dispatch({ type: 'SET_SCREEN', payload: 'vault' });
        }
        return success;
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
        return false;
      } finally {
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    },

    lock: () => {
      api.lockVault();
      dispatch({ type: 'RESET' });
      dispatch({ type: 'SET_SCREEN', payload: 'unlock' });
    },

    loadEntries: async () => {
      try {
        const entries = await api.listAllEntries();
        dispatch({ type: 'SET_ENTRIES', payload: entries });
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
      }
    },
    

    loadGroups: async () => {
      try {
        const groups = await api.listAllGroups();
        dispatch({ type: 'SET_GROUPS', payload: groups || [] });
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
      }
    },

    createGroup: async (name: string) => {
      try {
        await api.createGroup(name);
        await actions.loadGroups();
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
        throw error;
      }
    },

    updateGroup: async (id: string, name: string) => {
      try {
        await api.updateGroup(id, name);
        await actions.loadGroups();
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
        throw error;
      }
    },

    deleteGroup: async (id: string) => {
      try {
        await api.removeGroup(id);
        await actions.loadGroups();
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
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
        const entry = await api.getEntry(id);
        dispatch({ type: 'SET_SELECTED_ENTRY', payload: entry });
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
      }
    },

    getEntry: async (id: string) => {
      try {
        return await api.getEntry(id);
      } catch {
        return null;
      }
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

    navigate: (screen: AppScreen) => {
      dispatch({ type: 'SET_SCREEN', payload: screen });
    },

    setSearchQuery: (query: string) => {
      dispatch({ type: 'SET_SEARCH_QUERY', payload: query });
    },
  };

  return (
    <AppContext.Provider value={{ state, dispatch, actions }}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within AppProvider');
  }
  return context;
}