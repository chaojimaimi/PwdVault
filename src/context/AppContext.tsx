import { useMemo, type ReactNode } from 'react';
import { AuthProvider, useAuth } from './AuthContext';
import { SettingsProvider, useSettings } from './SettingsContext';
import { VaultProvider, useVault } from './VaultContext';

// ---------------------------------------------------------------------------
// Backward-compatible facade
//
// The three sub-contexts (Auth / Vault / Settings) own their state. To avoid a
// large migration of every screen that calls `useApp()`, we expose a combined
// `useApp()` hook that merges the three contexts into the shape callers
// already expect: { state, dispatch, actions }.
//
// New code should prefer the granular hooks (useAuth / useVault / useSettings)
// to avoid unnecessary re-renders.
// ---------------------------------------------------------------------------

function formatError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try { return JSON.stringify(error); } catch { return 'Unknown error'; }
}

interface CombinedState {
  screen: ReturnType<typeof useAuth>['state']['screen'];
  isInitialized: boolean;
  isUnlocked: boolean;
  isLoading: boolean;
  error: string | null;
  entries: ReturnType<typeof useVault>['state']['entries'];
  groups: ReturnType<typeof useVault>['state']['groups'];
  selectedGroupId: string | null;
  selectedEntry: ReturnType<typeof useVault>['state']['selectedEntry'];
  searchQuery: string;
  settings: ReturnType<typeof useSettings>['state']['settings'];
  updateInfo: ReturnType<typeof useSettings>['state']['updateInfo'];
}

interface CombinedActions {
  initialize: (password: string) => Promise<void>;
  unlock: (password: string) => Promise<boolean>;
  lock: () => Promise<void>;
  loadEntries: () => Promise<void>;
  loadGroups: () => Promise<void>;
  createGroup: (name: string) => Promise<void>;
  updateGroup: (id: string, name: string) => Promise<void>;
  deleteGroup: (id: string) => Promise<void>;
  selectGroup: (id: string | null) => void;
  selectEntry: (id: string | null) => Promise<void>;
  getEntrySecret: (id: string) => Promise<import('../types').EntrySecretResponse | null>;
  createEntry: (data: Parameters<ReturnType<typeof useVault>['actions']['createEntry']>[0]) => Promise<import('../types').EntrySummary>;
  updateEntry: (id: string, data: Parameters<ReturnType<typeof useVault>['actions']['updateEntry']>[1]) => Promise<import('../types').EntrySummary>;
  deleteEntry: (id: string) => Promise<void>;
  navigate: (screen: import('../types').AppScreen) => void;
  setSearchQuery: (query: string) => void;
  loadSettings: () => Promise<void>;
  updateSettings: (settings: import('../types').Settings) => Promise<void>;
  exportVault: (password: string) => Promise<import('../types').VaultBackup>;
  importVault: (backup: import('../types').VaultBackup, password: string) => Promise<import('../types').ImportResult>;
}

interface AppContextValue {
  state: CombinedState;
  dispatch: React.Dispatch<any>;
  actions: CombinedActions;
}

import { createContext, useContext } from 'react';

export const AppContext = createContext<AppContextValue | null>(null);

function useCombinedApp(): AppContextValue {
  const auth = useAuth();
  const vault = useVault();
  const settings = useSettings();

  // Wrap vault/settings actions so errors are surfaced via the auth error
  // channel, preserving the previous single-context behaviour.
  const wrap = <T extends (...args: any[]) => Promise<any>>(fn: T): T =>
    (async (...args: Parameters<T>) => {
      try {
        return await fn(...args);
      } catch (error) {
        auth.dispatch({ type: 'SET_ERROR', payload: formatError(error) });
        throw error;
      }
    }) as T;

  const state: CombinedState = {
    screen: auth.state.screen,
    isInitialized: auth.state.isInitialized,
    isUnlocked: auth.state.isUnlocked,
    isLoading: auth.state.isLoading,
    error: auth.state.error,
    entries: vault.state.entries,
    groups: vault.state.groups,
    selectedGroupId: vault.state.selectedGroupId,
    selectedEntry: vault.state.selectedEntry,
    searchQuery: vault.state.searchQuery,
    settings: settings.state.settings,
    updateInfo: settings.state.updateInfo,
  };

  const actions: CombinedActions = {
    initialize: auth.actions.initialize,
    unlock: auth.actions.unlock,
    // Wrap lock so that VaultContext state (entries, selectedEntry, groups,
    // searchQuery) is also cleared on manual lock. Without this, sensitive
    // metadata remains in React memory after the vault is locked.
    lock: async () => {
      await auth.actions.lock();
      vault.dispatch({ type: 'RESET' });
    },
    loadEntries: wrap(vault.actions.loadEntries),
    loadGroups: wrap(vault.actions.loadGroups),
    createGroup: wrap(vault.actions.createGroup),
    updateGroup: wrap(vault.actions.updateGroup),
    deleteGroup: wrap(vault.actions.deleteGroup),
    selectGroup: vault.actions.selectGroup,
    selectEntry: wrap(vault.actions.selectEntry),
    getEntrySecret: vault.actions.getEntrySecret,
    createEntry: wrap(vault.actions.createEntry),
    updateEntry: wrap(vault.actions.updateEntry),
    deleteEntry: wrap(vault.actions.deleteEntry),
    navigate: auth.actions.navigate,
    setSearchQuery: vault.actions.setSearchQuery,
    loadSettings: wrap(settings.actions.loadSettings),
    updateSettings: wrap(settings.actions.updateSettings),
    exportVault: vault.actions.exportVault,
    importVault: wrap(vault.actions.importVault),
  };

  // dispatch proxy: route known action types to the right sub-context.
  const dispatch: React.Dispatch<any> = (action: any) => {
    switch (action.type) {
      case 'SET_ENTRIES':
      case 'SET_GROUPS':
      case 'SET_SELECTED_GROUP':
      case 'SET_SELECTED_ENTRY':
      case 'SET_SEARCH_QUERY':
      case 'RESET':
        // RESET clears VaultContext (entries/groups/selectedEntry/searchQuery)
        // so manual lock does not leave sensitive metadata in React memory.
        vault.dispatch(action);
        break;
      case 'SET_SETTINGS':
      case 'SET_UPDATE_INFO':
        settings.dispatch(action);
        break;
      default:
        auth.dispatch(action);
    }
  };

  return useMemo(() => ({ state, dispatch, actions }), [auth, vault, settings]);
}

export function AppProvider({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <SettingsProvider>
        <VaultProvider>
          <AppContextBridge>{children}</AppContextBridge>
        </VaultProvider>
      </SettingsProvider>
    </AuthProvider>
  );
}

function AppContextBridge({ children }: { children: ReactNode }) {
  const value = useCombinedApp();
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
}

export { useAuth, useVault, useSettings };
