import { createContext, useContext, useReducer, useEffect, useMemo, type ReactNode } from 'react';
import type { Settings, UpdateInfo } from '../types';
import { DEFAULT_SETTINGS } from '../types';
import * as api from '../api/vault';
import { useAuth } from './AuthContext';

function formatError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try { return JSON.stringify(error); } catch { return 'Unknown error'; }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

export interface SettingsState {
  settings: Settings;
  updateInfo: UpdateInfo | null;
}

type SettingsAction =
  | { type: 'SET_SETTINGS'; payload: Settings }
  | { type: 'SET_UPDATE_INFO'; payload: UpdateInfo | null };

const initialSettingsState: SettingsState = {
  settings: DEFAULT_SETTINGS,
  updateInfo: null,
};

function settingsReducer(state: SettingsState, action: SettingsAction): SettingsState {
  switch (action.type) {
    case 'SET_SETTINGS':
      return { ...state, settings: action.payload };
    case 'SET_UPDATE_INFO':
      return { ...state, updateInfo: action.payload };
    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

export interface SettingsContextValue {
  state: SettingsState;
  dispatch: React.Dispatch<SettingsAction>;
  actions: {
    loadSettings: () => Promise<void>;
    updateSettings: (settings: Settings) => Promise<void>;
    checkForUpdates: () => Promise<void>;
    dismissUpdate: () => void;
  };
}

export const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(settingsReducer, initialSettingsState);
  const { state: authState } = useAuth();

  // Check for updates on mount (non-blocking, silent on failure)
  useEffect(() => {
    let cancelled = false;
    api.checkForUpdates()
      .then((info) => {
        if (cancelled) return;
        if (info.has_update) {
          const dismissed = localStorage.getItem('pwdvault_dismissed_update');
          if (dismissed !== info.latest_version) {
            dispatch({ type: 'SET_UPDATE_INFO', payload: info });
          }
        }
      })
      .catch(() => { /* silently ignore */ });
    return () => { cancelled = true; };
  }, []);

  // Load settings from the backend after the vault is unlocked so that
  // SettingsScreen and GeneratorScreen reflect the user's saved preferences
  // (auto_lock_secs, default_length, charset defaults) instead of
  // DEFAULT_SETTINGS. Without this, state.settings stays at defaults until
  // the user manually opens SettingsScreen and saves.
  useEffect(() => {
    if (!authState.isUnlocked) {
      // Vault locked (or never unlocked): clear any previously loaded
      // settings so they don't linger in React memory while locked.
      dispatch({ type: 'SET_SETTINGS', payload: DEFAULT_SETTINGS });
      return;
    }
    let cancelled = false;
    api.getSettings()
      .then((settings) => {
        if (!cancelled) dispatch({ type: 'SET_SETTINGS', payload: settings });
      })
      .catch(() => { /* settings unavailable — keep defaults */ });
    return () => { cancelled = true; };
  }, [authState.isUnlocked]);

  const actions = useMemo(() => ({
    loadSettings: async () => {
      try {
        const settings = await api.getSettings();
        dispatch({ type: 'SET_SETTINGS', payload: settings });
      } catch (error) {
        // Surface via auth error channel by rethrowing to caller
        throw error;
      }
    },

    updateSettings: async (settings: Settings) => {
      try {
        const updated = await api.updateSettings(settings);
        dispatch({ type: 'SET_SETTINGS', payload: updated });
      } catch (error) {
        throw error;
      }
    },

    checkForUpdates: async () => {
      try {
        const info = await api.checkForUpdates();
        dispatch({ type: 'SET_UPDATE_INFO', payload: info.has_update ? info : null });
      } catch {
        /* ignore */
      }
    },

    dismissUpdate: () => {
      if (state.updateInfo) {
        localStorage.setItem('pwdvault_dismissed_update', state.updateInfo.latest_version);
      }
      dispatch({ type: 'SET_UPDATE_INFO', payload: null });
    },
  }), [dispatch, state.updateInfo]);

  const value = useMemo(() => ({ state, dispatch, actions }), [state, dispatch, actions]);
  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings() {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error('useSettings must be used within SettingsProvider');
  return ctx;
}

// Re-export for convenience
export { formatError };
