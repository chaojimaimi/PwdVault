import { createContext, useContext, useReducer, useEffect, useMemo, useRef, type ReactNode } from 'react';
import type { Settings, UpdateInfo, ResourceStatus } from '../types';
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
  status: ResourceStatus;
  error: string | null;
}

type SettingsAction =
  | { type: 'SET_SETTINGS'; payload: Settings }
  | { type: 'SET_UPDATE_INFO'; payload: UpdateInfo | null }
  | { type: 'SET_RESOURCE'; payload: { status: ResourceStatus; error?: string | null } }
  | { type: 'RESET' };

const initialSettingsState: SettingsState = {
  settings: DEFAULT_SETTINGS,
  updateInfo: null,
  status: 'idle',
  error: null,
};

function settingsReducer(state: SettingsState, action: SettingsAction): SettingsState {
  switch (action.type) {
    case 'SET_SETTINGS':
      return { ...state, settings: action.payload };
    case 'SET_UPDATE_INFO':
      return { ...state, updateInfo: action.payload };
    case 'SET_RESOURCE':
      return { ...state, status: action.payload.status, error: action.payload.error ?? null };
    case 'RESET':
      return initialSettingsState;
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
  const checkedThisStartup = useRef(false);

  // Privacy invariant: update checks run only after unlock + successful settings
  // load + explicit opt-in, and at most once during this application startup.
  useEffect(() => {
    if (!api.UPDATE_CHECK_AVAILABLE || !authState.isUnlocked || state.status !== 'success' || !state.settings.check_updates || checkedThisStartup.current) {
      return;
    }
    checkedThisStartup.current = true;
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
  }, [authState.isUnlocked, state.status, state.settings.check_updates]);

  // Load settings from the backend after the vault is unlocked so that
  // SettingsScreen and GeneratorScreen reflect the user's saved preferences
  // (auto_lock_secs, default_length, charset defaults) instead of
  // DEFAULT_SETTINGS. Without this, state.settings stays at defaults until
  // the user manually opens SettingsScreen and saves.
  useEffect(() => {
    if (!authState.isUnlocked) {
      // Vault locked (or never unlocked): clear any previously loaded
      // settings so they don't linger in React memory while locked.
      dispatch({ type: 'RESET' });
      return;
    }
    let cancelled = false;
    dispatch({ type: 'SET_RESOURCE', payload: { status: 'loading' } });
    api.getSettings()
      .then((settings) => {
        if (!cancelled) {
          dispatch({ type: 'SET_SETTINGS', payload: settings });
          dispatch({ type: 'SET_RESOURCE', payload: { status: 'success' } });
        }
      })
      .catch((error) => {
        if (!cancelled) dispatch({ type: 'SET_RESOURCE', payload: { status: 'error', error: formatError(error) } });
      });
    return () => { cancelled = true; };
  }, [authState.isUnlocked]);

  const actions = useMemo(() => ({
    loadSettings: async () => {
      dispatch({ type: 'SET_RESOURCE', payload: { status: 'loading' } });
      try {
        const settings = await api.getSettings();
        dispatch({ type: 'SET_SETTINGS', payload: settings });
        dispatch({ type: 'SET_RESOURCE', payload: { status: 'success' } });
      } catch (error) {
        dispatch({ type: 'SET_RESOURCE', payload: { status: 'error', error: formatError(error) } });
        throw error;
      }
    },

    updateSettings: async (settings: Settings) => {
      try {
        const updated = await api.updateSettings(settings);
        dispatch({ type: 'SET_SETTINGS', payload: updated });
        dispatch({ type: 'SET_RESOURCE', payload: { status: 'success' } });
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
