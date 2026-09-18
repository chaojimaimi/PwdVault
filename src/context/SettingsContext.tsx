import { createContext, useContext, useReducer, useEffect, useMemo, useRef, type ReactNode } from 'react';
import { check, type Update, type DownloadEvent } from '@tauri-apps/plugin-updater';
import type { Settings, ResourceStatus } from '../types';
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

/** Banner lifecycle: offer → download (with progress) → ready to relaunch. */
export type UpdatePhase = 'available' | 'downloading' | 'ready';

export interface SettingsState {
  settings: Settings;
  /** Update found by the plugin `check()`; null = up to date or silent. */
  update: { version: string } | null;
  updatePhase: UpdatePhase;
  /** Download progress 0-100 (only meaningful while phase is 'downloading'). */
  downloadProgress: number;
  status: ResourceStatus;
  error: string | null;
}

type SettingsAction =
  | { type: 'SET_SETTINGS'; payload: Settings }
  | { type: 'SET_UPDATE'; payload: { version: string } | null }
  | { type: 'SET_UPDATE_PHASE'; payload: UpdatePhase }
  | { type: 'SET_DOWNLOAD_PROGRESS'; payload: number }
  | { type: 'SET_RESOURCE'; payload: { status: ResourceStatus; error?: string | null } }
  | { type: 'RESET' };

const initialSettingsState: SettingsState = {
  settings: DEFAULT_SETTINGS,
  update: null,
  updatePhase: 'available',
  downloadProgress: 0,
  status: 'idle',
  error: null,
};

function settingsReducer(state: SettingsState, action: SettingsAction): SettingsState {
  switch (action.type) {
    case 'SET_SETTINGS':
      return { ...state, settings: action.payload };
    case 'SET_UPDATE':
      return {
        ...state,
        update: action.payload,
        updatePhase: action.payload ? 'available' : initialSettingsState.updatePhase,
        downloadProgress: 0,
      };
    case 'SET_UPDATE_PHASE':
      return { ...state, updatePhase: action.payload };
    case 'SET_DOWNLOAD_PROGRESS':
      return { ...state, downloadProgress: action.payload };
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
    installUpdate: () => Promise<void>;
    relaunchApp: () => Promise<void>;
    dismissUpdate: () => void;
  };
}

/** Same localStorage key the pre-updater notification flow used. */
const DISMISSED_UPDATE_KEY = 'pwdvault_dismissed_update';

/** D1.4: updater check timeout — a hung feed must not stall startup UX. */
const UPDATE_CHECK_TIMEOUT_MS = 5000;

export const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(settingsReducer, initialSettingsState);
  const { state: authState } = useAuth();
  const checkedThisStartup = useRef(false);
  // The plugin `Update` object is resource-backed and must be kept around for
  // downloadAndInstall; it never goes into React state (only its version does).
  const updateRef = useRef<Update | null>(null);

  // Privacy invariant (unchanged from the old check flow): the update check
  // runs only after unlock + successful settings load + explicit opt-in, and
  // at most once during this application startup. Failures stay silent.
  useEffect(() => {
    if (!authState.isUnlocked || state.status !== 'success' || !state.settings.check_updates || checkedThisStartup.current) {
      return;
    }
    checkedThisStartup.current = true;
    let cancelled = false;
    check({ timeout: UPDATE_CHECK_TIMEOUT_MS })
      .then((update) => {
        if (cancelled || !update) return;
        const dismissed = localStorage.getItem(DISMISSED_UPDATE_KEY);
        if (dismissed === update.version) {
          void update.close().catch(() => {});
          return;
        }
        updateRef.current = update;
        dispatch({ type: 'SET_UPDATE', payload: { version: update.version } });
      })
      .catch(() => { /* silently ignore — degraded to "no update right now" */ });
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

    installUpdate: async () => {
      const update = updateRef.current;
      if (!update || state.updatePhase === 'downloading' || state.updatePhase === 'ready') return;
      dispatch({ type: 'SET_UPDATE_PHASE', payload: 'downloading' });
      let total = 0;
      let received = 0;
      try {
        await update.downloadAndInstall((event: DownloadEvent) => {
          if (event.event === 'Started') {
            total = event.data.contentLength ?? 0;
            received = 0;
          } else if (event.event === 'Progress') {
            received += event.data.chunkLength;
            if (total > 0) {
              const percent = Math.min(100, Math.round((received / total) * 100));
              dispatch({ type: 'SET_DOWNLOAD_PROGRESS', payload: percent });
            }
          } else if (event.event === 'Finished') {
            dispatch({ type: 'SET_DOWNLOAD_PROGRESS', payload: 100 });
          }
        });
        // Windows exits by itself when the NSIS installer launches; on macOS
        // the banner flips to "Relaunch" and the user restarts explicitly.
        dispatch({ type: 'SET_UPDATE_PHASE', payload: 'ready' });
        updateRef.current = null;
        void update.close().catch(() => {});
      } catch {
        // Silent degradation: back to the offer state so "Update now" can retry.
        dispatch({ type: 'SET_UPDATE_PHASE', payload: 'available' });
        dispatch({ type: 'SET_DOWNLOAD_PROGRESS', payload: 0 });
      }
    },

    relaunchApp: async () => {
      const { relaunch } = await import('@tauri-apps/plugin-process');
      await relaunch();
    },

    dismissUpdate: () => {
      if (state.update) {
        localStorage.setItem(DISMISSED_UPDATE_KEY, state.update.version);
      }
      const update = updateRef.current;
      updateRef.current = null;
      if (update) {
        void update.close().catch(() => {});
      }
      dispatch({ type: 'SET_UPDATE', payload: null });
    },
  }), [dispatch, state.update, state.updatePhase]);

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
