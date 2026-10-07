import { createContext, useContext, useReducer, useEffect, useMemo, useRef, type ReactNode } from 'react';
import { check, type Update, type DownloadEvent } from '@tauri-apps/plugin-updater';
import type { Settings, ResourceStatus } from '../types';
import { DEFAULT_SETTINGS } from '../types';
import * as api from '../api/vault';
import { errorMessage } from '../utils/errorMessage';
import { useAuth } from './AuthContext';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** Banner lifecycle: offer → download (with progress) → ready to relaunch. */
export type UpdatePhase = 'available' | 'downloading' | 'ready';

/** Manual "Check for updates" button lifecycle (Settings page). */
export type ManualCheckPhase = 'idle' | 'checking' | 'available' | 'uptodate' | 'error';

export interface ManualCheckState {
  phase: ManualCheckPhase;
  /** Date.now() of the last completed check — powers the "checked HH:MM" hint. */
  checkedAt: number | null;
  /** Feed version when phase === 'available'. */
  version?: string;
}

export interface SettingsState {
  settings: Settings;
  /** Update found by the plugin `check()`; null = up to date or silent. */
  update: { version: string } | null;
  updatePhase: UpdatePhase;
  /** Download progress 0-100 (only meaningful while phase is 'downloading'). */
  downloadProgress: number;
  /** Result of the last explicit (button-triggered) update check. */
  manualCheck: ManualCheckState;
  status: ResourceStatus;
  error: string | null;
}

type SettingsAction =
  | { type: 'SET_SETTINGS'; payload: Settings }
  | { type: 'SET_UPDATE'; payload: { version: string } | null }
  | { type: 'SET_UPDATE_PHASE'; payload: UpdatePhase }
  | { type: 'SET_DOWNLOAD_PROGRESS'; payload: number }
  | { type: 'SET_MANUAL_CHECK'; payload: ManualCheckState }
  | { type: 'SET_RESOURCE'; payload: { status: ResourceStatus; error?: string | null } }
  | { type: 'RESET' };

const initialSettingsState: SettingsState = {
  settings: DEFAULT_SETTINGS,
  update: null,
  updatePhase: 'available',
  downloadProgress: 0,
  manualCheck: { phase: 'idle', checkedAt: null },
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
    case 'SET_MANUAL_CHECK':
      return { ...state, manualCheck: action.payload };
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
    installUpdate: () => Promise<void>;
    relaunchApp: () => Promise<void>;
    dismissUpdate: () => void;
  };
}

/** Same localStorage key the pre-updater notification flow used. */
const DISMISSED_UPDATE_KEY = 'pwdvault_dismissed_update';

/** D1.4: updater check timeout — a hung feed must not stall startup UX. */
const UPDATE_CHECK_TIMEOUT_MS = 5000;

/**
 * Manual checks have a user actively waiting on the result, so the timeout
 * is relaxed vs. the 5s startup check that must not block boot UX.
 */
const MANUAL_UPDATE_CHECK_TIMEOUT_MS = 15000;

const SettingsContext = createContext<SettingsContextValue | null>(null);

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
        // Close-before-overwrite, mirroring checkForUpdates: if a manual check
        // already populated the ref, overwriting without close would leak the
        // plugin handle. Concurrency policy (plan v1.2.2 §1.2.5): last writer
        // wins; a transient null/error from either path clearing the banner is
        // accepted — the user can always re-check for the latest fact.
        const previous = updateRef.current;
        if (previous) void previous.close().catch(() => {});
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
        if (!cancelled) dispatch({ type: 'SET_RESOURCE', payload: { status: 'error', error: errorMessage(error, 'Failed to load settings') } });
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
        dispatch({ type: 'SET_RESOURCE', payload: { status: 'error', error: errorMessage(error, 'Failed to load settings') } });
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
      // Guards: a check is already in flight, or an install is in progress.
      // Re-checking mid-download would close the in-flight Update handle, and
      // a re-check from 'ready' would flip a finished install back into a
      // re-download. The manual button is the first path able to trigger a
      // close during a download, so this is stopped at the action layer (the
      // Settings button mirrors the same disabled conditions).
      if (
        state.manualCheck.phase === 'checking' ||
        state.updatePhase === 'downloading' ||
        state.updatePhase === 'ready'
      ) {
        return;
      }
      dispatch({ type: 'SET_MANUAL_CHECK', payload: { phase: 'checking', checkedAt: null } });
      try {
        const update = await check({ timeout: MANUAL_UPDATE_CHECK_TIMEOUT_MS });
        if (update) {
          // Explicit ask: bypass the dismissal memory (and never write it) —
          // the user asked, so they get the full answer. The auto-path gate
          // (checkedThisStartup) stays untouched — the two are orthogonal.
          const previous = updateRef.current;
          if (previous) void previous.close().catch(() => {});
          updateRef.current = update;
          dispatch({ type: 'SET_UPDATE', payload: { version: update.version } });
          dispatch({
            type: 'SET_MANUAL_CHECK',
            payload: { phase: 'available', checkedAt: Date.now(), version: update.version },
          });
        } else {
          // No update: the latest explicit fact overrides any stale banner.
          const previous = updateRef.current;
          updateRef.current = null;
          if (previous) void previous.close().catch(() => {});
          dispatch({ type: 'SET_UPDATE', payload: null });
          dispatch({
            type: 'SET_MANUAL_CHECK',
            payload: { phase: 'uptodate', checkedAt: Date.now() },
          });
        }
      } catch {
        // Failure only means "this check found nothing reliable" — it must
        // not overturn an existing banner/download state.
        dispatch({
          type: 'SET_MANUAL_CHECK',
          payload: { phase: 'error', checkedAt: Date.now() },
        });
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
  }), [dispatch, state.update, state.updatePhase, state.manualCheck]);

  const value = useMemo(() => ({ state, dispatch, actions }), [state, dispatch, actions]);
  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings() {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error('useSettings must be used within SettingsProvider');
  return ctx;
}
