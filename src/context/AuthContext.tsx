import { createContext, useContext, useReducer, useEffect, useMemo, type ReactNode } from 'react';
import type { AppScreen } from '../types';
import * as api from '../api/vault';
import { errorMessage } from '../utils/errorMessage';

function formatError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try { return JSON.stringify(error); } catch { return 'Unknown error'; }
}

// The Tauri layer rejects with the serialized VaultError enum; a dismissed
// Touch ID prompt arrives as the plain string "BiometricCancelled".
function isBiometricCancelled(error: unknown): boolean {
  return errorMessage(error, '') === 'BiometricCancelled';
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

export interface AuthState {
  screen: AppScreen;
  isInitialized: boolean;
  isUnlocked: boolean;
  isLoading: boolean;
  error: string | null;
  bootError: string | null;
}

type AuthAction =
  | { type: 'SET_INITIALIZED'; payload: boolean }
  | { type: 'SET_UNLOCKED'; payload: boolean }
  | { type: 'SET_SCREEN'; payload: AppScreen }
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'SET_BOOT_ERROR'; payload: string | null }
  | { type: 'RESET' };

const initialAuthState: AuthState = {
  screen: 'setup',
  isInitialized: false,
  isUnlocked: false,
  isLoading: true,
  error: null,
  bootError: null,
};

function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'SET_INITIALIZED':
      return { ...state, isInitialized: action.payload };
    case 'SET_UNLOCKED':
      return { ...state, isUnlocked: action.payload };
    case 'SET_SCREEN':
      return { ...state, screen: action.payload };
    case 'SET_LOADING':
      return { ...state, isLoading: action.payload };
    case 'SET_ERROR':
      return { ...state, error: action.payload };
    case 'SET_BOOT_ERROR':
      return { ...state, bootError: action.payload };
    case 'RESET':
      return { ...initialAuthState, isLoading: false };
    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

export interface AuthContextValue {
  state: AuthState;
  dispatch: React.Dispatch<AuthAction>;
  actions: {
    initialize: (password: string) => Promise<void>;
    unlock: (password: string) => Promise<boolean>;
    unlockBiometric: () => Promise<boolean>;
    recover: (recoveryKey: string, newPassword: string) => Promise<boolean>;
    lock: () => Promise<void>;
    navigate: (screen: AppScreen) => void;
    retryBoot: () => Promise<void>;
  };
}

export const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(authReducer, initialAuthState);

  const boot = async () => {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_BOOT_ERROR', payload: null });
      try {
        const initialized = await api.setupVault();
        dispatch({ type: 'SET_INITIALIZED', payload: initialized });
        dispatch({ type: 'SET_SCREEN', payload: initialized ? 'unlock' : 'setup' });
      } catch (error) {
        dispatch({ type: 'SET_BOOT_ERROR', payload: formatError(error) });
      } finally {
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    };

  useEffect(() => {
    void boot();
  }, []);

  // Shared post-unlock transition (Phase 1): password unlock, Touch ID unlock,
  // and vault recovery all land here. SettingsContext / VaultContext watch
  // `isUnlocked` and perform the post-unlock state loading themselves.
  const postUnlock = () => {
    dispatch({ type: 'SET_UNLOCKED', payload: true });
    dispatch({ type: 'SET_SCREEN', payload: 'vault' });
  };

  const actions = useMemo(() => ({
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
          postUnlock();
        } else {
          // Wrong password resolves Ok(false) without any error written, so
          // write it here. Deliberately NOT branching on state.error: the
          // actions closure always sees the mount-time state snapshot
          // (useMemo deps are [dispatch]), so a literal state.error check
          // would be vacuously empty and silently drop this message. The
          // throw path cannot reach this branch (catch short-circuits), so
          // this is the only writer for false results without an error.
          dispatch({ type: 'SET_ERROR', payload: 'Invalid password' });
        }
        return success;
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
        return false;
      } finally {
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    },

    // Touch ID unlock: the backend publishes the session keys itself, so
    // success only needs the shared post-unlock transition. A dismissed
    // Touch ID prompt is a normal outcome — stay silent, surface every
    // other failure through state.error.
    unlockBiometric: async () => {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });
      try {
        await api.unlockBiometric();
        postUnlock();
        return true;
      } catch (error) {
        if (!isBiometricCancelled(error)) {
          dispatch({ type: 'SET_ERROR', payload: formatError(error) });
        }
        return false;
      } finally {
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    },

    // Recovery unlock: recover_vault publishes the new session keys on
    // success (vault ends up unlocked), so this mirrors `unlock`.
    recover: async (recoveryKey: string, newPassword: string) => {
      dispatch({ type: 'SET_LOADING', payload: true });
      dispatch({ type: 'SET_ERROR', payload: null });
      try {
        await api.recoverVault(recoveryKey, newPassword);
        postUnlock();
        return true;
      } catch (error) {
        dispatch({ type: 'SET_ERROR', payload: formatError(error) });
        return false;
      } finally {
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    },

    lock: async () => {
      // A4: the backend lock is idempotent, so a transport failure must not
      // leave the UI on an unlocked screen. Reset to the unlock screen
      // unconditionally in `finally`.
      try {
        await api.lockVault();
      } catch (error) {
        console.error('lock failed', error);
      } finally {
        dispatch({ type: 'RESET' });
        dispatch({ type: 'SET_SCREEN', payload: 'unlock' });
      }
    },

    navigate: (screen: AppScreen) => {
      dispatch({ type: 'SET_SCREEN', payload: screen });
    },

    retryBoot: boot,
  }), [dispatch]);

  const value = useMemo(() => ({ state, dispatch, actions }), [state, dispatch, actions]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
