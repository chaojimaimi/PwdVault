import { createContext, useContext, useReducer, useEffect, useMemo, type ReactNode } from 'react';
import type { AppScreen } from '../types';
import * as api from '../api/vault';

function formatError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try { return JSON.stringify(error); } catch { return 'Unknown error'; }
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

    lock: async () => {
      await api.lockVault();
      dispatch({ type: 'RESET' });
      dispatch({ type: 'SET_SCREEN', payload: 'unlock' });
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
