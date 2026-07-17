import type { ReactNode } from 'react';
import { AuthProvider } from './AuthContext';
import { SettingsProvider } from './SettingsContext';
import { VaultProvider } from './VaultContext';

// ---------------------------------------------------------------------------
// Provider composition
//
// Phase 6 (§5.6.1) removed the `useApp()` aggregation facade. The three
// sub-contexts (Auth / Vault / Settings) own their state independently, and
// each screen subscribes to only the context(es) it needs. This eliminates
// the "any context change re-renders every screen" behaviour and the
// `dispatch: any` facade.
//
// AppContent (App.tsx) subscribes only to AuthContext to decide which screen
// to render; the screens themselves pull vault/settings state directly.
//
// Cross-context coordination that used to live in the facade:
//   - On manual lock, VaultContext resets its entries/groups/selection.
//     VaultContext now watches `auth.isUnlocked` and clears itself when the
//     vault transitions to locked, so the lock path no longer needs to
//     dispatch into VaultContext from outside.
// ---------------------------------------------------------------------------

export function AppProvider({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <SettingsProvider>
        <VaultProvider>{children}</VaultProvider>
      </SettingsProvider>
    </AuthProvider>
  );
}

export { useAuth } from './AuthContext';
export { useVault } from './VaultContext';
export { useSettings } from './SettingsContext';
