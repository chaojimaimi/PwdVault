import {
	createContext,
	useContext,
	useReducer,
	useEffect,
	useMemo,
	useRef,
	type ReactNode,
} from "react";
import type { AppScreen } from "../types";
import * as api from "../api/vault";
import { errorMessage } from "../utils/errorMessage";
import { showToast } from "../utils/toast";

// The Tauri layer rejects with the serialized VaultError enum. Since v1.3.2
// every variant serializes to its public_message() text, so a dismissed Touch
// ID prompt arrives as "Touch ID was cancelled" (error.rs); the bare enum
// name is kept for the pre-v1.3.2 wire shape. EXACT strings only — never
// /cancel/i substring matching: IntegrityCheckFailed's public message
// contains "was cancelled" and must NOT be silenced. This set ↔ error.rs
// pairing is pinned by tests on BOTH sides (error.rs ipc test + frontend
// biometricCancelledContract guard).
const BIOMETRIC_CANCELLED_STRINGS: ReadonlySet<string> = new Set([
	"BiometricCancelled",
	"Touch ID was cancelled",
]);

function isBiometricCancelled(error: unknown): boolean {
	return BIOMETRIC_CANCELLED_STRINGS.has(errorMessage(error, ""));
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
	// v1.8.0: "one biometric attempt per lock episode". Lives in the reducer —
	// NOT in a screen ref — because unlockBiometric's SET_LOADING swaps the
	// whole auth screen tree for the Loading screen (App.tsx), unmounting
	// UnlockScreen mid-prompt; a component ref would die on that remount and
	// turn every cancel into a re-prompt loop. RESET (every lock) clears it,
	// so the next lock episode auto-prompts again.
	biometricAutoPrompted: boolean;
}

type AuthAction =
	| { type: "SET_INITIALIZED"; payload: boolean }
	| { type: "SET_UNLOCKED"; payload: boolean }
	| { type: "SET_SCREEN"; payload: AppScreen }
	| { type: "SET_LOADING"; payload: boolean }
	| { type: "SET_ERROR"; payload: string | null }
	| { type: "SET_BOOT_ERROR"; payload: string | null }
	| { type: "MARK_BIOMETRIC_AUTO_PROMPTED" }
	| { type: "RESET" };

const initialAuthState: AuthState = {
	screen: "setup",
	isInitialized: false,
	isUnlocked: false,
	isLoading: true,
	error: null,
	bootError: null,
	biometricAutoPrompted: false,
};

function authReducer(state: AuthState, action: AuthAction): AuthState {
	switch (action.type) {
		case "SET_INITIALIZED":
			return { ...state, isInitialized: action.payload };
		case "SET_UNLOCKED":
			return { ...state, isUnlocked: action.payload };
		case "SET_SCREEN":
			return { ...state, screen: action.payload };
		case "SET_LOADING":
			return { ...state, isLoading: action.payload };
		case "SET_ERROR":
			return { ...state, error: action.payload };
		case "SET_BOOT_ERROR":
			return { ...state, bootError: action.payload };
		case "MARK_BIOMETRIC_AUTO_PROMPTED":
			return { ...state, biometricAutoPrompted: true };
		case "RESET":
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

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
	const [state, dispatch] = useReducer(authReducer, initialAuthState);

	// Latest-state mirror for the biometric late-failure guard below. Assigned
	// in an effect (after commit) — a render-phase write could strand a state
	// value from an interrupted concurrent render in the ref, and this guard's
	// failure direction is "silently swallow a real error". Every read site is
	// an async catch, which necessarily runs after commit; one beat of lag is
	// harmless.
	const authStateRef = useRef(initialAuthState);
	useEffect(() => {
		authStateRef.current = state;
	});

	const boot = async () => {
		dispatch({ type: "SET_LOADING", payload: true });
		dispatch({ type: "SET_BOOT_ERROR", payload: null });
		try {
			const initialized = await api.setupVault();
			dispatch({ type: "SET_INITIALIZED", payload: initialized });
			dispatch({
				type: "SET_SCREEN",
				payload: initialized ? "unlock" : "setup",
			});
		} catch (error) {
			dispatch({
				type: "SET_BOOT_ERROR",
				payload: errorMessage(error, "Failed to initialize the vault"),
			});
		} finally {
			dispatch({ type: "SET_LOADING", payload: false });
		}
	};

	useEffect(() => {
		void boot();
	}, []);

	// Shared post-unlock transition (Phase 1): password unlock, Touch ID unlock,
	// and vault recovery all land here. SettingsContext / VaultContext watch
	// `isUnlocked` and perform the post-unlock state loading themselves.
	const postUnlock = () => {
		dispatch({ type: "SET_UNLOCKED", payload: true });
		dispatch({ type: "SET_SCREEN", payload: "vault" });
	};

	const actions = useMemo(
		() => ({
			initialize: async (password: string) => {
				dispatch({ type: "SET_LOADING", payload: true });
				dispatch({ type: "SET_ERROR", payload: null });
				try {
					await api.initVault(password);
					dispatch({ type: "SET_INITIALIZED", payload: true });
					dispatch({ type: "SET_UNLOCKED", payload: true });
					dispatch({ type: "SET_SCREEN", payload: "vault" });
				} catch (error) {
					dispatch({
						type: "SET_ERROR",
						payload: errorMessage(error, "Failed to create the vault"),
					});
					throw error;
				} finally {
					dispatch({ type: "SET_LOADING", payload: false });
				}
			},

			unlock: async (password: string) => {
				dispatch({ type: "SET_LOADING", payload: true });
				dispatch({ type: "SET_ERROR", payload: null });
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
						dispatch({ type: "SET_ERROR", payload: "Invalid password" });
					}
					return success;
				} catch (error) {
					dispatch({
						type: "SET_ERROR",
						payload: errorMessage(error, "Unlock failed"),
					});
					return false;
				} finally {
					dispatch({ type: "SET_LOADING", payload: false });
				}
			},

			// Touch ID unlock: the backend publishes the session keys itself, so
			// success only needs the shared post-unlock transition. A dismissed
			// Touch ID prompt is a normal outcome — stay silent, surface every
			// other failure through state.error.
			//
			// MARK on entry: auto or manual, a biometric attempt has happened in
			// this lock episode — the auto-prompt effect in UnlockScreen reads
			// this flag and stays quiet for the rest of the episode. RESET (on
			// every lock) clears it.
			unlockBiometric: async () => {
				dispatch({ type: "MARK_BIOMETRIC_AUTO_PROMPTED" });
				dispatch({ type: "SET_LOADING", payload: true });
				dispatch({ type: "SET_ERROR", payload: null });
				try {
					await api.unlockBiometric();
					postUnlock();
					return true;
				} catch (error) {
					if (isBiometricCancelled(error)) {
						// dismissed prompt: normal outcome.
					} else if (authStateRef.current.isUnlocked) {
						// Late failure guard (v1.8.0, defense in depth): another
						// unlock path already won, so this stale rejection must not
						// pollute the global error banner. UNREACHABLE in the current
						// topology — the Loading screen swallows all interaction while
						// the Touch ID prompt is up, so a password unlock cannot race
						// it — but the guard becomes load-bearing the moment the
						// loading topology changes. What a late resolution would
						// actually do (do NOT re-derive this as "harmless"):
						//  - success: complete_unlock_if rebuilds the whole Unlocked
						//    state and bumps the session generation (session.rs),
						//    invalidating in-flight D8 leases and resetting
						//    last_remote_activity (the paired extension's 120s grace;
						//    the wrap-key slot is cleared but restored at the biometric
						//    step), and postUnlock's SET_SCREEN "vault" yanks the user
						//    back from whatever screen they navigated to;
						//  - failure (e.g. VAULT_STATE_CHANGED from an interleaved
						//    password change): a stale error banner on the next lock
						//    screen.
					} else {
						dispatch({
							type: "SET_ERROR",
							payload: errorMessage(error, "Touch ID unlock failed"),
						});
					}
					return false;
				} finally {
					dispatch({ type: "SET_LOADING", payload: false });
				}
			},

			// Recovery unlock: recover_vault publishes the new session keys on
			// success (vault ends up unlocked), so this mirrors `unlock`.
			recover: async (recoveryKey: string, newPassword: string) => {
				dispatch({ type: "SET_LOADING", payload: true });
				dispatch({ type: "SET_ERROR", payload: null });
				try {
					await api.recoverVault(recoveryKey, newPassword);
					postUnlock();
					return true;
				} catch (error) {
					dispatch({
						type: "SET_ERROR",
						payload: errorMessage(error, "Recovery failed"),
					});
					return false;
				} finally {
					dispatch({ type: "SET_LOADING", payload: false });
				}
			},

			lock: async () => {
				// A4: the backend lock is idempotent, so a transport failure must not
				// leave the UI on an unlocked screen. Reset to the unlock screen
				// unconditionally in `finally`.
				try {
					await api.lockVault();
				} catch (error) {
					console.error("lock failed", error);
					showToast("Failed to lock the vault — please retry or quit the app");
				} finally {
					dispatch({ type: "RESET" });
					dispatch({ type: "SET_SCREEN", payload: "unlock" });
				}
			},

			navigate: (screen: AppScreen) => {
				dispatch({ type: "SET_SCREEN", payload: screen });
			},

			retryBoot: boot,
		}),
		[dispatch],
	);

	const value = useMemo(
		() => ({ state, dispatch, actions }),
		[state, dispatch, actions],
	);
	return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
	const ctx = useContext(AuthContext);
	if (!ctx) throw new Error("useAuth must be used within AuthProvider");
	return ctx;
}
