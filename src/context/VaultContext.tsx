import {
	createContext,
	useContext,
	useReducer,
	useMemo,
	useEffect,
	useRef,
	type ReactNode,
} from "react";
import type {
	EntrySummary,
	EntrySecretResponse,
	Group,
	VaultBackup,
	ImportResult,
	ResourceStatus,
} from "../types";
import * as api from "../api/vault";
import { useAuth } from "./AuthContext";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

export interface VaultState {
	entries: EntrySummary[];
	groups: Group[];
	selectedGroupId: string | null;
	selectedEntry: EntrySummary | null;
	searchQuery: string;
	entriesStatus: ResourceStatus;
	entriesError: string | null;
	groupsStatus: ResourceStatus;
	groupsError: string | null;
}

type VaultAction =
	| { type: "SET_ENTRIES"; payload: EntrySummary[] }
	| { type: "SET_GROUPS"; payload: Group[] }
	| { type: "SET_SELECTED_GROUP"; payload: string | null }
	| { type: "SET_SELECTED_ENTRY"; payload: EntrySummary | null }
	| { type: "SET_SEARCH_QUERY"; payload: string }
	| {
			type: "SET_ENTRIES_RESOURCE";
			payload: { status: ResourceStatus; error?: string | null };
	  }
	| {
			type: "SET_GROUPS_RESOURCE";
			payload: { status: ResourceStatus; error?: string | null };
	  }
	| { type: "RESET" };

const initialVaultState: VaultState = {
	entries: [],
	groups: [],
	selectedGroupId: null,
	selectedEntry: null,
	searchQuery: "",
	entriesStatus: "idle",
	entriesError: null,
	groupsStatus: "idle",
	groupsError: null,
};

function vaultReducer(state: VaultState, action: VaultAction): VaultState {
	switch (action.type) {
		case "SET_ENTRIES":
			return { ...state, entries: action.payload };
		case "SET_GROUPS":
			return { ...state, groups: action.payload };
		case "SET_SELECTED_GROUP":
			return { ...state, selectedGroupId: action.payload };
		case "SET_SELECTED_ENTRY":
			return { ...state, selectedEntry: action.payload };
		case "SET_SEARCH_QUERY":
			return { ...state, searchQuery: action.payload };
		case "SET_ENTRIES_RESOURCE":
			return {
				...state,
				entriesStatus: action.payload.status,
				entriesError: action.payload.error ?? null,
			};
		case "SET_GROUPS_RESOURCE":
			return {
				...state,
				groupsStatus: action.payload.status,
				groupsError: action.payload.error ?? null,
			};
		case "RESET":
			return { ...initialVaultState };
		default:
			return state;
	}
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

export interface VaultContextValue {
	state: VaultState;
	dispatch: React.Dispatch<VaultAction>;
	actions: {
		loadEntries: () => Promise<void>;
		loadGroups: () => Promise<void>;
		createGroup: (name: string) => Promise<Group>;
		updateGroup: (id: string, name: string) => Promise<void>;
		deleteGroup: (id: string) => Promise<void>;
		selectGroup: (id: string | null) => void;
		selectEntry: (id: string | null) => Promise<void>;
		getEntrySecret: (id: string) => Promise<EntrySecretResponse | null>;
		createEntry: (
			data: Parameters<typeof api.createEntry>[0],
		) => Promise<EntrySummary>;
		updateEntry: (
			id: string,
			data: Parameters<typeof api.updateEntry>[1],
		) => Promise<EntrySummary>;
		deleteEntry: (id: string) => Promise<void>;
		setSearchQuery: (query: string) => void;
		exportVault: (password: string) => Promise<VaultBackup>;
		importVault: (
			backup: VaultBackup,
			password: string,
		) => Promise<ImportResult>;
	};
}

export const VaultContext = createContext<VaultContextValue | null>(null);

export function VaultProvider({ children }: { children: ReactNode }) {
	const [state, dispatch] = useReducer(vaultReducer, initialVaultState);
	// Watch auth.isUnlocked so a manual lock or auto-lock clears sensitive
	// vault state (entries, groups, selectedEntry, searchQuery) from React
	// memory. Previously this RESET was dispatched from the AppContext facade
	// after lock returned; with the facade gone (§5.6.1), VaultProvider drives
	// it directly by observing the locked transition.
	const { state: authState } = useAuth();
	const wasUnlocked = useRef(authState.isUnlocked);
	useEffect(() => {
		if (wasUnlocked.current && !authState.isUnlocked) {
			dispatch({ type: "RESET" });
		}
		wasUnlocked.current = authState.isUnlocked;
	}, [authState.isUnlocked]);

	const actions = useMemo(
		() => ({
			loadEntries: async () => {
				dispatch({
					type: "SET_ENTRIES_RESOURCE",
					payload: { status: "loading" },
				});
				try {
					const entries = await api.listAllEntries();
					dispatch({ type: "SET_ENTRIES", payload: entries });
					dispatch({
						type: "SET_ENTRIES_RESOURCE",
						payload: { status: "success" },
					});
				} catch (error) {
					dispatch({
						type: "SET_ENTRIES_RESOURCE",
						payload: { status: "error", error: formatError(error) },
					});
					throw error;
				}
			},

			loadGroups: async () => {
				dispatch({
					type: "SET_GROUPS_RESOURCE",
					payload: { status: "loading" },
				});
				try {
					const groups = await api.listAllGroups();
					dispatch({ type: "SET_GROUPS", payload: groups || [] });
					dispatch({
						type: "SET_GROUPS_RESOURCE",
						payload: { status: "success" },
					});
				} catch (error) {
					dispatch({
						type: "SET_GROUPS_RESOURCE",
						payload: { status: "error", error: formatError(error) },
					});
					throw error;
				}
			},

			createGroup: async (name: string) => {
				try {
					const created = await api.createGroup(name);
					await actions.loadGroups();
					return created;
				} catch (error) {
					throw error;
				}
			},

			updateGroup: async (id: string, name: string) => {
				try {
					await api.updateGroup(id, name);
					await actions.loadGroups();
				} catch (error) {
					throw error;
				}
			},

			deleteGroup: async (id: string) => {
				try {
					await api.removeGroup(id);
					await actions.loadGroups();
					await actions.loadEntries();
					dispatch({
						type: "SET_SELECTED_GROUP",
						payload:
							state.selectedGroupId === id ? null : state.selectedGroupId,
					});
				} catch (error) {
					throw error;
				}
			},

			selectGroup: (id: string | null) => {
				dispatch({ type: "SET_SELECTED_GROUP", payload: id });
			},

			selectEntry: async (id: string | null) => {
				if (!id) {
					dispatch({ type: "SET_SELECTED_ENTRY", payload: null });
					return;
				}
				try {
					const entry = await api.getEntryMeta(id);
					dispatch({ type: "SET_SELECTED_ENTRY", payload: entry });
				} catch (error) {
					throw error;
				}
			},

			getEntrySecret: async (id: string) => {
				return api.getEntrySecret(id);
			},

			createEntry: async (data: Parameters<typeof api.createEntry>[0]) => {
				const entry = await api.createEntry(data);
				await actions.loadEntries();
				return entry;
			},

			updateEntry: async (
				id: string,
				data: Parameters<typeof api.updateEntry>[1],
			) => {
				const entry = await api.updateEntry(id, data);
				await actions.loadEntries();
				return entry;
			},

			deleteEntry: async (id: string) => {
				await api.removeEntry(id);
				dispatch({ type: "SET_SELECTED_ENTRY", payload: null });
				await actions.loadEntries();
			},

			setSearchQuery: (query: string) => {
				dispatch({ type: "SET_SEARCH_QUERY", payload: query });
			},

			exportVault: async (password: string) => {
				return api.exportVault(password);
			},

			importVault: async (backup: VaultBackup, password: string) => {
				const result = await api.importVault(backup, password);
				await actions.loadEntries();
				await actions.loadGroups();
				return result;
			},
		}),
		[dispatch, state.selectedGroupId],
	);

	const value = useMemo(
		() => ({ state, dispatch, actions }),
		[state, dispatch, actions],
	);
	return (
		<VaultContext.Provider value={value}>{children}</VaultContext.Provider>
	);
}

function formatError(error: unknown): string {
	if (error instanceof Error) return error.message;
	if (typeof error === "string") return error;
	try {
		return JSON.stringify(error);
	} catch {
		return "Unknown error";
	}
}

export function useVault() {
	const ctx = useContext(VaultContext);
	if (!ctx) throw new Error("useVault must be used within VaultProvider");
	return ctx;
}
