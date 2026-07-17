import {
	useCallback,
	useEffect,
	useDeferredValue,
	useMemo,
	useState,
} from "react";
import { Virtuoso } from "react-virtuoso";
import { useAuth, useVault, useSettings } from "../context/AppContext";
import { useTheme } from "../hooks/useTheme";
import { copyWithTimeout, copyWithoutClear } from "../utils/clipboard";
import { searchWithIndex } from "../utils/search";
import { showToast } from "../utils/toast";
import { UpdateNotification } from "../components/UpdateNotification";
import { EntryRow } from "../components/EntryRow";
import {
	PlusIcon,
	GenerateIcon,
	SettingsIcon,
	LockIcon,
	SearchIcon,
	FolderIcon,
} from "../components/Icons";
import type { EntrySummary } from "../types";

export function VaultScreen() {
	const { state: authState, actions: authActions } = useAuth();
	const { state, actions } = useVault();
	const { state: settingsState, actions: settingsActions } = useSettings();
	const { toggleTheme } = useTheme();
	const [copiedId, setCopiedId] = useState<string | null>(null);

	useEffect(() => {
		if (authState.isUnlocked) {
			void Promise.allSettled([actions.loadEntries(), actions.loadGroups()]);
		}
		// loadEntries/loadGroups are stable enough for the unlock transition;
		// we intentionally only re-run on isUnlocked.
	}, [authState.isUnlocked]);

	// §5.6.1: apply the group filter first, then search the filtered set.
	// searchWithIndex uses a two-tier strategy: substring fast-path for the
	// common case (O(N), no index build), Fuse fuzzy fallback for typos.
	// The query is deferred so typing stays responsive even with 10k entries.
	const groupFiltered = useMemo(() => {
		if (!state.selectedGroupId) return state.entries;
		return state.entries.filter(
			(entry) => entry.group_id === state.selectedGroupId,
		);
	}, [state.entries, state.selectedGroupId]);

	const deferredQuery = useDeferredValue(state.searchQuery);

	const filteredEntries = useMemo(
		() => searchWithIndex(groupFiltered, deferredQuery),
		[groupFiltered, deferredQuery],
	);

	const handleEntryClick = useCallback(
		async (entry: EntrySummary) => {
			await actions.selectEntry(entry.id);
			authActions.navigate("entry");
		},
		[actions, authActions],
	);

	const handleCopyUsername = useCallback(async (username: string) => {
		await copyWithoutClear(username);
		showToast("Username copied");
	}, []);

	const handleCopyPassword = useCallback(
		async (entry: EntrySummary) => {
			const secret = await actions.getEntrySecret(entry.id);
			if (secret?.password) {
				await copyWithTimeout(secret.password);
				setCopiedId(entry.id);
				showToast("Password copied (auto-clears in 30s)");
				setTimeout(() => setCopiedId(null), 2000);
			}
		},
		[actions],
	);

	const handleAddClick = () => {
		actions.selectEntry(null);
		authActions.navigate("entry");
	};

	const handleManageGroups = () => {
		authActions.navigate("groupManager");
	};

	return (
		<div className="vault-container screen-shell">
			{settingsState.updateInfo && (
				<UpdateNotification
					updateInfo={settingsState.updateInfo}
					onDismiss={() => settingsActions.dismissUpdate()}
				/>
			)}
			<header className="vault-header">
				<h1>PwdVault</h1>
				<div className="header-actions">
					<button
						className="btn btn-icon"
						onClick={handleAddClick}
						title="Add password"
						aria-label="Add password"
					>
						<PlusIcon />
					</button>
					<button
						className="theme-dot"
						onClick={toggleTheme}
						title="Switch theme"
						aria-label="Toggle theme"
					/>
					<div className="header-separator" />
					<button
						className="btn btn-icon"
						onClick={() => authActions.navigate("generator")}
						title="Password Generator"
						aria-label="Password generator"
					>
						<GenerateIcon />
					</button>
					<button
						className="btn btn-icon"
						onClick={() => authActions.navigate("settings")}
						title="Settings"
						aria-label="Settings"
					>
						<SettingsIcon />
					</button>
					<button
						className="btn btn-icon"
						onClick={() => authActions.lock()}
						title="Lock Vault"
						aria-label="Lock vault"
					>
						<LockIcon />
					</button>
				</div>
			</header>

			<div className="search-bar">
				<div className="search-input-wrapper">
					<SearchIcon className="search-icon" />
					<input
						aria-label="Search passwords"
						type="text"
						className="search-input"
						placeholder="Search passwords..."
						value={state.searchQuery}
						onChange={(e) => actions.setSearchQuery(e.target.value)}
					/>
				</div>
			</div>

			{state.groupsStatus === "success" && state.groups.length > 0 && (
				<div className="group-tabs">
					<div className="group-tabs-scroll">
						<button
							className={`group-tab ${!state.selectedGroupId ? "active" : ""}`}
							onClick={() => actions.selectGroup(null)}
						>
							All
						</button>
						{state.groups.map((g) => (
							<button
								key={g.id}
								className={`group-tab ${state.selectedGroupId === g.id ? "active" : ""}`}
								onClick={() => actions.selectGroup(g.id)}
							>
								{g.name}
							</button>
						))}
					</div>
					<button
						className="group-manage-btn"
						onClick={handleManageGroups}
						title="Manage groups"
						aria-label="Manage groups"
					>
						<SettingsIcon size={14} />
					</button>
				</div>
			)}

			{state.groupsStatus === "success" && state.groups.length === 0 && (
				<div className="group-tabs group-tabs-empty">
					<button
						className="group-manage-btn group-manage-first"
						onClick={handleManageGroups}
					>
						<FolderIcon size={14} />
						Create group
					</button>
				</div>
			)}

			{state.groupsStatus === "error" && (
				<div className="resource-error resource-error-compact" role="alert">
					<span>Could not load groups.</span>
					<button
						className="btn btn-link"
						onClick={() => void actions.loadGroups()}
					>
						Retry
					</button>
				</div>
			)}

			<div className="entry-list screen-scroll-region" role="list">
				{state.entriesStatus === "idle" || state.entriesStatus === "loading" ? (
					<div className="loading" role="status">
						<span className="spinner" />
						<span>Loading passwords…</span>
					</div>
				) : state.entriesStatus === "error" ? (
					<div className="resource-error" role="alert">
						<p>Could not load passwords.</p>
						<p className="text-muted-hint">{state.entriesError}</p>
						<button
							className="btn btn-secondary"
							onClick={() => void actions.loadEntries()}
						>
							Retry
						</button>
					</div>
				) : filteredEntries.length === 0 ? (
					<div className="empty-state" role="listitem">
						<LockIcon size={64} />
						<p>
							{state.searchQuery
								? "No matching passwords found"
								: "No passwords saved yet"}
						</p>
						<p className="text-muted-hint">Tap + to add your first password</p>
					</div>
				) : (
					// §5.6.1: virtualize the entry list so 10k entries render only the
					// visible window. Combined with the memoized EntryRow and the
					// deferred query, this keeps the main-thread long task under 50ms.
					<Virtuoso
						data={filteredEntries}
						itemContent={(_i, entry) => (
							<EntryRow
								entry={entry}
								copied={copiedId === entry.id}
								onOpen={handleEntryClick}
								onCopyUsername={handleCopyUsername}
								onCopyPassword={handleCopyPassword}
							/>
						)}
						style={{ height: "100%" }}
					/>
				)}
			</div>
		</div>
	);
}
