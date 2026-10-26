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
import { errorMessage } from "../utils/errorMessage";
import { searchWithIndex } from "../utils/search";
import { sortEntries } from "../utils/sortEntries";
import { showToast } from "../utils/toast";
import { UpdateNotification } from "../components/UpdateNotification";
import { EntryRow } from "../components/EntryRow";
import DeleteConfirmModal from "../components/DeleteConfirmModal";
import {
	PlusIcon,
	BackIcon,
	GenerateIcon,
	SettingsIcon,
	LockIcon,
	SearchIcon,
	FolderIcon,
	TrashIcon,
	ShieldIcon,
} from "../components/Icons";
import type { EntrySummary, SortMode } from "../types";

const SORT_OPTIONS: Array<{ value: SortMode; label: string }> = [
	{ value: "recent", label: "Recent" },
	{ value: "updated", label: "Recently updated" },
	{ value: "alpha", label: "A–Z" },
];

export function VaultScreen() {
	const { state: authState, actions: authActions } = useAuth();
	const { state, actions } = useVault();
	const { state: settingsState, actions: settingsActions } = useSettings();
	const { toggleTheme } = useTheme();
	const [copiedId, setCopiedId] = useState<string | null>(null);
	// v1.4.0: trash view state (simple local toggle — the trash is a separate
	// list, not a filter of the live list).
	const [trashOpen, setTrashOpen] = useState(false);
	const [trashBusy, setTrashBusy] = useState(false);
	const [purgeTarget, setPurgeTarget] = useState<EntrySummary | null>(null);
	const [emptyConfirm, setEmptyConfirm] = useState(false);

	useEffect(() => {
		if (authState.isUnlocked) {
			void Promise.allSettled([actions.loadEntries(), actions.loadGroups()]);
		}
		// "Run once per unlock transition": actions is now referentially stable
		// (VaultContext memoizes on [dispatch] — v1.3.2 removed the
		// selectedGroupId dependency), so listing it cannot re-trigger the load
		// and the old latestRef workaround is gone.
	}, [authState.isUnlocked, actions]);

	// v1.4.0: load the trash lazily — only when the user opens the view.
	useEffect(() => {
		if (!trashOpen || !authState.isUnlocked) return;
		void actions.loadDeletedEntries().catch((e) => {
			showToast(errorMessage(e, "Failed to load trash"));
		});
		// actions is referentially stable (VaultContext memoizes on dispatch).
	}, [trashOpen, authState.isUnlocked, actions]);

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

	// v1.4.0: the persisted sort mode applies LAST, after filter + search.
	// Unknown persisted values fall back to "recent" (same default as Rust).
	const sortMode: SortMode = settingsState.settings.sort_mode ?? "recent";
	const sortedEntries = useMemo(
		() => sortEntries(filteredEntries, sortMode),
		[filteredEntries, sortMode],
	);

	const handleSortChange = useCallback(
		(mode: SortMode) => {
			void settingsActions
				.updateSettings({ ...settingsState.settings, sort_mode: mode })
				.catch((e) => {
					showToast(errorMessage(e, "Failed to save sort preference"));
				});
		},
		[settingsActions, settingsState.settings],
	);

	const handleEntryClick = useCallback(
		async (entry: EntrySummary) => {
			try {
				await actions.selectEntry(entry.id);
				authActions.navigate("entry");
			} catch (e) {
				showToast(errorMessage(e, "Failed to open entry"));
			}
		},
		[actions, authActions],
	);

	const handleCopyUsername = useCallback(async (username: string) => {
		try {
			await copyWithoutClear(username);
			showToast("Username copied");
		} catch (e) {
			showToast(errorMessage(e, "Failed to copy username"));
		}
	}, []);

	const handleCopyPassword = useCallback(
		async (entry: EntrySummary) => {
			try {
				const secret = await actions.getEntrySecret(entry.id);
				if (secret?.password) {
					await copyWithTimeout(secret.password);
					setCopiedId(entry.id);
					showToast("Password copied (auto-clears in 30s)");
					setTimeout(() => setCopiedId(null), 2000);
				}
			} catch (e) {
				showToast(errorMessage(e, "Failed to copy password"));
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

	const handleRestore = async (entry: EntrySummary) => {
		try {
			await actions.restoreEntry(entry.id);
			showToast("Entry restored");
		} catch (e) {
			showToast(errorMessage(e, "Failed to restore entry"));
		}
	};

	const handlePurgeConfirm = async () => {
		if (!purgeTarget || trashBusy) return;
		setTrashBusy(true);
		try {
			await actions.purgeEntry(purgeTarget.id);
			showToast("Entry permanently deleted");
			setPurgeTarget(null);
		} catch (e) {
			showToast(errorMessage(e, "Failed to delete entry"));
		} finally {
			setTrashBusy(false);
		}
	};

	const handleEmptyTrash = async () => {
		if (trashBusy) return;
		setTrashBusy(true);
		try {
			await actions.emptyTrash();
			showToast("Trash emptied");
		} catch (e) {
			showToast(errorMessage(e, "Failed to empty trash"));
		} finally {
			setTrashBusy(false);
		}
	};

	const trashList = state.deletedEntries;

	return (
		<div className="vault-container screen-shell">
			{settingsState.update && (
				<UpdateNotification
					version={settingsState.update.version}
					phase={settingsState.updatePhase}
					progress={settingsState.downloadProgress}
					onUpdate={() => void settingsActions.installUpdate()}
					onRelaunch={() => void settingsActions.relaunchApp()}
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
						onClick={() => authActions.navigate("dashboard")}
						title="Security Dashboard"
						aria-label="Security dashboard"
					>
						<ShieldIcon />
					</button>
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
						// A4: void + fallback catch — a lock rejection must not become
						// an unhandled rejection in the browser console.
						onClick={() => {
							void authActions.lock().catch(() => {});
						}}
						title="Lock Vault"
						aria-label="Lock vault"
					>
						<LockIcon />
					</button>
				</div>
			</header>

			{!trashOpen && (
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
					{/* v1.4.0: persisted sort control — applies after filter+search. */}
					<select
						className="sort-select"
						aria-label="Sort passwords"
						value={sortMode}
						onChange={(e) => handleSortChange(e.target.value as SortMode)}
					>
						{SORT_OPTIONS.map((opt) => (
							<option key={opt.value} value={opt.value}>
								{opt.label}
							</option>
						))}
					</select>
				</div>
			)}

			{/* v1.4.1: the tabs row is always rendered — Trash and the group
			    manager stay reachable while groups are loading or failed to load,
			    and the trash view below renders in place (tabs stay visible)
			    instead of replacing the whole screen. */}
			<div className="group-tabs">
				<div className="group-tabs-scroll">
					{state.groupsStatus === "success" && state.groups.length > 0 && (
						<>
							<button
								className={`group-tab ${!state.selectedGroupId && !trashOpen ? "active" : ""}`}
								onClick={() => {
									// Navigation mutex: picking a group always leaves the
									// trash view (v1.4.1).
									setTrashOpen(false);
									actions.selectGroup(null);
								}}
								aria-current={
									(!state.selectedGroupId && !trashOpen) || undefined
								}
							>
								All
							</button>
							{state.groups.map((g) => (
								<button
									key={g.id}
									className={`group-tab ${state.selectedGroupId === g.id && !trashOpen ? "active" : ""}`}
									onClick={() => {
										setTrashOpen(false);
										actions.selectGroup(g.id);
									}}
									aria-current={
										(state.selectedGroupId === g.id && !trashOpen) ||
										undefined
									}
								>
									{g.name}
								</button>
							))}
						</>
					)}
					{state.groupsStatus === "success" && state.groups.length === 0 && (
						<button
							className="group-manage-btn group-manage-first"
							onClick={handleManageGroups}
						>
							<FolderIcon size={14} />
							Create group
						</button>
					)}
					{state.groupsStatus === "error" && (
						<div
							className="resource-error resource-error-compact"
							role="alert"
						>
							<span>Could not load groups.</span>
							<button
								className="btn btn-link"
								onClick={() => void actions.loadGroups()}
							>
								Retry
							</button>
						</div>
					)}
				</div>
				<div className="group-tabs-actions">
					<div className="group-tabs-divider" />
					{/* Pinned trash tab (v1.4.1): the visible text is the accessible
					    name — no aria-label that could override it. */}
					<button
						className={`group-tab group-tab-trash ${trashOpen ? "active" : ""}`}
						onClick={() => setTrashOpen((v) => !v)}
						aria-current={trashOpen || undefined}
					>
						<TrashIcon size={12} />
						Trash
					</button>
					<button
						className="group-manage-btn"
						onClick={handleManageGroups}
						title="Manage groups"
						aria-label="Manage groups"
					>
						<SettingsIcon size={14} />
					</button>
				</div>
			</div>

			{trashOpen && (
				// -----------------------------------------------------------
				// Trash view (v1.4.0): standalone simple list — NOT part of the
				// search index or the sort. Deleted time + restore/purge per row.
				// -----------------------------------------------------------
					<div className="trash-screen">
						<div className="trash-header">
							{/* v1.5.1: explicit Back affordance restored — two real-device
							    QA rounds flagged the toggle-only return as undiscoverable.
							    The Trash tab's toggle still works (it is the only return
							    path when no groups exist). */}
							<button
								className="btn btn-icon"
								onClick={() => setTrashOpen(false)}
								title="Back to passwords"
								aria-label="Back to passwords"
							>
								<BackIcon />
							</button>
							<h2>Trash</h2>
							<button
								className="btn btn-danger btn-sm"
								onClick={() => setEmptyConfirm(true)}
								disabled={trashBusy || trashList.length === 0}
							>
								Empty trash
						</button>
					</div>
					<div className="entry-list screen-scroll-region" role="list">
						{state.deletedStatus === "idle" ||
						state.deletedStatus === "loading" ? (
							<div className="loading" role="status">
								<span className="spinner" />
								<span>Loading trash…</span>
							</div>
						) : state.deletedStatus === "error" ? (
							<div className="resource-error" role="alert">
								<p>Could not load the trash.</p>
								<button
									className="btn btn-secondary"
									onClick={() =>
										void actions.loadDeletedEntries().catch((e) => {
											showToast(errorMessage(e, "Failed to load trash"));
										})
									}
								>
									Retry
								</button>
							</div>
						) : trashList.length === 0 ? (
							<div className="empty-state" role="listitem">
								<TrashIcon size={48} />
								<p>Trash is empty</p>
							</div>
						) : (
							<ul className="trash-list">
								{trashList.map((entry) => (
									<li key={entry.id} className="trash-item">
										<div className="trash-item-info">
											<span className="trash-item-title">
												{entry.title || "Untitled"}
											</span>
											<span className="trash-item-time">
												{entry.deleted_at
													? `Deleted ${new Date(entry.deleted_at * 1000).toLocaleString()}`
													: "Deleted"}
											</span>
										</div>
										<div className="trash-item-actions">
											<button
												type="button"
												className="btn btn-secondary btn-sm"
												onClick={() => void handleRestore(entry)}
												disabled={trashBusy}
											>
												Restore
											</button>
											<button
												type="button"
												className="btn btn-danger btn-sm"
												onClick={() => setPurgeTarget(entry)}
												disabled={trashBusy}
											>
												Delete forever
											</button>
										</div>
									</li>
								))}
							</ul>
						)}
					</div>
					{/* Permanent delete is the one destructive trash action, so it
						    goes through the shared danger-confirmation modal. */}
					<DeleteConfirmModal
						isOpen={emptyConfirm}
						message={`Permanently delete all ${trashList.length} item${trashList.length === 1 ? "" : "s"} in the trash? This cannot be undone.`}
						onConfirm={() => {
							setEmptyConfirm(false);
							void handleEmptyTrash();
						}}
						onCancel={() => setEmptyConfirm(false)}
						isDeleting={trashBusy}
					/>
					<DeleteConfirmModal
						isOpen={purgeTarget !== null}
						message={`Permanently delete "${purgeTarget?.title || "Untitled"}"? This cannot be undone.`}
						onConfirm={() => void handlePurgeConfirm()}
						onCancel={() => setPurgeTarget(null)}
						isDeleting={trashBusy}
					/>
				</div>
			)}

			{/* The live list is the trash's sibling, not its parent: opening the
			    trash unmounts search/sort and the list (v1.4.0 rule, unchanged). */}
			{!trashOpen && (
				<div className="entry-list screen-scroll-region" role="list">
					{state.entriesStatus === "idle" ||
					state.entriesStatus === "loading" ? (
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
								onClick={() =>
									void actions.loadEntries().catch((e) => {
										// loadEntries already flips the resource state; the
										// toast keeps the retry rejection from being silent
										// for transient failures the state banner misses.
										showToast(errorMessage(e, "Failed to load passwords"));
									})
								}
							>
								Retry
							</button>
						</div>
					) : sortedEntries.length === 0 ? (
						<div className="empty-state" role="listitem">
							<LockIcon size={64} />
							<p>
								{state.searchQuery
									? "No matching passwords found"
									: "No passwords saved yet"}
							</p>
							{!state.searchQuery && (
								<button
									type="button"
									className="btn btn-primary"
									onClick={handleAddClick}
								>
									Add your first password
								</button>
							)}
						</div>
					) : (
						// §5.6.1: virtualize the entry list so 10k entries render only the
						// visible window. Combined with the memoized EntryRow and the
						// deferred query, this keeps the main-thread long task under 50ms.
						<Virtuoso
							data={sortedEntries}
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
			)}
		</div>
	);
}
