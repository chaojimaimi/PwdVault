import type React from "react";
import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { EntrySummary, Group } from "../../types";

// v1.4.0 (WP4): trash view on the VaultScreen — open/list/restore/purge/
// empty flow, plus the sort-select wiring. VaultScreen pulls three contexts
// and the theme hook; they are mocked here (established screen-test pattern).

const actions = {
	loadEntries: vi.fn().mockResolvedValue(undefined),
	loadGroups: vi.fn().mockResolvedValue(undefined),
	loadDeletedEntries: vi.fn().mockResolvedValue(undefined),
	restoreEntry: vi.fn().mockResolvedValue(undefined),
	purgeEntry: vi.fn().mockResolvedValue(undefined),
	emptyTrash: vi.fn().mockResolvedValue(undefined),
	selectEntry: vi.fn().mockResolvedValue(undefined),
	selectGroup: vi.fn(),
	getEntrySecret: vi.fn().mockResolvedValue(null),
	setSearchQuery: vi.fn(),
	deleteEntry: vi.fn(),
};

const deletedEntries: EntrySummary[] = [
	{
		id: "dead-1",
		title: "Old Site",
		url: "",
		username: "u",
		tags: [],
		created_at: 0,
		updated_at: 100,
		deleted_at: 1_700_000_000,
	},
	{
		id: "dead-2",
		title: "Other Site",
		url: "",
		username: "u",
		tags: [],
		created_at: 0,
		updated_at: 200,
		deleted_at: 1_700_000_500,
	},
];

// Canonical baseline for the holder: every field a test might mutate must be
// reset in beforeEach, or an injected groups/groupsStatus variant leaks into
// later cases (review P2 — the sort case was already rendering on inherited
// "error"+selected state that it merely did not assert against).
const DEFAULT_STATE = {
	entries: [
		{
			id: "live-1",
			title: "Live Site",
			url: "",
			username: "u",
			tags: [],
			created_at: 0,
			updated_at: 300,
		},
	],
	deletedEntries: [] as EntrySummary[],
	deletedStatus: "success" as const,
	// Widened (SettingsScreen.updates precedent): the v1.4.1 tests inject
	// groups / a groupsStatus variant through shallow copies of this holder.
	groups: [] as Group[],
	selectedGroupId: null as string | null,
	selectedEntry: null,
	searchQuery: "",
	entriesStatus: "success" as const,
	entriesError: null,
	groupsStatus: "success" as string,
	groupsError: null as string | null,
};

const vaultHolder = {
	state: { ...DEFAULT_STATE, deletedEntries },
	actions,
};

const settingsHolder = {
	state: {
		settings: {
			auto_lock_secs: 600,
			default_length: 16,
			default_include_uppercase: true,
			default_include_lowercase: true,
			default_include_numbers: true,
			default_include_symbols: true,
			check_updates: true,
			sort_mode: "recent" as const,
			global_shortcut_enabled: true,
			global_shortcut: "CmdOrCtrl+Shift+Space",
		},
		update: null,
		updatePhase: "available" as const,
		downloadProgress: 0,
		status: "success" as const,
		error: null,
	},
	actions: {
		updateSettings: vi.fn().mockResolvedValue(undefined),
		installUpdate: vi.fn(),
		relaunchApp: vi.fn(),
		dismissUpdate: vi.fn(),
		loadSettings: vi.fn(),
	},
};

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({
		state: { isUnlocked: true, isLoading: false, bootError: null },
		actions: { navigate: vi.fn(), lock: vi.fn().mockResolvedValue(undefined) },
	}),
	useVault: () => vaultHolder,
	useSettings: () => settingsHolder,
}));

vi.mock("../../hooks/useTheme", () => ({
	useTheme: () => ({ theme: "light", toggleTheme: vi.fn(), themes: [] }),
}));

vi.mock("../../utils/clipboard", () => ({
	copyWithTimeout: vi.fn().mockResolvedValue(undefined),
	copyWithoutClear: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../utils/toast", () => ({ showToast: vi.fn() }));

// jsdom has no layout: render entries as a plain list instead of Virtuoso.
vi.mock("react-virtuoso", () => ({
	Virtuoso: ({
		data,
		itemContent,
	}: {
		data: unknown[];
		itemContent: (index: number, item: unknown) => React.ReactElement;
	}) => (
		<div>
			{data.map((item, index) => (
				<div key={index}>{itemContent(index, item)}</div>
			))}
		</div>
	),
}));

beforeEach(() => {
	vi.clearAllMocks();
	actions.loadEntries.mockResolvedValue(undefined);
	actions.loadDeletedEntries.mockResolvedValue(undefined);
	// The group-tab test gives selectGroup a state-mutating implementation;
	// re-stub it here so that behavior cannot leak into later tests.
	actions.selectGroup.mockImplementation(() => {});
	vaultHolder.state = { ...DEFAULT_STATE, deletedEntries };
});

describe("VaultScreen trash (v1.4.0)", () => {
	it("opens the trash, lists deleted entries, and hides the live-list search", async () => {
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);

		// The trash list is NOT in the main view (not searched, not sorted).
		expect(screen.queryByText("Old Site")).toBeNull();
		expect(screen.getByLabelText("Search passwords")).toBeTruthy();
		// v1.4.1: the old icon-button entry is gone — its locator must match
		// nothing (the "Trash" tab name and "Open trash" never overlap, so a
		// missed deletion would not fail the new locator on its own).
		expect(screen.queryByLabelText("Open trash")).toBeNull();

		fireEvent.click(screen.getByRole("button", { name: "Trash" }));

		await waitFor(() => expect(actions.loadDeletedEntries).toHaveBeenCalled());
		expect(screen.getByText("Old Site")).toBeTruthy();
		expect(screen.getByText("Other Site")).toBeTruthy();
		// Each row carries its deleted-time stamp.
		expect(screen.getAllByText(/Deleted/)).toHaveLength(2);
		// Structural guarantee: the trash view has no search/sort UI at all.
		expect(screen.queryByLabelText("Search passwords")).toBeNull();
		expect(screen.queryByLabelText("Sort passwords")).toBeNull();
	});

	it("restores an entry from the trash", async () => {
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);
		fireEvent.click(screen.getByRole("button", { name: "Trash" }));
		await screen.findByText("Old Site");

		fireEvent.click(screen.getAllByRole("button", { name: "Restore" })[0]);
		await waitFor(() =>
			expect(actions.restoreEntry).toHaveBeenCalledWith("dead-1"),
		);
	});

	it("routes permanent deletion through the danger confirmation modal", async () => {
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);
		fireEvent.click(screen.getByRole("button", { name: "Trash" }));
		await screen.findByText("Old Site");

		fireEvent.click(
			screen.getAllByRole("button", { name: "Delete forever" })[0],
		);
		// The confirm modal names the victim before anything is purged.
		expect(await screen.findByText("Confirm Delete")).toBeTruthy();
		expect(screen.getByText(/Permanently delete "Old Site"/)).toBeTruthy();
		expect(actions.purgeEntry).not.toHaveBeenCalled();

		fireEvent.click(screen.getByRole("button", { name: "Delete" }));
		await waitFor(() =>
			expect(actions.purgeEntry).toHaveBeenCalledWith("dead-1"),
		);
	});

	it("empties the trash from the header button", async () => {
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);
		fireEvent.click(screen.getByRole("button", { name: "Trash" }));
		await screen.findByText("Old Site");

		fireEvent.click(screen.getByRole("button", { name: "Empty trash" }));
		// Bulk emptying goes through the same danger confirmation: the modal
		// names the scope before anything is purged.
		expect(await screen.findByText("Confirm Delete")).toBeTruthy();
		expect(screen.getByText(/Permanently delete all 2 items/)).toBeTruthy();
		expect(actions.emptyTrash).not.toHaveBeenCalled();

		fireEvent.click(screen.getByRole("button", { name: "Delete" }));
		await waitFor(() => expect(actions.emptyTrash).toHaveBeenCalled());
	});

	it("shows the empty state once the trash is cleared", async () => {
		vaultHolder.state = { ...vaultHolder.state, deletedEntries: [] };
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);
		fireEvent.click(screen.getByRole("button", { name: "Trash" }));
		expect(await screen.findByText("Trash is empty")).toBeTruthy();
		const empty = screen.getByRole("button", { name: "Empty trash" });
		expect((empty as HTMLButtonElement).disabled).toBe(true);
	});

	// --- v1.4.1: the entry is a pinned Trash tab in the group tabs row ---

	it("keeps the Trash tab reachable next to Create group with zero groups", async () => {
		// Default holder: groups=[] — the CTA and the pinned tab share one row.
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);

		expect(screen.getByRole("button", { name: "Create group" })).toBeTruthy();
		expect(screen.getByRole("button", { name: "Trash" })).toBeTruthy();
	});

	it("returns to the main list when the Trash tab is toggled again", async () => {
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);

		fireEvent.click(screen.getByRole("button", { name: "Trash" }));
		await screen.findByText("Old Site");
		expect(screen.queryByLabelText("Search passwords")).toBeNull();

		// Toggle, not a one-way door: with zero groups there is no All tab,
		// so the Trash tab is the only way back to the main list.
		fireEvent.click(screen.getByRole("button", { name: "Trash" }));
		expect(screen.getByLabelText("Search passwords")).toBeTruthy();
		expect(screen.queryByText("Old Site")).toBeNull();
	});

	it("a group tab exits the trash without ever co-activating with it", async () => {
		// The mock bypasses the real reducer: selectGroup must update the
		// holder or the post-click active state would never render.
		actions.selectGroup.mockImplementation((groupId: string | null) => {
			vaultHolder.state = { ...vaultHolder.state, selectedGroupId: groupId };
		});
		vaultHolder.state = {
			...vaultHolder.state,
			groups: [{ id: "g1", name: "Work", created_at: 0, updated_at: 0 }],
			selectedGroupId: null,
		};
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);

		fireEvent.click(screen.getByRole("button", { name: "Trash" }));
		await screen.findByText("Old Site");

		// Mutex while the trash is open (review condition): the group tab must
		// not highlight — Trash is the only current tab. Asserting only the
		// post-exit state would stay green even without the !trashOpen guard.
		const workTab = screen.getByRole("button", { name: "Work" });
		expect(workTab).not.toHaveClass("active");
		expect(workTab).not.toHaveAttribute("aria-current");
		const trashTab = screen.getByRole("button", { name: "Trash" });
		expect(trashTab).toHaveClass("active");
		expect(trashTab).toHaveAttribute("aria-current", "true");

		fireEvent.click(workTab);
		await waitFor(() => expect(actions.selectGroup).toHaveBeenCalledWith("g1"));

		// Back on the main list with the mutex flipped: Work is current,
		// Trash lost its highlight.
		expect(screen.getByLabelText("Search passwords")).toBeTruthy();
		expect(screen.queryByText("Old Site")).toBeNull();
		const workTabAfter = screen.getByRole("button", { name: "Work" });
		expect(workTabAfter).toHaveClass("active");
		expect(workTabAfter).toHaveAttribute("aria-current", "true");
		const trashTabAfter = screen.getByRole("button", { name: "Trash" });
		expect(trashTabAfter).not.toHaveClass("active");
		expect(trashTabAfter).not.toHaveAttribute("aria-current");
	});

	it("keeps the Trash tab reachable when loading groups failed", async () => {
		vaultHolder.state = {
			...vaultHolder.state,
			groupsStatus: "error",
			groupsError: "database unavailable",
		};
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);

		// The inline retry and the pinned tab coexist in one row (D1 error
		// state): the trash stays reachable even when groups never loaded.
		expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
		expect(screen.getByRole("button", { name: "Trash" })).toBeTruthy();
	});
});

describe("VaultScreen sort control (v1.4.0)", () => {
	it("persists a sort-mode change through updateSettings", async () => {
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);

		fireEvent.change(screen.getByLabelText("Sort passwords"), {
			target: { value: "alpha" },
		});
		await waitFor(() =>
			expect(settingsHolder.actions.updateSettings).toHaveBeenCalledWith(
				expect.objectContaining({ sort_mode: "alpha" }),
			),
		);
	});
});
