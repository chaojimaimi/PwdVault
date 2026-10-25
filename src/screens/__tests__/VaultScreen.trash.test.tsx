import type React from "react";
import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { EntrySummary } from "../../types";

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

const vaultHolder = {
	state: {
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
		deletedEntries,
		deletedStatus: "success" as const,
		groups: [],
		selectedGroupId: null,
		selectedEntry: null,
		searchQuery: "",
		entriesStatus: "success" as const,
		entriesError: null,
		groupsStatus: "success" as const,
		groupsError: null,
	},
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
			{data.map((item, index) => itemContent(index, item))}
		</div>
	),
}));

beforeEach(() => {
	vi.clearAllMocks();
	actions.loadEntries.mockResolvedValue(undefined);
	actions.loadDeletedEntries.mockResolvedValue(undefined);
	vaultHolder.state = {
		...vaultHolder.state,
		deletedEntries,
		deletedStatus: "success",
	};
});

describe("VaultScreen trash (v1.4.0)", () => {
	it("opens the trash, lists deleted entries, and hides the live-list search", async () => {
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);

		// The trash list is NOT in the main view (not searched, not sorted).
		expect(screen.queryByText("Old Site")).toBeNull();
		expect(screen.getByLabelText("Search passwords")).toBeTruthy();

		fireEvent.click(screen.getByLabelText("Open trash"));

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
		fireEvent.click(screen.getByLabelText("Open trash"));
		await screen.findByText("Old Site");

		fireEvent.click(screen.getAllByRole("button", { name: "Restore" })[0]);
		await waitFor(() => expect(actions.restoreEntry).toHaveBeenCalledWith("dead-1"));
	});

	it("routes permanent deletion through the danger confirmation modal", async () => {
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);
		fireEvent.click(screen.getByLabelText("Open trash"));
		await screen.findByText("Old Site");

		fireEvent.click(screen.getAllByRole("button", { name: "Delete forever" })[0]);
		// The confirm modal names the victim before anything is purged.
		expect(await screen.findByText("Confirm Delete")).toBeTruthy();
		expect(screen.getByText(/Permanently delete "Old Site"/)).toBeTruthy();
		expect(actions.purgeEntry).not.toHaveBeenCalled();

		fireEvent.click(screen.getByRole("button", { name: "Delete" }));
		await waitFor(() => expect(actions.purgeEntry).toHaveBeenCalledWith("dead-1"));
	});

	it("empties the trash from the header button", async () => {
		const { VaultScreen } = await import("../VaultScreen");
		render(<VaultScreen />);
		fireEvent.click(screen.getByLabelText("Open trash"));
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
		fireEvent.click(screen.getByLabelText("Open trash"));
		expect(await screen.findByText("Trash is empty")).toBeTruthy();
		const empty = screen.getByRole("button", { name: "Empty trash" });
		expect((empty as HTMLButtonElement).disabled).toBe(true);
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
