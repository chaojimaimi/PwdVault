import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { EntrySummary, SecurityReport } from "../../types";

// v1.5.0 (WP1): DashboardScreen — renders the three finding lists with
// titles resolved from the vault entry list, opens entries on row click,
// shows the all-clear state, and re-runs the report. Contexts and the api
// module are mocked (established screen-test pattern).

const getSecurityReport = vi.fn();

vi.mock("../../api/vault", () => ({
	getSecurityReport: (...args: unknown[]) => getSecurityReport(...args),
}));

const authActions = {
	navigate: vi.fn(),
	lock: vi.fn().mockResolvedValue(undefined),
};

const vaultActions = {
	loadEntries: vi.fn().mockResolvedValue(undefined),
	selectEntry: vi.fn().mockResolvedValue(undefined),
};

const DEFAULT_ENTRIES: EntrySummary[] = [
	{
		id: "weak-1",
		title: "Old Mail",
		url: "",
		username: "weak-user",
		tags: [],
		created_at: 0,
		updated_at: 1_700_000_000,
	},
	{
		id: "reused-1",
		title: "Forum A",
		url: "",
		username: "shared-user",
		tags: [],
		created_at: 0,
		updated_at: 1_700_000_100,
	},
	{
		id: "reused-2",
		title: "Forum B",
		url: "",
		username: "shared-user",
		tags: [],
		created_at: 0,
		updated_at: 1_700_000_200,
	},
	{
		id: "stale-1",
		title: "Ancient",
		url: "",
		username: "old-user",
		tags: [],
		created_at: 0,
		updated_at: 1_600_000_000,
	},
];

const vaultHolder = {
	state: {
		entries: DEFAULT_ENTRIES,
		deletedEntries: [],
		deletedStatus: "success",
		groups: [],
		selectedGroupId: null,
		selectedEntry: null,
		searchQuery: "",
		entriesStatus: "success",
		entriesError: null,
		groupsStatus: "success",
		groupsError: null,
	},
	actions: vaultActions,
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
		actions: authActions,
	}),
	useVault: () => vaultHolder,
	useSettings: () => settingsHolder,
}));

vi.mock("../../utils/toast", () => ({ showToast: vi.fn() }));

const REPORT: SecurityReport = {
	generated_at: 1_800_000_000,
	total: 4,
	// v1.7.0: score is the zxcvbn wire value 0-4 (was 0-100); the badge
	// renders the securityScoreLabel mapping, not `${score}/100`.
	weak: [{ id: "weak-1", score: 2 }],
	reused: [["reused-1", "reused-2"]],
	stale: ["stale-1"],
};

beforeEach(() => {
	vi.clearAllMocks();
	vaultActions.loadEntries.mockResolvedValue(undefined);
	vaultActions.selectEntry.mockResolvedValue(undefined);
	vaultHolder.state = { ...vaultHolder.state, entries: DEFAULT_ENTRIES };
	getSecurityReport.mockResolvedValue(REPORT);
});

import { DashboardScreen } from "../DashboardScreen";

describe("DashboardScreen", () => {
	it("renders the three finding lists with titles resolved from the vault", async () => {
		render(<DashboardScreen />);

		await waitFor(() => expect(getSecurityReport).toHaveBeenCalledTimes(1));
		expect(await screen.findByText("Old Mail")).toBeTruthy();
		expect(screen.getByText("Weak")).toBeTruthy();
		// v1.7.0 honest copy for the new weak semantics.
		expect(screen.getByText(/leak-corpus scan/i)).toBeTruthy();
		expect(screen.getByText("Forum A")).toBeTruthy();
		expect(screen.getByText("Forum B")).toBeTruthy();
		// The stale copy is "unchanged for over a year" — never "unused".
		expect(screen.getByText(/Unchanged for over a year/i)).toBeTruthy();
		expect(screen.getByText("Ancient")).toBeTruthy();
		expect(screen.getByText(/4 passwords scanned/)).toBeTruthy();
		// Summary row: title, hint and re-run button coexist in one row.
		expect(screen.getByText("Re-run check")).toBeTruthy();
		expect(vaultActions.loadEntries).toHaveBeenCalled();
	});

	it("opens the entry editor when a finding row is clicked", async () => {
		render(<DashboardScreen />);
		const row = await screen.findByText("Old Mail");
		fireEvent.click(row);

		await waitFor(() =>
			expect(vaultActions.selectEntry).toHaveBeenCalledWith("weak-1"),
		);
		expect(authActions.navigate).toHaveBeenCalledWith("entry");
	});

	it("keeps navigation working when selectEntry rejects", async () => {
		const { showToast } = await import("../../utils/toast");
		vaultActions.selectEntry.mockRejectedValueOnce(new Error("locked"));
		render(<DashboardScreen />);
		const row = await screen.findByText("Old Mail");
		fireEvent.click(row);

		await waitFor(() => expect(showToast).toHaveBeenCalled());
		expect(authActions.navigate).not.toHaveBeenCalled();
	});

	it("shows the healthy empty state when every list is empty", async () => {
		getSecurityReport.mockResolvedValue({
			generated_at: 1,
			total: 2,
			weak: [],
			reused: [],
			stale: [],
		});
		render(<DashboardScreen />);

		expect(await screen.findByText(/All clear/i)).toBeTruthy();
		expect(
			screen.getByText(/No weak, reused, or stale passwords found/),
		).toBeTruthy();
		expect(screen.queryByText("Weak passwords")).toBeNull();
		expect(screen.queryByText("Reused passwords")).toBeNull();
		expect(screen.queryByText("Stale passwords")).toBeNull();
	});

	it("re-runs the report from the re-run button", async () => {
		render(<DashboardScreen />);
		await screen.findByText("Old Mail");
		fireEvent.click(screen.getByText("Re-run check"));

		await waitFor(() => expect(getSecurityReport).toHaveBeenCalledTimes(2));
	});

	it("shows the error state with retry when the report fails", async () => {
		getSecurityReport.mockRejectedValueOnce(new Error("VaultLocked"));
		render(<DashboardScreen />);

		expect(
			await screen.findByText(/Could not build the security report/),
		).toBeTruthy();
		fireEvent.click(screen.getByText("Retry"));
		await waitFor(() => expect(getSecurityReport).toHaveBeenCalledTimes(2));
	});
});
