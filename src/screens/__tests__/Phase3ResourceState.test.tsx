import { render, screen } from "@testing-library/react";
import { vi, expect, test } from "vitest";
import { VaultScreen } from "../VaultScreen";

// VaultScreen now subscribes to useAuth, useVault, and useSettings separately.
vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({
		state: { isUnlocked: true },
		actions: { navigate: vi.fn(), lock: vi.fn() },
	}),
	useVault: () => ({
		state: {
			entries: [],
			groups: [],
			selectedGroupId: null,
			selectedEntry: null,
			searchQuery: "",
			entriesStatus: "error",
			entriesError: "database unavailable",
			groupsStatus: "error",
			groupsError: "database unavailable",
		},
		dispatch: vi.fn(),
		actions: {
			loadEntries: vi.fn().mockRejectedValue(new Error("database unavailable")),
			loadGroups: vi.fn().mockRejectedValue(new Error("database unavailable")),
			selectGroup: vi.fn(),
			setSearchQuery: vi.fn(),
			getEntrySecret: vi.fn(),
			selectEntry: vi.fn(),
		},
	}),
	useSettings: () => ({
		state: { updateInfo: null, settings: {}, status: "idle", error: null },
		actions: { dismissUpdate: vi.fn() },
	}),
}));
vi.mock("../../hooks/useTheme", () => ({
	useTheme: () => ({ toggleTheme: vi.fn() }),
}));

test("entry load error is never rendered as an empty vault", async () => {
	render(<VaultScreen />);
	expect(
		await screen.findByText("Could not load passwords."),
	).toBeInTheDocument();
	expect(screen.queryByText("No passwords saved yet")).not.toBeInTheDocument();
	expect(
		screen.getAllByRole("button", { name: "Retry" }).length,
	).toBeGreaterThan(0);
});
