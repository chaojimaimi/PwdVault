import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { DEFAULT_SETTINGS } from "../../types";

// v1.6.0 (D6): the timed auto-sync settings section. Sits next to Trash
// Auto-Purge (the other unlock-gated background automation) and saves
// through the shared updateSettings action like every other option-row.

const updateSettings = vi.fn();

vi.mock("../../api/vault", () => ({
	registerGlobalShortcut: vi.fn(),
	revokeExtensionAccess: vi.fn(),
}));
vi.mock("../../utils/toast", () => ({ showToast: vi.fn() }));

// Heavy self-contained sections are irrelevant here.
vi.mock("../../components/SecuritySettingsSection", () => ({
	SecuritySettingsSection: () => <div />,
}));
vi.mock("../../components/SyncSettingsSection", () => ({
	SyncSettingsSection: () => <div />,
}));
vi.mock("../../components/UpdatesSettingsSection", () => ({
	UpdatesSettingsSection: () => <div />,
}));

const settingsHolder = {
	state: {
		settings: { ...DEFAULT_SETTINGS },
		update: null,
		updatePhase: "available" as const,
		downloadProgress: 0,
		status: "success" as const,
		error: null,
	},
	actions: {
		updateSettings: (...args: unknown[]) => updateSettings(...args),
		loadSettings: vi.fn(),
		installUpdate: vi.fn(),
		relaunchApp: vi.fn(),
		dismissUpdate: vi.fn(),
	},
};

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({
		actions: { navigate: vi.fn() },
	}),
	useSettings: () => settingsHolder,
}));

vi.mock("../../hooks/useTheme", () => ({
	useTheme: () => ({ theme: "light", toggleTheme: vi.fn(), themes: [] }),
}));

const loadedSettings = (overrides: Partial<typeof DEFAULT_SETTINGS>) => {
	settingsHolder.state = {
		...settingsHolder.state,
		settings: { ...DEFAULT_SETTINGS, ...overrides },
	};
};

beforeEach(() => {
	vi.clearAllMocks();
	updateSettings.mockResolvedValue({ ...DEFAULT_SETTINGS });
	loadedSettings({});
});

async function renderScreen() {
	const { SettingsScreen } = await import("../SettingsScreen");
	return render(<SettingsScreen />);
}

describe("SettingsScreen auto-sync (v1.6.0)", () => {
	it("renders the Off default and the 5/15/30/60 choices", async () => {
		const { unmount } = await renderScreen();

		const select = screen.getByLabelText(
			"Sync automatically",
		) as HTMLSelectElement;
		expect(select.value).toBe("0");
		const options = Array.from(select.options).map((option) => option.value);
		expect(options).toEqual(["0", "5", "15", "30", "60"]);
		// The cloud-connection precondition must be visible to the user.
		expect(
			screen.getByText(/Requires cloud sync to be connected/),
		).toBeTruthy();
		unmount();
	});

	it("saves a chosen interval and persists it through updateSettings", async () => {
		const { unmount } = await renderScreen();

		fireEvent.change(screen.getByLabelText("Sync automatically"), {
			target: { value: "15" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save Settings" }));

		await waitFor(() =>
			expect(updateSettings).toHaveBeenCalledWith(
				expect.objectContaining({ auto_sync_interval_min: 15 }),
			),
		);
		unmount();
	});

	it("reflects a loaded nonzero setting instead of the default", async () => {
		loadedSettings({ auto_sync_interval_min: 60 });
		const { unmount } = await renderScreen();

		expect(
			(screen.getByLabelText("Sync automatically") as HTMLSelectElement)
				.value,
		).toBe("60");
		unmount();
	});
});
