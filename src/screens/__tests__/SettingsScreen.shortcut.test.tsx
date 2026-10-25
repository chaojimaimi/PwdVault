import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { DEFAULT_SETTINGS } from "../../types";

// v1.4.0 (WP5): the global-shortcut settings section. A changed binding is
// validated through the register_global_shortcut command BEFORE persisting;
// a registration failure shows a red hint and keeps the previous binding.

const registerGlobalShortcut = vi.fn();
const updateSettings = vi.fn();

vi.mock("../../api/vault", () => ({
	registerGlobalShortcut: (...args: unknown[]) =>
		registerGlobalShortcut(...args),
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
	registerGlobalShortcut.mockResolvedValue(undefined);
	loadedSettings({});
});

async function renderScreen() {
	const { SettingsScreen } = await import("../SettingsScreen");
	return render(<SettingsScreen />);
}

describe("SettingsScreen global shortcut (v1.4.0)", () => {
	it("registers a changed binding, then persists it", async () => {
		const { unmount } = await renderScreen();

		fireEvent.change(screen.getByLabelText("Shortcut"), {
			target: { value: "CmdOrCtrl+P" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save Settings" }));

		await waitFor(() =>
			expect(registerGlobalShortcut).toHaveBeenCalledWith(true, "CmdOrCtrl+P"),
		);
		await waitFor(() =>
			expect(updateSettings).toHaveBeenCalledWith(
				expect.objectContaining({ global_shortcut: "CmdOrCtrl+P" }),
			),
		);
		unmount();
	});

	it("keeps an unchanged binding out of the registration path", async () => {
		const { unmount } = await renderScreen();

		// Toggle an unrelated setting only — no shortcut change, no
		// registration call.
		fireEvent.change(screen.getByLabelText("Lock after inactivity"), {
			target: { value: "300" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save Settings" }));

		await waitFor(() => expect(updateSettings).toHaveBeenCalled());
		expect(registerGlobalShortcut).not.toHaveBeenCalled();
		unmount();
	});

	it("shows the error in red and reverts to the previous binding on failure", async () => {
		registerGlobalShortcut.mockRejectedValue(
			new Error("Cannot register shortcut 'Ctrl++': bad key"),
		);
		const { unmount } = await renderScreen();

		fireEvent.change(screen.getByLabelText("Shortcut"), {
			target: { value: "Ctrl++" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save Settings" }));

		const hint = await screen.findByRole("alert");
		expect(hint.textContent).toContain("Cannot register shortcut");
		// Nothing persisted; the input shows the previously-loaded binding.
		expect(updateSettings).not.toHaveBeenCalled();
		await waitFor(() =>
			expect(
				(screen.getByLabelText("Shortcut") as HTMLInputElement).value,
			).toBe(DEFAULT_SETTINGS.global_shortcut),
		);
		unmount();
	});
});
