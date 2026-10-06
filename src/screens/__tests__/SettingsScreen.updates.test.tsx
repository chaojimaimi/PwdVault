import { render, fireEvent, screen } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { SettingsScreen } from "../SettingsScreen";
import type { ManualCheckState } from "../../context/SettingsContext";
import { getVersion } from "@tauri-apps/api/app";

// v1.2.2: manual "Check for updates" UI in the Settings Updates section —
// status-line copy for the four manualCheck phases, button disabling that
// mirrors the checkForUpdates guards (checking / downloading / ready),
// banner mounting above the content, and the current-version row.

const navigate = vi.fn();
const checkForUpdates = vi.fn();
const installUpdate = vi.fn();
const relaunchApp = vi.fn();
const dismissUpdate = vi.fn();
const updateSettings = vi.fn();

// Mutable holder read at render time (mock factory hoisting precedent from
// GeneratorScreen.resync.test.tsx).
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
		},
		update: null as { version: string } | null,
		updatePhase: "available" as "available" | "downloading" | "ready",
		downloadProgress: 0,
		manualCheck: { phase: "idle", checkedAt: null } as ManualCheckState,
		status: "success" as string,
		error: null as string | null,
	},
};

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({ actions: { navigate } }),
	useSettings: () => ({
		state: settingsHolder.state,
		actions: { checkForUpdates, installUpdate, relaunchApp, dismissUpdate, updateSettings },
	}),
}));

vi.mock("../../hooks/useTheme", () => ({
	useTheme: () => ({ theme: "light", setTheme: vi.fn(), themes: ["light", "dark"] }),
}));

vi.mock("@tauri-apps/api/app", () => ({
	getVersion: vi.fn(),
}));

// The two self-contained sections fetch their own data; this test targets the
// Updates section only, so stub them out.
vi.mock("../../components/SecuritySettingsSection", () => ({
	SecuritySettingsSection: () => <div data-testid="security-section" />,
}));
vi.mock("../../components/SyncSettingsSection", () => ({
	SyncSettingsSection: () => <div data-testid="sync-section" />,
}));

const idleState = () => ({
	settings: { ...settingsHolder.state.settings },
	update: null,
	updatePhase: "available" as const,
	downloadProgress: 0,
	manualCheck: { phase: "idle" as const, checkedAt: null },
	status: "success",
	error: null,
});

beforeEach(() => {
	vi.clearAllMocks();
	vi.mocked(getVersion).mockResolvedValue("1.2.1");
	checkForUpdates.mockResolvedValue(undefined);
	settingsHolder.state = idleState();
});

describe("SettingsScreen manual update check", () => {
	it("shows the current version row and an enabled check button when idle", async () => {
		render(<SettingsScreen />);

		expect(await screen.findByText("Current version: 1.2.1")).toBeInTheDocument();
		expect(screen.queryByText(/is available/)).not.toBeInTheDocument();
		const button = screen.getByRole("button", { name: "Check for updates" });
		expect(button).toBeEnabled();
		fireEvent.click(button);
		expect(checkForUpdates).toHaveBeenCalledTimes(1);
	});

	it("renders the four phase status lines in an aria-live region", async () => {
		const { rerender } = render(<SettingsScreen />);
		await screen.findByText("Current version: 1.2.1");

		settingsHolder.state.manualCheck = { phase: "checking", checkedAt: null };
		rerender(<SettingsScreen />);
		const statusLine = screen.getByText("Checking for updates…");
		expect(statusLine).toHaveAttribute("aria-live", "polite");
		expect(statusLine).toHaveClass("update-check-status");

		settingsHolder.state.manualCheck = { phase: "available", checkedAt: 1, version: "1.2.2" };
		rerender(<SettingsScreen />);
		expect(
			screen.getByText("Update available: v1.2.2 — use the banner above to install"),
		).toBeInTheDocument();

		settingsHolder.state.manualCheck = {
			phase: "uptodate",
			checkedAt: new Date(2026, 9, 6, 14, 5).getTime(),
		};
		rerender(<SettingsScreen />);
		expect(
			screen.getByText("You're up to date (v1.2.1) — checked 14:05"),
		).toBeInTheDocument();

		settingsHolder.state.manualCheck = { phase: "error", checkedAt: 1 };
		rerender(<SettingsScreen />);
		expect(
			screen.getByText(
				"Couldn't reach the update server — check your connection and try again",
			),
		).toBeInTheDocument();
	});

	it("disables the check button while checking, downloading, or ready", async () => {
		const { rerender } = render(<SettingsScreen />);
		await screen.findByText("Current version: 1.2.1");

		settingsHolder.state.manualCheck = { phase: "checking", checkedAt: null };
		rerender(<SettingsScreen />);
		expect(screen.getByRole("button", { name: "Checking…" })).toBeDisabled();

		settingsHolder.state.manualCheck = { phase: "idle", checkedAt: null };
		settingsHolder.state.updatePhase = "downloading";
		rerender(<SettingsScreen />);
		expect(screen.getByRole("button", { name: "Check for updates" })).toBeDisabled();

		settingsHolder.state.updatePhase = "ready";
		rerender(<SettingsScreen />);
		expect(screen.getByRole("button", { name: "Check for updates" })).toBeDisabled();
	});

	it("mounts the update banner above the content when an update is present", async () => {
		settingsHolder.state.update = { version: "1.2.2" };
		render(<SettingsScreen />);

		expect(await screen.findByText("PwdVault 1.2.2 is available")).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Update now" }));
		expect(installUpdate).toHaveBeenCalledTimes(1);
	});
});
