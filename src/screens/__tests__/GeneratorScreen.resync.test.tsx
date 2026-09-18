import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";

// E16 regression: the generator must resync its options (and regenerate once)
// when saved settings finish loading after mount, unless the user already
// touched a control.

const generatePassword = vi.fn();
const navigate = vi.fn();

vi.mock("../../api/vault", () => ({
	generatePassword: (...args: unknown[]) => generatePassword(...args),
}));
vi.mock("../../utils/clipboard", () => ({
	copyWithTimeout: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("../../utils/toast", () => ({ showToast: vi.fn() }));

// Mutable holder read at render time (mock factory hoisting precedent from
// GroupManager.test.tsx).
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
		update: null,
		updatePhase: "available" as const,
		downloadProgress: 0,
		status: "loading" as string,
		error: null,
	},
};

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({ actions: { navigate } }),
	useSettings: () => settingsHolder,
}));

const loadedSettings = (length: number) => ({
	...settingsHolder.state.settings,
	default_length: length,
});

beforeEach(() => {
	vi.clearAllMocks();
	generatePassword.mockResolvedValue("generated-password");
	settingsHolder.state = {
		...settingsHolder.state,
		settings: loadedSettings(16),
		status: "loading",
	};
});

describe("GeneratorScreen settings resync", () => {
	it("resyncs options and regenerates once settings land after mount", async () => {
		const { GeneratorScreen } = await import("../GeneratorScreen");
		const { rerender } = render(<GeneratorScreen />);

		// Mount generation used the pre-load defaults.
		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(1));
		expect(generatePassword).toHaveBeenLastCalledWith(
			expect.objectContaining({ length: 16 }),
		);

		// Saved settings (length 32) finish loading — one resync + one
		// regeneration with the NEW options.
		settingsHolder.state = {
			...settingsHolder.state,
			settings: loadedSettings(32),
			status: "success",
		};
		rerender(<GeneratorScreen />);

		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(2));
		expect(generatePassword).toHaveBeenLastCalledWith(
			expect.objectContaining({ length: 32 }),
		);
		// The length control reflects the resynced default.
		expect(
			screen.getByRole("slider", { name: "Password length" }),
		).toHaveValue("32");
	});

	it("does not regenerate a second time when settings were already loaded", async () => {
		settingsHolder.state = {
			...settingsHolder.state,
			settings: loadedSettings(24),
			status: "success",
		};
		const { GeneratorScreen } = await import("../GeneratorScreen");
		render(<GeneratorScreen />);

		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(1));
		expect(generatePassword).toHaveBeenLastCalledWith(
			expect.objectContaining({ length: 24 }),
		);
	});

	it("keeps user-touched options when settings land afterwards", async () => {
		const { GeneratorScreen } = await import("../GeneratorScreen");
		const { rerender } = render(<GeneratorScreen />);
		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(1));

		// User drags the length slider.
		fireEvent.change(
			screen.getByRole("slider", { name: "Password length" }),
			{ target: { value: "48" } },
		);

		settingsHolder.state = {
			...settingsHolder.state,
			settings: loadedSettings(32),
			status: "success",
		};
		rerender(<GeneratorScreen />);

		// No regeneration from the resync path; the touched value stays.
		expect(
			screen.getByRole("slider", { name: "Password length" }),
		).toHaveValue("48");
	});
});
