import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";

// v1.4.0 (WP3): generator mode tabs (password / passphrase / PIN), per-mode
// options, and the session-only history list.

const generatePassword = vi.fn();
const navigate = vi.fn();

vi.mock("../../api/vault", () => ({
	generatePassword: (...args: unknown[]) => generatePassword(...args),
}));
vi.mock("../../utils/clipboard", () => ({
	copyWithTimeout: vi.fn().mockResolvedValue(undefined),
}));
vi.mock("../../utils/toast", () => ({ showToast: vi.fn() }));

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
};

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({ actions: { navigate } }),
	useSettings: () => settingsHolder,
}));

beforeEach(() => {
	vi.clearAllMocks();
	generatePassword.mockResolvedValue("generated-value");
});

describe("GeneratorScreen modes", () => {
	it("switches to passphrase mode and sends the passphrase parameters", async () => {
		const { GeneratorScreen } = await import("../GeneratorScreen");
		render(<GeneratorScreen />);

		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(1));
		fireEvent.click(screen.getByRole("tab", { name: "Passphrase" }));

		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(2));
		expect(generatePassword).toHaveBeenLastCalledWith(
			expect.objectContaining({
				mode: "passphrase",
				words: 6,
				separator: "-",
				capitalize: false,
				appendNumber: false,
			}),
		);
	});

	it("switches to PIN mode and sends the pin length", async () => {
		const { GeneratorScreen } = await import("../GeneratorScreen");
		render(<GeneratorScreen />);

		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(1));
		fireEvent.click(screen.getByRole("tab", { name: "PIN" }));

		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(2));
		expect(generatePassword).toHaveBeenLastCalledWith(
			expect.objectContaining({ mode: "pin", length: 6 }),
		);
	});

	it("respects passphrase option edits on the next generation", async () => {
		const { GeneratorScreen } = await import("../GeneratorScreen");
		render(<GeneratorScreen />);
		fireEvent.click(screen.getByRole("tab", { name: "Passphrase" }));
		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(2));

		// Option edits alone do NOT auto-regenerate (same discipline as the
		// password-mode checkboxes) — the explicit Generate button does.
		fireEvent.change(screen.getByLabelText("Passphrase word count"), {
			target: { value: "9" },
		});
		fireEvent.change(screen.getByLabelText("Separator"), {
			target: { value: "." },
		});
		fireEvent.click(screen.getByLabelText("Append number (0-99)"));
		expect(generatePassword).toHaveBeenCalledTimes(2);

		fireEvent.click(
			screen.getByRole("button", { name: "Generate New Password" }),
		);
		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(3));
		expect(generatePassword).toHaveBeenLastCalledWith(
			expect.objectContaining({
				mode: "passphrase",
				words: 9,
				separator: ".",
				appendNumber: true,
			}),
		);
	});

	it("keeps a session history of the last generations and copies on click", async () => {
		generatePassword.mockImplementation(async (options) =>
			options.mode === "passphrase"
				? "correct horse battery"
				: "generated-value",
		);
		const { GeneratorScreen } = await import("../GeneratorScreen");
		const { copyWithTimeout } = await import("../../utils/clipboard");
		render(<GeneratorScreen />);

		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(1));
		fireEvent.click(screen.getByRole("tab", { name: "Passphrase" }));
		await waitFor(() => expect(generatePassword).toHaveBeenCalledTimes(2));

		const history = screen.getByText("Session history");
		expect(history).toBeTruthy();
		// Both generated values are listed in the history scope (the preview
		// shows the latest value too, so scope the queries).
		const historyList = history.closest(".generator-history") as HTMLElement;
		expect(historyList.textContent).toContain("correct horse battery");
		expect(historyList.textContent).toContain("generated-value");

		// Clicking a history entry copies it.
		fireEvent.click(historyList.querySelector(".history-item")!);
		await waitFor(() =>
			expect(copyWithTimeout).toHaveBeenCalledWith("correct horse battery"),
		);
	});
});
