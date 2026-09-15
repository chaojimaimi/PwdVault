import React from "react";
import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";

const recover = vi.fn();
const navigate = vi.fn();

let authError: string | null = null;

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({
		state: { isLoading: false, error: authError },
		actions: { recover, navigate },
	}),
}));

beforeEach(() => {
	vi.clearAllMocks();
	authError = null;
});

async function renderScreen() {
	const { RecoveryScreen } = await import("../RecoveryScreen");
	return render(<RecoveryScreen />);
}

describe("RecoveryScreen", () => {
	it("calls recover with the trimmed key and new password on submit", async () => {
		recover.mockResolvedValue(true);
		await renderScreen();

		fireEvent.change(screen.getByLabelText("Recovery Key"), {
			target: { value: "  key-abc-123  " },
		});
		fireEvent.change(screen.getByLabelText("New Master Password"), {
			target: { value: "new master password" },
		});
		fireEvent.change(screen.getByLabelText("Confirm New Password"), {
			target: { value: "new master password" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Recover Vault" }));

		await waitFor(() =>
			expect(recover).toHaveBeenCalledWith("key-abc-123", "new master password"),
		);
	});

	it("shows a local error and skips the backend call when passwords differ", async () => {
		await renderScreen();

		fireEvent.change(screen.getByLabelText("Recovery Key"), {
			target: { value: "key-abc-123" },
		});
		fireEvent.change(screen.getByLabelText("New Master Password"), {
			target: { value: "password-one" },
		});
		fireEvent.change(screen.getByLabelText("Confirm New Password"), {
			target: { value: "password-two" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Recover Vault" }));

		expect(
			await screen.findByText("Passwords do not match"),
		).toBeInTheDocument();
		expect(recover).not.toHaveBeenCalled();
	});

	it("surfaces the backend error when recovery fails", async () => {
		authError = "Recovery key is invalid. Check the saved key and try again";
		await renderScreen();

		expect(
			await screen.findByText(/Recovery key is invalid/),
		).toBeInTheDocument();
	});

	it("navigates back to the unlock screen", async () => {
		await renderScreen();

		fireEvent.click(screen.getByText("Back to unlock"));
		expect(navigate).toHaveBeenCalledWith("unlock");
	});
});
