import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";

const initialize = vi.fn();

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({
		state: { isLoading: false, error: null },
		actions: { initialize },
	}),
}));

beforeEach(() => {
	vi.clearAllMocks();
});

async function renderScreen() {
	const { SetupScreen } = await import("../SetupScreen");
	return render(<SetupScreen />);
}

describe("SetupScreen", () => {
	it("renders the auth shell with both password fields", async () => {
		await renderScreen();

		expect(screen.getByText("PwdVault")).toBeInTheDocument();
		expect(screen.getByText("Create your master password")).toBeInTheDocument();
		expect(screen.getByLabelText("Master password")).toBeInTheDocument();
		expect(screen.getByLabelText("Confirm Password")).toBeInTheDocument();
		expect(
			screen.getByRole("button", { name: "Create Vault" }),
		).toBeInTheDocument();
	});

	it("calls initialize with the entered password on submit", async () => {
		initialize.mockResolvedValue(true);
		await renderScreen();

		fireEvent.change(screen.getByLabelText("Master password"), {
			target: { value: "correct horse battery" },
		});
		fireEvent.change(screen.getByLabelText("Confirm Password"), {
			target: { value: "correct horse battery" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create Vault" }));

		await waitFor(() =>
			expect(initialize).toHaveBeenCalledWith("correct horse battery"),
		);
	});

	it("shows a local error and skips the backend call when passwords differ", async () => {
		await renderScreen();

		fireEvent.change(screen.getByLabelText("Master password"), {
			target: { value: "password-one" },
		});
		fireEvent.change(screen.getByLabelText("Confirm Password"), {
			target: { value: "password-two" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create Vault" }));

		expect(
			await screen.findByText("Passwords do not match"),
		).toBeInTheDocument();
		expect(initialize).not.toHaveBeenCalled();
	});
});
