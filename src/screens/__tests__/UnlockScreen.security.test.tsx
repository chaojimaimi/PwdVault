import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";

const unlock = vi.fn();
const unlockBiometric = vi.fn();
const navigate = vi.fn();

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({
		state: { isLoading: false, error: null },
		actions: { unlock, unlockBiometric, navigate },
	}),
}));

const biometricStatus = vi.fn();
const recoveryStatus = vi.fn();

vi.mock("../../api/vault", () => ({
	biometricStatus: (...args: unknown[]) => biometricStatus(...args),
	recoveryStatus: (...args: unknown[]) => recoveryStatus(...args),
}));

beforeEach(() => {
	vi.clearAllMocks();
	biometricStatus.mockResolvedValue({ available: false, enabled: false });
	recoveryStatus.mockResolvedValue(false);
});

describe("UnlockScreen security affordances", () => {
	it("shows the Touch ID button only when biometry is available and enabled", async () => {
		biometricStatus.mockResolvedValue({ available: true, enabled: true });
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		expect(await screen.findByRole("button", { name: "Use Touch ID" })).toBeInTheDocument();
		expect(screen.queryByText("Forgot password?")).not.toBeInTheDocument();
	});

	it("hides the Touch ID button when biometry is unavailable", async () => {
		biometricStatus.mockResolvedValue({ available: false, enabled: true });
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		await waitFor(() => expect(biometricStatus).toHaveBeenCalled());
		expect(screen.queryByRole("button", { name: "Use Touch ID" })).not.toBeInTheDocument();
	});

	it("shows the recovery link only when recovery is enabled", async () => {
		recoveryStatus.mockResolvedValue(true);
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		expect(await screen.findByText("Forgot password?")).toBeInTheDocument();
	});

	it("navigates to the recovery screen from the forgot-password link", async () => {
		recoveryStatus.mockResolvedValue(true);
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		fireEvent.click(await screen.findByText("Forgot password?"));
		expect(navigate).toHaveBeenCalledWith("recovery");
	});

	it("calls unlockBiometric and stays silent on a cancelled prompt", async () => {
		biometricStatus.mockResolvedValue({ available: true, enabled: true });
		unlockBiometric.mockResolvedValue(false); // cancelled: no error surfaced
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		fireEvent.click(await screen.findByRole("button", { name: "Use Touch ID" }));

		await waitFor(() => expect(unlockBiometric).toHaveBeenCalled());
		expect(screen.queryByRole("alert")).not.toBeInTheDocument();
		expect(navigate).not.toHaveBeenCalled();
	});
});
