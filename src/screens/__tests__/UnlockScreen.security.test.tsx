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

	it("shows the no-recovery-key warning when recovery is not enabled", async () => {
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		expect(await screen.findByText(/No recovery key set up/)).toBeInTheDocument();
		expect(screen.queryByText("Recovery key enabled")).not.toBeInTheDocument();
	});

	it("shows the enabled confirmation instead of the warning when recovery is enabled", async () => {
		recoveryStatus.mockResolvedValue(true);
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		expect(await screen.findByText("Recovery key enabled")).toBeInTheDocument();
		expect(screen.queryByText(/No recovery key set up/)).not.toBeInTheDocument();
		expect(screen.getByText("Forgot password?")).toBeInTheDocument();
	});

	it("renders no recovery hint at all when the probe fails (never assert an unverified fact)", async () => {
		recoveryStatus.mockRejectedValue(new Error("transport down"));
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		// Give the effect a tick to settle into its rejection path.
		await waitFor(() => expect(recoveryStatus).toHaveBeenCalled());
		expect(screen.queryByText(/No recovery key set up/)).not.toBeInTheDocument();
		expect(screen.queryByText("Recovery key enabled")).not.toBeInTheDocument();
		expect(screen.queryByText("Forgot password?")).not.toBeInTheDocument();
	});

	it("toggles password visibility with the show/hide eye button", async () => {
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		const input = await screen.findByLabelText("Master password");
		expect(input).toHaveAttribute("type", "password");

		fireEvent.click(screen.getByRole("button", { name: "Show password" }));
		expect(screen.getByLabelText("Master password")).toHaveAttribute("type", "text");
		expect(screen.getByRole("button", { name: "Hide password" })).toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: "Hide password" }));
		expect(screen.getByLabelText("Master password")).toHaveAttribute("type", "password");
	});

	it("surfaces the local error when the unlock call rejects", async () => {
		unlock.mockRejectedValue(new Error("transport down"));
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		fireEvent.change(await screen.findByLabelText("Master password"), {
			target: { value: "master-pw" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Unlock" }));

		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Failed to unlock vault",
		);
	});
});
