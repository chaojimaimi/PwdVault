import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";

const unlock = vi.fn();
const unlockBiometric = vi.fn();
const navigate = vi.fn();
// v1.8.0: mutable auth-state mock shared by reference. biometricAutoPrompted
// defaults to TRUE so every pre-existing case keeps its no-auto-fire
// behavior; the auto-prompt cases below flip it explicitly. The actions
// object is a stable reference — the auto-prompt effect lists `actions` in
// its deps, and a per-render literal would re-trigger it every render.
const mockState = {
	isLoading: false,
	error: null as string | null,
	biometricAutoPrompted: true,
};
const mockActions = { unlock, unlockBiometric, navigate };

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({
		state: mockState,
		actions: mockActions,
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
	// clearAllMocks keeps mockImplementation — reset it too, so the flag-
	// flipping implementation set by the auto-prompt case cannot leak into
	// later cases (review P3-1).
	unlockBiometric.mockReset();
	unlockBiometric.mockResolvedValue(false);
	mockState.isLoading = false;
	mockState.error = null;
	mockState.biometricAutoPrompted = true;
	biometricStatus.mockResolvedValue({ available: false, enabled: false });
	recoveryStatus.mockResolvedValue(false);
});

describe("UnlockScreen security affordances", () => {
	it("shows the Touch ID button only when biometry is available and enabled", async () => {
		biometricStatus.mockResolvedValue({ available: true, enabled: true });
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		expect(
			await screen.findByRole("button", { name: "Use Touch ID" }),
		).toBeInTheDocument();
		expect(screen.queryByText("Forgot password?")).not.toBeInTheDocument();
	});

	it("hides the Touch ID button when biometry is unavailable", async () => {
		biometricStatus.mockResolvedValue({ available: false, enabled: true });
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		await waitFor(() => expect(biometricStatus).toHaveBeenCalled());
		expect(
			screen.queryByRole("button", { name: "Use Touch ID" }),
		).not.toBeInTheDocument();
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

		fireEvent.click(
			await screen.findByRole("button", { name: "Use Touch ID" }),
		);

		await waitFor(() => expect(unlockBiometric).toHaveBeenCalled());
		expect(screen.queryByRole("alert")).not.toBeInTheDocument();
		expect(navigate).not.toHaveBeenCalled();
	});

	it("auto-prompts Touch ID exactly once on a fresh lock episode", async () => {
		biometricStatus.mockResolvedValue({ available: true, enabled: true });
		// Mimic the real context: the attempt marks the episode flag on entry.
		unlockBiometric.mockImplementation(() => {
			mockState.biometricAutoPrompted = true;
			return Promise.resolve(false); // cancelled: silent
		});
		mockState.biometricAutoPrompted = false;
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		await waitFor(() => expect(unlockBiometric).toHaveBeenCalledTimes(1));
		expect(screen.queryByRole("alert")).not.toBeInTheDocument();
		expect(navigate).not.toHaveBeenCalled();
	});

	it("does not auto-prompt when biometry is unavailable or disabled", async () => {
		biometricStatus.mockResolvedValue({ available: false, enabled: false });
		mockState.biometricAutoPrompted = false;
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		await waitFor(() => expect(biometricStatus).toHaveBeenCalled());
		expect(unlockBiometric).not.toHaveBeenCalled();
	});

	it("does not auto-prompt when this episode already had a biometric attempt", async () => {
		biometricStatus.mockResolvedValue({ available: true, enabled: true });
		mockState.biometricAutoPrompted = true;
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		// Manual path must still work — only the auto-fire is gated.
		expect(
			await screen.findByRole("button", { name: "Use Touch ID" }),
		).toBeInTheDocument();
		expect(unlockBiometric).not.toHaveBeenCalled();
	});

	it("shows the no-recovery-key warning when recovery is not enabled", async () => {
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		expect(
			await screen.findByText(/No recovery key set up/),
		).toBeInTheDocument();
		expect(screen.queryByText("Recovery key enabled")).not.toBeInTheDocument();
	});

	it("shows the enabled confirmation instead of the warning when recovery is enabled", async () => {
		recoveryStatus.mockResolvedValue(true);
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		expect(await screen.findByText("Recovery key enabled")).toBeInTheDocument();
		expect(
			screen.queryByText(/No recovery key set up/),
		).not.toBeInTheDocument();
		expect(screen.getByText("Forgot password?")).toBeInTheDocument();
	});

	it("renders no recovery hint at all when the probe fails (never assert an unverified fact)", async () => {
		recoveryStatus.mockRejectedValue(new Error("transport down"));
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		// Give the effect a tick to settle into its rejection path.
		await waitFor(() => expect(recoveryStatus).toHaveBeenCalled());
		expect(
			screen.queryByText(/No recovery key set up/),
		).not.toBeInTheDocument();
		expect(screen.queryByText("Recovery key enabled")).not.toBeInTheDocument();
		expect(screen.queryByText("Forgot password?")).not.toBeInTheDocument();
	});

	it("toggles password visibility with the show/hide eye button", async () => {
		const { UnlockScreen } = await import("../UnlockScreen");
		render(<UnlockScreen />);

		const input = await screen.findByLabelText("Master password");
		expect(input).toHaveAttribute("type", "password");

		fireEvent.click(screen.getByRole("button", { name: "Show password" }));
		expect(screen.getByLabelText("Master password")).toHaveAttribute(
			"type",
			"text",
		);
		expect(
			screen.getByRole("button", { name: "Hide password" }),
		).toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: "Hide password" }));
		expect(screen.getByLabelText("Master password")).toHaveAttribute(
			"type",
			"password",
		);
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
