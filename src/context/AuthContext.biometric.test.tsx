import { useState } from "react";
import {
	render,
	screen,
	fireEvent,
	waitFor,
	act,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider, useAuth } from "./AuthContext";
import { UnlockScreen } from "../screens/UnlockScreen";

// v1.8.0 lifecycle contract: ONE biometric attempt per lock episode. The flag
// lives in AuthContext — NOT in a screen ref — because every attempt swaps the
// auth screen tree for the Loading screen and unmounts UnlockScreen, so this
// harness mounts and remounts UnlockScreen INSIDE one AuthProvider to pin
// exactly that: the pre-fix (component ref) design fails at the second mount.

const setupVault = vi.fn();
const biometricStatus = vi.fn();
const recoveryStatus = vi.fn();
const unlockBiometric = vi.fn();
const lockVault = vi.fn();

vi.mock("../api/vault", () => ({
	setupVault: (...args: unknown[]) => setupVault(...args),
	unlockBiometric: (...args: unknown[]) => unlockBiometric(...args),
	biometricStatus: (...args: unknown[]) => biometricStatus(...args),
	recoveryStatus: (...args: unknown[]) => recoveryStatus(...args),
	lockVault: (...args: unknown[]) => lockVault(...args),
}));

let harnessActions: ReturnType<typeof useAuth>["actions"] | null = null;

function Harness() {
	const { state, actions } = useAuth();
	harnessActions = actions;
	// The toggle simulates the real topology's Loading-screen unmount/remount
	// of the auth tree WITHOUT discarding the provider (where the flag lives).
	const [show, setShow] = useState(true);
	return (
		<div>
			<span data-testid="auth-error">{state.error ?? ""}</span>
			<span data-testid="auth-unlocked">{String(state.isUnlocked)}</span>
			<button type="button" onClick={() => setShow((s) => !s)}>
				toggle-screen
			</button>
			{show && <UnlockScreen />}
		</div>
	);
}

function toggleScreen() {
	fireEvent.click(screen.getByRole("button", { name: "toggle-screen" }));
}

beforeEach(() => {
	vi.clearAllMocks();
	harnessActions = null;
	setupVault.mockResolvedValue(true);
	biometricStatus.mockResolvedValue({ available: true, enabled: true });
	recoveryStatus.mockResolvedValue(false);
	// Default: a dismissed prompt (no navigation, no error).
	unlockBiometric.mockResolvedValue(false);
	lockVault.mockResolvedValue(undefined);
});

describe("biometric auto-prompt lifecycle (one attempt per lock episode)", () => {
	it("auto-prompts once per episode across remounts; lock RESET re-arms", async () => {
		render(
			<AuthProvider>
				<Harness />
			</AuthProvider>,
		);

		// Mount 1: boot settles → probe settles → exactly one auto attempt.
		await waitFor(() => expect(unlockBiometric).toHaveBeenCalledTimes(1));

		// Unmount + remount inside the SAME provider (the Loading-screen cycle).
		// The fresh mount re-probes, but the episode flag gates the effect —
		// the pre-fix component-ref design would fire again here.
		toggleScreen();
		toggleScreen();
		await waitFor(() => expect(biometricStatus).toHaveBeenCalledTimes(2));
		expect(unlockBiometric).toHaveBeenCalledTimes(1);

		// Lock: RESET clears the flag → the next episode auto-prompts again.
		await act(async () => {
			await harnessActions?.lock();
		});
		toggleScreen();
		toggleScreen();
		await waitFor(() => expect(biometricStatus).toHaveBeenCalledTimes(3));
		await waitFor(() => expect(unlockBiometric).toHaveBeenCalledTimes(2));
	});

	it("keeps a late biometric failure silent once the vault is unlocked", async () => {
		// Defense-in-depth guard (plan §2): the Loading topology makes the
		// race unreachable today, but a late failure after another unlock path
		// must never pollute the global error banner.
		unlockBiometric
			.mockResolvedValueOnce(true) // first attempt unlocks the vault
			.mockRejectedValueOnce("Keychain unavailable"); // late stale failure
		render(
			<AuthProvider>
				<Harness />
			</AuthProvider>,
		);

		await waitFor(() =>
			expect(screen.getByTestId("auth-unlocked")).toHaveTextContent("true"),
		);

		await act(async () => {
			await harnessActions?.unlockBiometric();
		});
		expect(screen.getByTestId("auth-error")).toHaveTextContent("");
	});

	it("surfaces non-cancelled biometric failures while still locked", async () => {
		unlockBiometric.mockRejectedValue("Keychain unavailable");
		render(
			<AuthProvider>
				<Harness />
			</AuthProvider>,
		);

		await waitFor(() =>
			expect(screen.getByTestId("auth-error")).toHaveTextContent(
				"Keychain unavailable",
			),
		);
	});
});
