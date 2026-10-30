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

// v1.8.2 focus gate: UnlockScreen probes isFocused and subscribes to
// onFocusChanged on the current Tauri window.
const windowMock = {
	isFocused: vi.fn(),
	onFocusChanged: vi.fn(),
};

vi.mock("@tauri-apps/api/window", () => ({
	getCurrentWindow: () => windowMock,
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
	// v1.8.2 focus-gate defaults (set UNCONDITIONALLY — clearAllMocks keeps
	// implementations, so ordering does not matter; what matters is that the
	// first run and post-case resets always see these): "focused" mirrors
	// today's behavior so the pre-existing cases stay green — without these
	// the mock returns undefined, the four-way gate never opens, and the
	// first existing case goes red.
	windowMock.isFocused.mockResolvedValue(true);
	windowMock.onFocusChanged.mockResolvedValue(() => {});
	harnessActions = null;
	setupVault.mockResolvedValue(true);
	biometricStatus.mockResolvedValue({ available: true, enabled: true });
	recoveryStatus.mockResolvedValue(false);
	// Default: a RESOLVING attempt — the action ignores the resolved value,
	// so this exercises the success path (v1.8.1 review: the old comment
	// wrongly called it a dismissed prompt).
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

	it("gates the auto-prompt on window focus across remounts (v1.8.2)", async () => {
		windowMock.isFocused.mockResolvedValue(false);
		let captured: ((event: { payload: boolean }) => void) | null = null;
		windowMock.onFocusChanged.mockImplementation(async (handler) => {
			captured = handler;
			return () => {};
		});
		render(
			<AuthProvider>
				<Harness />
			</AuthProvider>,
		);

		// Unfocused boot: probe settles, episode flag is clear, but the focus
		// gate keeps the prompt silent.
		await waitFor(() => expect(biometricStatus).toHaveBeenCalledTimes(1));
		await act(async () => {}); // let the focus probe settle (isFocused=false)
		expect(unlockBiometric).not.toHaveBeenCalled();

		// Loading-cycle remount: the fresh mount re-subscribes and re-probes —
		// wait for the NEW subscription before firing, or the handler invoked
		// is the cleaned-up old one whose cancelled guard silently drops the
		// event (false red).
		toggleScreen();
		toggleScreen();
		await waitFor(() =>
			expect(windowMock.onFocusChanged).toHaveBeenCalledTimes(2),
		);
		await waitFor(() => expect(biometricStatus).toHaveBeenCalledTimes(2));
		await act(async () => {}); // let the remount's subscription settle
		expect(unlockBiometric).not.toHaveBeenCalled();

		// Focus arrives on the CURRENT subscription → exactly one attempt.
		await act(async () => {
			await captured?.({ payload: true });
		});
		await waitFor(() => expect(unlockBiometric).toHaveBeenCalledTimes(1));

		// Blur + refocus in the same episode → the flag holds at one.
		await act(async () => {
			await captured?.({ payload: false });
		});
		await act(async () => {
			await captured?.({ payload: true });
		});
		expect(unlockBiometric).toHaveBeenCalledTimes(1);
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
		// Flush passive effects so authStateRef is current before the manual
		// call — RTL's MutationObserver can release waitFor in the same macro
		// task as the commit, BEFORE the ref-sync effect runs (v1.8.2: this
		// flaked twice under a cold cache; the guard would then read a stale
		// isUnlocked=false and surface the error).
		await act(async () => {});

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

	it("keeps the real-wire cancellation silent (public_message shape, v1.8.1)", async () => {
		unlockBiometric.mockRejectedValue("Touch ID was cancelled");
		render(
			<AuthProvider>
				<Harness />
			</AuthProvider>,
		);

		await waitFor(() => expect(unlockBiometric).toHaveBeenCalledTimes(1));
		// Flush the rejection through the catch before asserting absence —
		// an early synchronous poll would pass vacuously (review P3).
		await act(async () => {});
		expect(screen.getByTestId("auth-error")).toHaveTextContent("");
		expect(unlockBiometric).toHaveBeenCalledTimes(1); // flag: no re-prompt
	});
});
