import { render, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	VaultProvider,
	useVault,
	type VaultContextValue,
} from "../VaultContext";
import * as api from "../../api/vault";
import type { EntrySummary } from "../../types";
import { showToast } from "../../utils/toast";

// v1.8.4 (P2-3): restoreEntry used to swallow a failed post-restore list
// refresh (`.catch(() => {})`) and let a loadDeletedEntries failure mask the
// successful restore by rejecting. The refreshed-flag pattern
// (SyncSettingsSection.handleSyncNow precedent) now toasts on any refresh
// failure while restoreEntry still resolves — and restore failures
// themselves keep propagating to the caller. Provider-harness structure
// follows SettingsContext.test.tsx.

vi.mock("../AuthContext", () => ({
	useAuth: () => ({ state: { isUnlocked: true } }),
}));

vi.mock("../../api/vault", () => ({
	restoreEntry: vi.fn(),
	listAllEntries: vi.fn(),
	listDeletedEntries: vi.fn(),
}));

vi.mock("../../utils/toast", () => ({ showToast: vi.fn() }));

let latestCtx: VaultContextValue | null = null;

function Probe() {
	const ctx = useVault();
	latestCtx = ctx;
	return null;
}

function renderProvider() {
	render(
		<VaultProvider>
			<Probe />
		</VaultProvider>,
	);
}

describe("VaultContext restoreEntry refresh visibility (v1.8.4 P2-3)", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		latestCtx = null;
	});

	it("toasts and still resolves when the post-restore refresh fails", async () => {
		vi.mocked(api.restoreEntry).mockResolvedValue({} as EntrySummary);
		// The live-list reload rejects; the trash reload succeeds. Either
		// failure must toast — neither may reject restoreEntry.
		vi.mocked(api.listAllEntries).mockRejectedValue(new Error("db busy"));
		vi.mocked(api.listDeletedEntries).mockResolvedValue([]);

		renderProvider();

		await expect(
			latestCtx!.actions.restoreEntry("entry-1"),
		).resolves.toBeUndefined();
		expect(vi.mocked(api.restoreEntry)).toHaveBeenCalledWith("entry-1");
		expect(vi.mocked(showToast)).toHaveBeenCalledWith(
			"Restored, but refreshing the list failed",
		);
	});

	it("keeps propagating a restore failure to the caller (no toast)", async () => {
		vi.mocked(api.restoreEntry).mockRejectedValue(
			new Error("restore rejected"),
		);

		renderProvider();

		await expect(latestCtx!.actions.restoreEntry("entry-1")).rejects.toThrow(
			"restore rejected",
		);
		// The refresh path never ran — the failure belongs to the caller's
		// existing error channel, not the refresh toast.
		expect(vi.mocked(showToast)).not.toHaveBeenCalled();
	});
});

// v1.8.4 (P3-7, review fold): the trash error payload must survive the
// context→reducer chain. The VaultScreen-level test injects state directly
// into the useVault holder, so only this level proves the dispatch actually
// carries the failure reason instead of dropping it at the action boundary.
describe("VaultContext loadDeletedEntries error payload (v1.8.4 P3-7)", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		latestCtx = null;
	});

	it("carries the failure reason into deletedError", async () => {
		vi.mocked(api.listAllEntries).mockResolvedValue([]);
		vi.mocked(api.listDeletedEntries).mockRejectedValue(new Error("db down"));

		renderProvider();

		await expect(latestCtx!.actions.loadDeletedEntries()).rejects.toThrow(
			"db down",
		);
		// The dispatch lands just before the throw — the probe's context
		// object is swapped on the NEXT React commit, so wait for it instead
		// of asserting against the pre-dispatch snapshot.
		await waitFor(() => expect(latestCtx!.state.deletedStatus).toBe("error"));
		expect(latestCtx!.state.deletedError).toBe("db down");
	});
});
