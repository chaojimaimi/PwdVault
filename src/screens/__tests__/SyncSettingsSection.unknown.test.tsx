import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const syncStatus = vi.fn();

vi.mock("../../api/vault", () => ({
	syncStatus: (...args: unknown[]) => syncStatus(...args),
}));

vi.mock("../../context/VaultContext", () => ({
	useVault: () => ({ actions: { loadEntries: vi.fn(), loadGroups: vi.fn() } }),
}));

const NOT_ENABLED = {
	enabled: false,
	backend: null,
	last_sync_at: null,
	last_result: null,
	remote_rev: null,
};

beforeEach(() => {
	vi.clearAllMocks();
});

async function renderSection() {
	const { SyncSettingsSection } = await import(
		"../../components/SyncSettingsSection"
	);
	return render(<SyncSettingsSection />);
}

// SF-P3f: the mount probe is three-valued — a failed first probe has no
// cached status to fall back on, so the section must show an explicit
// "unknown" state (with Retry) instead of silently pretending sync is off.
describe("SyncSettingsSection unknown status state", () => {
	it("enters the unknown state with a Retry button when the first probe fails", async () => {
		syncStatus.mockRejectedValueOnce(new Error("probe boom"));
		await renderSection();

		expect(await screen.findByText("Status unknown")).toBeInTheDocument();
		expect(
			screen.getByRole("button", { name: "Retry" }),
		).toBeInTheDocument();
		// The connect form stays hidden — acting on an unknown state would
		// be misleading.
		expect(screen.queryByLabelText("Backend")).not.toBeInTheDocument();
		expect(screen.queryByLabelText("Server URL")).not.toBeInTheDocument();
	});

	it("recovers into the connect form after a successful retry", async () => {
		syncStatus
			.mockRejectedValueOnce(new Error("probe boom"))
			.mockResolvedValue(NOT_ENABLED);
		await renderSection();

		fireEvent.click(await screen.findByRole("button", { name: "Retry" }));

		// Success path: the normal not-connected view (bootstrap form) shows
		// and the unknown-state affordances disappear.
		expect(
			await screen.findByLabelText("Server URL"),
		).toBeInTheDocument();
		expect(screen.queryByText("Status unknown")).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Retry" })).not
			.toBeInTheDocument();
	});
});
