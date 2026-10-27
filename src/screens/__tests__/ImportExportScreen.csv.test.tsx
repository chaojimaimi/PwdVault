import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { CsvImportPreview } from "../../types";

// v1.5.0 (WP2): the CSV import section on the ImportExportScreen — preset
// recognition failure display, preview table rendering (no password values),
// and the commit call. The api module is mocked; contexts follow the
// established screen-test pattern.

const importCsvOpen = vi.fn();
const importCsvOpenBytes = vi.fn();
const importCsvCommit = vi.fn();

vi.mock("../../api/vault", () => ({
	exportVaultFile: vi.fn().mockResolvedValue(null),
	readBackupFile: vi.fn().mockResolvedValue(null),
	// v1.6.2: the restore dialog probes sync state on open. These tests never
	// open that dialog, but the factory must carry the export anyway — a
	// missing entry would fail with the opaque vitest mock error if a future
	// case ever opens it.
	syncStatus: vi.fn().mockResolvedValue({ enabled: false }),
	importCsvOpen: (...args: unknown[]) => importCsvOpen(...args),
	importCsvOpenBytes: (...args: unknown[]) => importCsvOpenBytes(...args),
	importCsvCommit: (...args: unknown[]) => importCsvCommit(...args),
}));

const authActions = { navigate: vi.fn() };

const vaultActions = {
	exportVault: vi.fn().mockResolvedValue({}),
	importVault: vi
		.fn()
		.mockResolvedValue({ entries_imported: 0, groups_imported: 0 }),
};

vi.mock("../../context/AppContext", () => ({
	useAuth: () => ({
		state: { isUnlocked: true, isLoading: false, bootError: null },
		actions: authActions,
	}),
	useVault: () => ({ state: {}, actions: vaultActions }),
}));

vi.mock("../../components/AccessibleDialog", () => ({
	AccessibleDialog: ({ children }: { children?: React.ReactNode }) => (
		<>{children}</>
	),
}));

vi.mock("../../utils/toast", () => ({ showToast: vi.fn() }));

// The screen branches on its local isTauriEnvironment — pretend to be the
// desktop app so the select goes through the native-dialog command path.
beforeEach(() => {
	vi.clearAllMocks();
	(window as unknown as { __TAURI_INTERNALS__?: object }).__TAURI_INTERNALS__ =
		{};
});

import { ImportExportScreen } from "../ImportExportScreen";

const PREVIEW: CsvImportPreview = {
	preset: "Bitwarden",
	total_rows: 4,
	skipped_rows: 1,
	duplicate_candidates: 2,
	rows: [
		{
			title: "Site A",
			username: "a@x.com",
			url: "https://a.example.com",
			group: "Web",
			has_password: true,
			has_notes: false,
			has_totp: false,
		},
		{
			title: "Site B",
			username: "b@x.com",
			url: null,
			group: null,
			has_password: false,
			has_notes: true,
			has_totp: true,
		},
	],
};

function openCsvSection() {
	render(<ImportExportScreen />);
	const button = screen.getByText("Select CSV File");
	fireEvent.click(button);
	return button;
}

describe("ImportExportScreen CSV import section", () => {
	it("renders the preview table without password values", async () => {
		importCsvOpen.mockResolvedValueOnce(PREVIEW);
		openCsvSection();

		expect(await screen.findByText(/Recognized as/)).toBeTruthy();
		expect(screen.getByText("Bitwarden")).toBeTruthy();
		expect(screen.getByText(/2 of 4 rows will import/)).toBeTruthy();
		expect(screen.getByText(/1 skipped as invalid/)).toBeTruthy();
		// Duplicate statistic wording ("imported as new entries" semantics).
		expect(screen.getByText(/About 2 rows look like duplicates/)).toBeTruthy();
		// Table rows carry metadata, never a password column value.
		expect(screen.getByText("Site A")).toBeTruthy();
		expect(screen.getByText("a@x.com")).toBeTruthy();
		expect(screen.getByText("Web")).toBeTruthy();
		expect(screen.getByText("Yes")).toBeTruthy();
		expect(screen.getByText("Missing")).toBeTruthy();
	});

	it("shows the recognition failure inline with the preset expectations", async () => {
		importCsvOpen.mockRejectedValueOnce(
			new Error(
				"Could not recognize the CSV layout. Supported exports: Bitwarden, 1Password, Chrome, KeePassXC",
			),
		);
		openCsvSection();

		const alert = await screen.findByRole("alert");
		expect(alert.textContent).toContain("Could not recognize the CSV layout");
		// No preview and no commit button appear on failure.
		expect(screen.queryByText(/rows will import/)).toBeNull();
	});

	it("ignores a cancelled native dialog", async () => {
		importCsvOpen.mockResolvedValueOnce(null);
		openCsvSection();

		await waitFor(() => expect(importCsvOpen).toHaveBeenCalledTimes(1));
		expect(screen.queryByText(/rows will import/)).toBeNull();
	});

	it("commits the staged import and reports the result", async () => {
		const { showToast } = await import("../../utils/toast");
		importCsvOpen.mockResolvedValueOnce(PREVIEW);
		importCsvCommit.mockResolvedValueOnce({
			created_entries: 2,
			created_groups: 1,
			skipped_rows: 1,
		});
		openCsvSection();

		const importButton = await screen.findByText("Import 2 Entries");
		fireEvent.click(importButton);

		await waitFor(() => expect(importCsvCommit).toHaveBeenCalledTimes(1));
		expect(showToast).toHaveBeenCalledWith(
			"Imported 2 entries from Bitwarden (1 new group, 1 row skipped)",
		);
		// The preview is cleared after a successful commit.
		await waitFor(() =>
			expect(screen.queryByText(/rows will import/)).toBeNull(),
		);
	});

	it("clears the preview when the commit fails (staging is consumed)", async () => {
		const { showToast } = await import("../../utils/toast");
		importCsvOpen.mockResolvedValueOnce(PREVIEW);
		importCsvCommit.mockRejectedValueOnce(new Error("disk full"));
		openCsvSection();

		const importButton = await screen.findByText("Import 2 Entries");
		fireEvent.click(importButton);

		await waitFor(() => expect(showToast).toHaveBeenCalledWith("disk full"));
		// The backend consumed the staging on the failed commit too, so keeping
		// the preview would let a retry fail with a misleading "pick a file".
		await waitFor(() =>
			expect(screen.queryByText(/rows will import/)).toBeNull(),
		);
		expect(screen.queryByText("Import 2 Entries")).toBeNull();
	});
});
