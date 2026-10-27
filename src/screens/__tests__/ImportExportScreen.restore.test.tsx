import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { VaultBackup } from "../../types";

// v1.6.2 (F2/F3): the restore confirmation dialog — the exact-match hint
// while the typed word is wrong (answers "why is this button disabled?"),
// and the advisory cloud-sync warning shown while the dialog is open. The
// api module is mocked; contexts follow the established screen-test pattern
// (csv.test). jsdom sees no CSS — the disabled-button dimming is device QA.

const syncStatus = vi.fn();
const readBackupFile = vi.fn();

vi.mock("../../api/vault", () => ({
	exportVaultFile: vi.fn().mockResolvedValue(null),
	readBackupFile: (...args: unknown[]) => readBackupFile(...args),
	importCsvOpen: vi.fn(),
	importCsvOpenBytes: vi.fn(),
	importCsvCommit: vi.fn(),
	syncStatus: (...args: unknown[]) => syncStatus(...args),
}));

const authActions = { navigate: vi.fn() };

const vaultActions = {
	exportVault: vi.fn().mockResolvedValue({}),
	importVault: vi
		.fn()
		.mockResolvedValue({ entries_imported: 1, groups_imported: 1 }),
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

beforeEach(() => {
	vi.clearAllMocks();
	// Default probe answer so the dialog's advisory effect never crashes;
	// individual tests override with mockResolvedValueOnce/mockRejectedValueOnce.
	syncStatus.mockResolvedValue({ enabled: false });
	(window as unknown as { __TAURI_INTERNALS__?: object }).__TAURI_INTERNALS__ =
		{};
});

import { ImportExportScreen } from "../ImportExportScreen";

const BACKUP: VaultBackup = {
	version: 2,
	created_at: 0,
	magic: "PWDVAULT",
	kdf_name: "argon2id",
	cipher_name: "aes-256-gcm",
	salt: "c2FsdA==",
	kdf_memory: 65536,
	kdf_iterations: 3,
	kdf_parallelism: 2,
	nonce: "bm9uY2U=",
	data: "ZGF0YQ==",
};

async function openRestoreDialog() {
	readBackupFile.mockResolvedValueOnce(BACKUP);
	render(<ImportExportScreen />);
	fireEvent.click(screen.getByText("Select Backup File"));
	await screen.findByText("Selected backup");
	fireEvent.change(screen.getByLabelText("Backup password"), {
		target: { value: "backup-password-1" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Restore Backup" }));
	// The dialog is open once the advisory probe has been issued.
	await waitFor(() => expect(syncStatus).toHaveBeenCalled());
}

describe("ImportExportScreen restore dialog", () => {
	it("keeps Restore disabled with no hint while the confirmation is empty", async () => {
		await openRestoreDialog();

		expect(screen.getByRole("button", { name: "Restore" })).toBeDisabled();
		expect(screen.queryByText(/Type exactly RESTORE to continue/)).toBeNull();
	});

	it("shows the exact-match hint while the typed word is wrong and keeps Restore disabled", async () => {
		await openRestoreDialog();

		fireEvent.change(screen.getByLabelText("Type RESTORE to continue"), {
			target: { value: "RESTOR" },
		});

		expect(screen.getByText(/Type exactly RESTORE to continue/)).toBeTruthy();
		expect(screen.getByRole("button", { name: "Restore" })).toBeDisabled();
	});

	it("hides the hint and enables Restore once the word matches exactly", async () => {
		await openRestoreDialog();

		const input = screen.getByLabelText("Type RESTORE to continue");
		fireEvent.change(input, { target: { value: "RESTOR" } });
		fireEvent.change(input, { target: { value: "RESTORE" } });

		expect(screen.queryByText(/Type exactly RESTORE to continue/)).toBeNull();
		expect(screen.getByRole("button", { name: "Restore" })).toBeEnabled();
	});

	it("warns about merge semantics while cloud sync is enabled", async () => {
		syncStatus.mockResolvedValueOnce({ enabled: true });
		await openRestoreDialog();

		const warning = await screen.findByText(/Cloud sync is active/);
		expect(warning.textContent).toContain(
			"merges both sides by timestamp (newer wins)",
		);
		expect(warning.textContent).toContain("stay deleted once their deletion has synced");
	});

	it("omits the sync warning when sync is disabled", async () => {
		syncStatus.mockResolvedValueOnce({ enabled: false });
		await openRestoreDialog();

		await waitFor(() => expect(syncStatus).toHaveBeenCalledTimes(1));
		expect(screen.queryByText(/Cloud sync is active/)).toBeNull();
	});

	it("renders the dialog unchanged when the sync probe fails (advisory-only)", async () => {
		syncStatus.mockRejectedValueOnce(new Error("probe failed"));
		await openRestoreDialog();

		expect(screen.queryByText(/Cloud sync is active/)).toBeNull();
		expect(screen.getByRole("button", { name: "Restore" })).toBeTruthy();
		expect(
			screen.getByText(/This will replace all current vault data/),
		).toBeTruthy();
	});
});
