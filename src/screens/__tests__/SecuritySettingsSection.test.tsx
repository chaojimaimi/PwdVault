import { render, fireEvent, screen, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";

const showToast = vi.fn();

vi.mock("../../utils/toast", () => ({ showToast }));
vi.mock("../../utils/clipboard", () => ({ copyWithTimeout: vi.fn() }));

const biometricStatus = vi.fn();
const recoveryStatus = vi.fn();
const changePassword = vi.fn();
const enableBiometric = vi.fn();
const disableBiometric = vi.fn();
const enableRecovery = vi.fn();
const disableRecovery = vi.fn();

vi.mock("../../api/vault", () => ({
	biometricStatus: (...args: unknown[]) => biometricStatus(...args),
	recoveryStatus: (...args: unknown[]) => recoveryStatus(...args),
	changePassword: (...args: unknown[]) => changePassword(...args),
	enableBiometric: (...args: unknown[]) => enableBiometric(...args),
	disableBiometric: (...args: unknown[]) => disableBiometric(...args),
	enableRecovery: (...args: unknown[]) => enableRecovery(...args),
	disableRecovery: (...args: unknown[]) => disableRecovery(...args),
}));

beforeEach(() => {
	vi.clearAllMocks();
	biometricStatus.mockResolvedValue({ available: false, enabled: false });
	recoveryStatus.mockResolvedValue(false);
});

async function renderSection() {
	const { SecuritySettingsSection } = await import(
		"../../components/SecuritySettingsSection"
	);
	return render(<SecuritySettingsSection />);
}

describe("SecuritySettingsSection conditional rendering", () => {
	it("hides the Touch ID block when biometry is unavailable", async () => {
		await renderSection();

		await waitFor(() => expect(biometricStatus).toHaveBeenCalled());
		expect(screen.queryByText("Touch ID")).not.toBeInTheDocument();
		// Recovery disabled: enable entry point present, no required key field.
		expect(
			await screen.findByRole("button", { name: "Enable Recovery Key" }),
		).toBeInTheDocument();
		expect(screen.queryByLabelText("Recovery key")).not.toBeInTheDocument();
	});

	it("shows enabled states and the required recovery-key field when both are enabled", async () => {
		biometricStatus.mockResolvedValue({ available: true, enabled: true });
		recoveryStatus.mockResolvedValue(true);
		await renderSection();

		expect(await screen.findByText("Touch ID")).toBeInTheDocument();
		expect(screen.getAllByText("Enabled")).toHaveLength(2);
		// D3: password change requires re-entering the recovery key.
		expect(screen.getByLabelText("Recovery key")).toBeInTheDocument();
	});
});

describe("SecuritySettingsSection change password", () => {
	it("rejects mismatched confirmation without calling the backend", async () => {
		await renderSection();

		fireEvent.change(screen.getByLabelText("Current password"), {
			target: { value: "current" },
		});
		fireEvent.change(screen.getByLabelText("New password"), {
			target: { value: "brand-new-password" },
		});
		fireEvent.change(screen.getByLabelText("Confirm new password"), {
			target: { value: "different-password" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Change Password" }));

		expect(
			await screen.findByText("New passwords do not match"),
		).toBeInTheDocument();
		expect(changePassword).not.toHaveBeenCalled();
	});

	it("calls changePassword without a recovery key when recovery is disabled", async () => {
		changePassword.mockResolvedValue(undefined);
		await renderSection();

		fireEvent.change(screen.getByLabelText("Current password"), {
			target: { value: "current" },
		});
		fireEvent.change(screen.getByLabelText("New password"), {
			target: { value: "brand-new-password" },
		});
		fireEvent.change(screen.getByLabelText("Confirm new password"), {
			target: { value: "brand-new-password" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Change Password" }));

		await waitFor(() =>
			expect(changePassword).toHaveBeenCalledWith(
				"current",
				"brand-new-password",
				null,
			),
		);
		expect(showToast).toHaveBeenCalledWith("Master password changed");
	});
});

describe("SecuritySettingsSection Touch ID", () => {
	it("enables Touch ID with the master password and refreshes status", async () => {
		biometricStatus
			.mockResolvedValueOnce({ available: true, enabled: false })
			.mockResolvedValue({ available: true, enabled: true });
		enableBiometric.mockResolvedValue(undefined);
		await renderSection();

		fireEvent.click(
			await screen.findByRole("button", { name: "Enable Touch ID" }),
		);
		fireEvent.change(screen.getByLabelText("Master password"), {
			target: { value: "master-password" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Enable Touch ID" }));

		await waitFor(() =>
			expect(enableBiometric).toHaveBeenCalledWith("master-password"),
		);
		// Status refresh turns the section into its enabled state.
		expect(await screen.findByText("Enabled")).toBeInTheDocument();
		expect(
			screen.queryByRole("button", { name: "Enable Touch ID" }),
		).not.toBeInTheDocument();
	});

	it("disables Touch ID only after confirmation", async () => {
		biometricStatus.mockResolvedValue({ available: true, enabled: true });
		disableBiometric.mockResolvedValue(undefined);
		await renderSection();

		await screen.findByText("Enabled");
		expect(disableBiometric).not.toHaveBeenCalled();

		const disableButtons = screen.getAllByRole("button", { name: "Disable" });
		fireEvent.click(disableButtons[0]);
		// Confirmation dialog: the backend call happens only on the dialog's
		// Disable button (the last one rendered).
		const dialogDisable = (
			await screen.findAllByRole("button", { name: "Disable" })
		).pop()!;
		fireEvent.click(dialogDisable);

		await waitFor(() => expect(disableBiometric).toHaveBeenCalled());
	});
});

describe("SecuritySettingsSection recovery key", () => {
	it("shows the one-time key in a dialog closable only after acknowledgement", async () => {
		recoveryStatus.mockResolvedValueOnce(false).mockResolvedValue(true);
		enableRecovery.mockResolvedValue("recovery-key-43-chars");
		await renderSection();

		fireEvent.click(
			await screen.findByRole("button", { name: "Enable Recovery Key" }),
		);
		fireEvent.change(screen.getByLabelText("Master password"), {
			target: { value: "master-password" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Generate Recovery Key" }));

		expect(await screen.findByText("recovery-key-43-chars")).toBeInTheDocument();

		// Blocked until the user acknowledges storing the key.
		expect(screen.getByRole("button", { name: "Done" })).toBeDisabled();
		fireEvent.click(screen.getByLabelText("I have safely stored it"));
		expect(screen.getByRole("button", { name: "Done" })).toBeEnabled();

		fireEvent.click(screen.getByRole("button", { name: "Done" }));
		expect(screen.queryByText("recovery-key-43-chars")).not.toBeInTheDocument();
		// Status refresh: the section now shows the enabled state.
		expect(await screen.findByText("Enabled")).toBeInTheDocument();
	});
});
