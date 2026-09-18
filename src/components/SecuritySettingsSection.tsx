import { useCallback, useEffect, useState } from "react";
import {
	biometricStatus,
	changePassword,
	disableBiometric,
	disableRecovery,
	enableBiometric,
	enableRecovery,
	recoveryStatus,
} from "../api/vault";
import { copyWithTimeout } from "../utils/clipboard";
import { errorMessage } from "../utils/errorMessage";
import { showToast } from "../utils/toast";
import { AccessibleDialog } from "./AccessibleDialog";
import type { BiometricStatus } from "../types";

/**
 * Security section of the Settings screen (Phase 1): master password change,
 * Touch ID unlock toggle, and recovery key management. Self-contained: it
 * probes the backend for biometric/recovery status on mount and refreshes
 * after every successful operation. Status-probe failures degrade silently —
 * the affected affordance simply stays hidden or keeps its last known state.
 */

// One operation at a time: the backend serializes full re-seals anyway (D8),
// so a shared guard also prevents the user from stacking conflicting security
// operations in the UI.
type BusyOp =
	| "password"
	| "bio-enable"
	| "bio-disable"
	| "recovery-enable"
	| "recovery-disable"
	| "recovery-export"
	| null;

function isTauriEnvironment(): boolean {
	return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function recoveryKeyFileContent(key: string): string {
	return [
		"PwdVault Recovery Key",
		`Generated: ${new Date().toISOString().slice(0, 10)}`,
		"",
		"Keep this file somewhere safe. It is the only way to recover your",
		"vault if you forget your master password. Anyone holding this key",
		"can unlock your vault.",
		"",
		key,
		"",
	].join("\n");
}

export function SecuritySettingsSection() {
	const [bioStatus, setBioStatus] = useState<BiometricStatus | null>(null);
	const [recoveryEnabled, setRecoveryEnabled] = useState(false);
	const [busy, setBusy] = useState<BusyOp>(null);

	// Change master password form
	const [currentPassword, setCurrentPassword] = useState("");
	const [newPassword, setNewPassword] = useState("");
	const [confirmPassword, setConfirmPassword] = useState("");
	const [recoveryKeyField, setRecoveryKeyField] = useState("");
	const [passwordError, setPasswordError] = useState<string | null>(null);

	// Touch ID
	const [showBioEnable, setShowBioEnable] = useState(false);
	const [bioPassword, setBioPassword] = useState("");
	const [showBioDisable, setShowBioDisable] = useState(false);
	const [bioError, setBioError] = useState<string | null>(null);

	// Recovery key
	const [showRecoveryEnable, setShowRecoveryEnable] = useState(false);
	const [recoveryPassword, setRecoveryPassword] = useState("");
	const [generatedKey, setGeneratedKey] = useState<string | null>(null);
	const [keyStoredAck, setKeyStoredAck] = useState(false);
	const [showRecoveryDisable, setShowRecoveryDisable] = useState(false);
	const [recoveryDisablePassword, setRecoveryDisablePassword] = useState("");
	const [recoveryError, setRecoveryError] = useState<string | null>(null);

	// H4: stable via useCallback — the mount effect below depends on it. A
	// fresh function per render plus the fresh objects biometricStatus()
	// returns would otherwise risk re-probing loops once this lands in deps.
	const refreshStatuses = useCallback(async () => {
		try {
			const [bio, recovery] = await Promise.all([
				biometricStatus(),
				recoveryStatus(),
			]);
			setBioStatus(bio);
			setRecoveryEnabled(recovery);
		} catch {
			/* keep last known state; probes are non-critical */
		}
	}, []);

	// Probe once on mount (refreshStatuses is a stable useCallback; the API
	// functions and both setters it closes over are module/stable refs).
	useEffect(() => {
		void refreshStatuses();
	}, [refreshStatuses]);

	const handleChangePassword = async () => {
		if (busy) return;
		// Front-end owns only consistency checks; the backend validation is
		// authoritative for password strength.
		if (!currentPassword) {
			setPasswordError("Enter your current master password");
			return;
		}
		if (!newPassword) {
			setPasswordError("Enter a new master password");
			return;
		}
		if (newPassword !== confirmPassword) {
			setPasswordError("New passwords do not match");
			return;
		}
		if (recoveryEnabled && !recoveryKeyField.trim()) {
			setPasswordError("Re-enter your recovery key to rebind it to the new master password");
			return;
		}
		setBusy("password");
		setPasswordError(null);
		try {
			await changePassword(
				currentPassword,
				newPassword,
				recoveryEnabled ? recoveryKeyField.trim() : null,
			);
			showToast("Master password changed");
			setCurrentPassword("");
			setNewPassword("");
			setConfirmPassword("");
			setRecoveryKeyField("");
			await refreshStatuses();
		} catch (error) {
			setPasswordError(
				errorMessage(error, "Failed to change master password"),
			);
		} finally {
			setBusy(null);
		}
	};

	const handleBioEnable = async () => {
		if (busy || !bioPassword) return;
		setBusy("bio-enable");
		setBioError(null);
		try {
			await enableBiometric(bioPassword);
			showToast("Touch ID unlock enabled");
			setBioPassword("");
			setShowBioEnable(false);
			await refreshStatuses();
		} catch (error) {
			setBioError(errorMessage(error, "Failed to enable Touch ID"));
		} finally {
			setBusy(null);
		}
	};

	const handleBioDisable = async () => {
		if (busy) return;
		setBusy("bio-disable");
		setBioError(null);
		try {
			await disableBiometric();
			showToast("Touch ID unlock disabled");
			setShowBioDisable(false);
			await refreshStatuses();
		} catch (error) {
			setBioError(errorMessage(error, "Failed to disable Touch ID"));
		} finally {
			setBusy(null);
		}
	};

	const handleRecoveryEnable = async () => {
		if (busy || !recoveryPassword) return;
		setBusy("recovery-enable");
		setRecoveryError(null);
		try {
			const key = await enableRecovery(recoveryPassword);
			setRecoveryPassword("");
			setShowRecoveryEnable(false);
			// The key is shown exactly once, inside a dialog the user can only
			// dismiss after acknowledging it is stored.
			setGeneratedKey(key);
			setKeyStoredAck(false);
		} catch (error) {
			setRecoveryError(errorMessage(error, "Failed to enable recovery key"));
		} finally {
			setBusy(null);
		}
	};

	const handleRecoveryDisable = async () => {
		if (busy || !recoveryDisablePassword) return;
		setBusy("recovery-disable");
		setRecoveryError(null);
		try {
			await disableRecovery(recoveryDisablePassword);
			showToast("Recovery key disabled");
			setRecoveryDisablePassword("");
			setShowRecoveryDisable(false);
			await refreshStatuses();
		} catch (error) {
			setRecoveryError(errorMessage(error, "Failed to disable recovery key"));
		} finally {
			setBusy(null);
		}
	};

	const handleCopyKey = async () => {
		if (!generatedKey) return;
		try {
			await copyWithTimeout(generatedKey);
			showToast("Recovery key copied (clears in 30 seconds)");
		} catch {
			showToast("Failed to copy recovery key");
		}
	};

	const handleExportKey = async () => {
		if (!generatedKey || busy) return;
		setBusy("recovery-export");
		try {
			if (isTauriEnvironment()) {
				const { save } = await import("@tauri-apps/plugin-dialog");
				const filePath = await save({
					defaultPath: "pwdvault-recovery-key.txt",
					filters: [{ name: "Text", extensions: ["txt"] }],
				});
				if (filePath) {
					const { writeFile } = await import("@tauri-apps/plugin-fs");
					await writeFile(
						filePath,
						new TextEncoder().encode(recoveryKeyFileContent(generatedKey)),
					);
					showToast("Recovery key exported");
				}
			} else {
				const blob = new Blob([recoveryKeyFileContent(generatedKey)], {
					type: "text/plain",
				});
				const url = URL.createObjectURL(blob);
				const a = document.createElement("a");
				a.href = url;
				a.download = "pwdvault-recovery-key.txt";
				a.click();
				URL.revokeObjectURL(url);
				showToast("Recovery key exported");
			}
		} catch (error) {
			showToast(errorMessage(error, "Failed to export recovery key"));
		} finally {
			setBusy(null);
		}
	};

	const closeKeyDialog = () => {
		// The dialog must not be dismissable before the user acknowledged
		// storing the one-time key (Esc included — closeOnOverlay is off).
		if (!keyStoredAck) return;
		setGeneratedKey(null);
		setKeyStoredAck(false);
		void refreshStatuses();
	};

	return (
		<>
			<div className="settings-divider" />
			<div className="settings-section">
				<h3 className="settings-section-title">Security</h3>

				{/* --- Change master password --- */}
				<h4 className="settings-subsection-title">Change Master Password</h4>
				<div className="security-inline-form">
					<label htmlFor="security-current-password">Current password</label>
					<input
						id="security-current-password"
						type="password"
						className="input-field"
						placeholder="Current master password"
						value={currentPassword}
						onChange={(e) => setCurrentPassword(e.target.value)}
						autoComplete="current-password"
					/>
					<label htmlFor="security-new-password">New password</label>
					<input
						id="security-new-password"
						type="password"
						className="input-field"
						placeholder="New master password"
						value={newPassword}
						onChange={(e) => setNewPassword(e.target.value)}
						autoComplete="new-password"
					/>
					<label htmlFor="security-confirm-password">Confirm new password</label>
					<input
						id="security-confirm-password"
						type="password"
						className="input-field"
						placeholder="Confirm new master password"
						value={confirmPassword}
						onChange={(e) => setConfirmPassword(e.target.value)}
						autoComplete="new-password"
					/>
					{recoveryEnabled && (
						<>
							<label htmlFor="security-recovery-key">Recovery key</label>
							<input
								id="security-recovery-key"
								type="text"
								className="input-field"
								placeholder="Re-enter your recovery key"
								value={recoveryKeyField}
								onChange={(e) => setRecoveryKeyField(e.target.value)}
								autoComplete="off"
								spellCheck={false}
							/>
							<p className="settings-hint">
								Re-enter your recovery key to rebind it to the new master
								password.
							</p>
						</>
					)}
					{bioStatus?.enabled && (
						<p className="settings-hint">
							Touch ID is enabled for this vault: you may be asked to
							authenticate while the password is changed.
						</p>
					)}
					{passwordError && (
						<p className="error-message" role="alert">
							{passwordError}
						</p>
					)}
					<button
						type="button"
						className="btn btn-secondary btn-full"
						onClick={() => void handleChangePassword()}
						disabled={busy !== null}
					>
						{busy === "password" ? "Changing..." : "Change Password"}
					</button>
				</div>

				{/* --- Touch ID --- */}
				{bioStatus?.available && (
					<>
						<h4 className="settings-subsection-title">Touch ID</h4>
						{bioStatus.enabled ? (
							<div className="security-status-row">
								<span className="security-enabled-badge">Enabled</span>
								<button
									type="button"
									className="btn btn-danger btn-sm"
									onClick={() => setShowBioDisable(true)}
									disabled={busy !== null}
								>
									Disable
								</button>
							</div>
						) : showBioEnable ? (
							<div className="security-inline-form">
								<label htmlFor="security-bio-password">Master password</label>
								<input
									id="security-bio-password"
									type="password"
									className="input-field"
									placeholder="Confirm master password"
									value={bioPassword}
									onChange={(e) => setBioPassword(e.target.value)}
									autoComplete="current-password"
								/>
								{bioError && (
									<p className="error-message" role="alert">
										{bioError}
									</p>
								)}
								<div className="security-status-row">
									<button
										type="button"
										className="btn btn-secondary btn-sm"
										onClick={() => {
											setShowBioEnable(false);
											setBioPassword("");
											setBioError(null);
										}}
										disabled={busy !== null}
									>
										Cancel
									</button>
									<button
										type="button"
										className="btn btn-primary btn-sm"
										onClick={() => void handleBioEnable()}
										disabled={busy !== null || !bioPassword}
									>
										{busy === "bio-enable" ? "Enabling..." : "Enable Touch ID"}
									</button>
								</div>
							</div>
						) : (
							<div>
								<p className="settings-hint settings-action-description">
									Unlock this vault with Touch ID instead of your master
									password.
								</p>
								<button
									type="button"
									className="btn btn-secondary"
									onClick={() => setShowBioEnable(true)}
									disabled={busy !== null}
								>
									Enable Touch ID
								</button>
							</div>
						)}
						{bioStatus.enabled && bioError && (
							<p className="error-message" role="alert">
								{bioError}
							</p>
						)}
					</>
				)}

				{/* --- Recovery key --- */}
				<h4 className="settings-subsection-title">Recovery Key</h4>
				{recoveryEnabled ? (
					<>
						<div className="security-status-row">
							<span className="security-enabled-badge">Enabled</span>
							<button
								type="button"
								className="btn btn-danger btn-sm"
								onClick={() => setShowRecoveryDisable(!showRecoveryDisable)}
								disabled={busy !== null}
							>
								Disable
							</button>
						</div>
						{showRecoveryDisable && (
							<div className="security-inline-form">
								<label htmlFor="security-recovery-disable-password">
									Master password
								</label>
								<input
									id="security-recovery-disable-password"
									type="password"
									className="input-field"
									placeholder="Confirm master password"
									value={recoveryDisablePassword}
									onChange={(e) => setRecoveryDisablePassword(e.target.value)}
									autoComplete="current-password"
								/>
								<div className="security-status-row">
									<button
										type="button"
										className="btn btn-secondary btn-sm"
										onClick={() => {
											setShowRecoveryDisable(false);
											setRecoveryDisablePassword("");
											setRecoveryError(null);
										}}
										disabled={busy !== null}
									>
										Cancel
									</button>
									<button
										type="button"
										className="btn btn-danger btn-sm"
										onClick={() => void handleRecoveryDisable()}
										disabled={busy !== null || !recoveryDisablePassword}
									>
										{busy === "recovery-disable"
											? "Disabling..."
											: "Disable Recovery Key"}
									</button>
								</div>
							</div>
						)}
						{recoveryError && (
							<p className="error-message" role="alert">
								{recoveryError}
							</p>
						)}
					</>
				) : showRecoveryEnable ? (
					<div className="security-inline-form">
						<label htmlFor="security-recovery-password">Master password</label>
						<input
							id="security-recovery-password"
							type="password"
							className="input-field"
							placeholder="Confirm master password"
							value={recoveryPassword}
							onChange={(e) => setRecoveryPassword(e.target.value)}
							autoComplete="current-password"
						/>
						{recoveryError && (
							<p className="error-message" role="alert">
								{recoveryError}
							</p>
						)}
						<div className="security-status-row">
							<button
								type="button"
								className="btn btn-secondary btn-sm"
								onClick={() => {
									setShowRecoveryEnable(false);
									setRecoveryPassword("");
									setRecoveryError(null);
								}}
								disabled={busy !== null}
							>
								Cancel
							</button>
							<button
								type="button"
								className="btn btn-primary btn-sm"
								onClick={() => void handleRecoveryEnable()}
								disabled={busy !== null || !recoveryPassword}
							>
								{busy === "recovery-enable"
									? "Generating..."
									: "Generate Recovery Key"}
							</button>
						</div>
					</div>
				) : (
					<div>
						<p className="settings-hint settings-action-description">
							Generate a one-time recovery key that can restore access if you
							ever forget your master password.
						</p>
						<button
							type="button"
							className="btn btn-secondary"
							onClick={() => setShowRecoveryEnable(true)}
							disabled={busy !== null}
						>
							Enable Recovery Key
						</button>
					</div>
				)}
			</div>

			{/* One-time recovery key display: Copy / Export .txt, closable only
			    after the "I have safely stored it" acknowledgement. */}
			<AccessibleDialog
				isOpen={generatedKey !== null}
				onClose={closeKeyDialog}
				labelledBy="recovery-key-title"
				describedBy="recovery-key-description"
				className="confirm-modal"
				initialFocusSelector="[data-recovery-key-copy]"
				closeOnOverlay={false}
			>
				<div className="confirm-modal-header">
					<div className="confirm-modal-icon" aria-hidden="true">
						<svg
							viewBox="0 0 24 24"
							fill="none"
							stroke="currentColor"
							strokeWidth="2"
						>
							<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
						</svg>
					</div>
					<div>
						<h3 className="confirm-modal-title" id="recovery-key-title">
							Your recovery key
						</h3>
						<p className="confirm-modal-subtitle">
							Shown only once — store it before closing
						</p>
					</div>
				</div>
				<div className="confirm-modal-body">
					<p className="confirm-delete-message" id="recovery-key-description">
						This key can restore access to your vault if you forget your
						master password. Anyone holding it can unlock your vault.
					</p>
					<div className="recovery-key-display" aria-label="Recovery key">
						{generatedKey}
					</div>
					<div className="security-status-row">
						<button
							type="button"
							className="btn btn-secondary btn-sm"
							data-recovery-key-copy
							onClick={() => void handleCopyKey()}
						>
							Copy
						</button>
						<button
							type="button"
							className="btn btn-secondary btn-sm"
							onClick={() => void handleExportKey()}
							disabled={busy !== null}
						>
							{busy === "recovery-export" ? "Exporting..." : "Export .txt"}
						</button>
					</div>
					<label className="confirm-checkbox">
						<input
							type="checkbox"
							className="checkbox"
							checked={keyStoredAck}
							onChange={(e) => setKeyStoredAck(e.target.checked)}
						/>
						I have safely stored it
					</label>
				</div>
				<div className="confirm-modal-footer">
					<div className="confirm-modal-actions">
						<button
							className="btn btn-primary"
							onClick={closeKeyDialog}
							disabled={!keyStoredAck}
						>
							Done
						</button>
					</div>
				</div>
			</AccessibleDialog>

			{/* Touch ID disable confirmation */}
			<AccessibleDialog
				isOpen={showBioDisable}
				onClose={() => {
					if (busy === null) setShowBioDisable(false);
				}}
				labelledBy="bio-disable-title"
				describedBy="bio-disable-description"
				className="confirm-modal"
				initialFocusSelector="[data-bio-disable-cancel]"
				closeOnOverlay={busy === null}
			>
				<div className="confirm-modal-header">
					<div
						className="confirm-modal-icon confirm-modal-icon-danger"
						aria-hidden="true"
					>
						<svg
							viewBox="0 0 24 24"
							fill="none"
							stroke="currentColor"
							strokeWidth="2"
						>
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
						</svg>
					</div>
					<div>
						<h3 className="confirm-modal-title" id="bio-disable-title">
							Disable Touch ID unlock?
						</h3>
					</div>
				</div>
				<div className="confirm-modal-body">
					<p id="bio-disable-description">
						You will need your master password to unlock the vault. The stored
						Touch ID credential is removed from this device.
					</p>
				</div>
				<div className="confirm-modal-footer">
					<div className="confirm-modal-actions">
						<button
							className="btn btn-secondary"
							data-bio-disable-cancel
							onClick={() => setShowBioDisable(false)}
							disabled={busy !== null}
						>
							Cancel
						</button>
						<button
							className="btn btn-danger"
							onClick={() => void handleBioDisable()}
							disabled={busy !== null}
						>
							{busy === "bio-disable" ? "Disabling..." : "Disable"}
						</button>
					</div>
				</div>
			</AccessibleDialog>
		</>
	);
}
