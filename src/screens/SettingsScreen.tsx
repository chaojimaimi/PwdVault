import { useEffect, useMemo, useState } from "react";
import { useAuth, useSettings } from "../context/AppContext";
import { useTheme } from "../hooks/useTheme";
import { showToast } from "../utils/toast";
import { errorMessage } from "../utils/errorMessage";
import { BackHeader } from "../components/BackHeader";
import type { Settings } from "../types";
import { UnsavedChangesModal } from "../components/UnsavedChangesModal";
import { registerGlobalShortcut, revokeExtensionAccess } from "../api/vault";
import { AccessibleDialog } from "../components/AccessibleDialog";
import { UpdateNotification } from "../components/UpdateNotification";
import { SecuritySettingsSection } from "../components/SecuritySettingsSection";
import { SyncSettingsSection } from "../components/SyncSettingsSection";
import { UpdatesSettingsSection } from "../components/UpdatesSettingsSection";

const AUTO_LOCK_OPTIONS = [
	{ label: "1 minute", value: 60 },
	{ label: "2 minutes", value: 120 },
	{ label: "5 minutes", value: 300 },
	{ label: "10 minutes", value: 600 },
	{ label: "15 minutes", value: 900 },
	{ label: "30 minutes", value: 1800 },
	{ label: "1 hour", value: 3600 },
];

// v1.5.0 (WP3): trash auto-purge. 0 = off is the DEFAULT — permanent
// deletion is strict opt-in (deliberately more conservative than Bitwarden's
// 30-day default). The values mirror the Rust side's treatment: any nonzero
// number of days works, these four are the curated choices.
const TRASH_PURGE_OPTIONS = [
	{ label: "Off", value: 0 },
	{ label: "After 7 days", value: 7 },
	{ label: "After 30 days", value: 30 },
	{ label: "After 90 days", value: 90 },
];

export function SettingsScreen() {
	const { actions: authActions } = useAuth();
	const { state, actions } = useSettings();
	const { theme, setTheme, themes } = useTheme();
	const [settings, setSettings] = useState<Settings>(state.settings);
	const [saving, setSaving] = useState(false);
	const [showUnsaved, setShowUnsaved] = useState(false);
	const [showRevoke, setShowRevoke] = useState(false);
	const [revoking, setRevoking] = useState(false);
	// v1.4.0: red registration-failure hint for the global shortcut — set when
	// the Rust re-registration rejects the accelerator (conflict/bad string).
	const [shortcutError, setShortcutError] = useState<string | null>(null);
	const charsetValid =
		settings.default_include_uppercase ||
		settings.default_include_lowercase ||
		settings.default_include_numbers ||
		settings.default_include_symbols;
	const isDirty = useMemo(
		() =>
			state.status === "success" &&
			JSON.stringify(settings) !== JSON.stringify(state.settings),
		[settings, state.settings, state.status],
	);

	useEffect(() => {
		if (state.status === "success") setSettings(state.settings);
	}, [state.settings, state.status]);

	useEffect(() => {
		const warn = (event: BeforeUnloadEvent) => {
			if (!isDirty) return;
			event.preventDefault();
		};
		window.addEventListener("beforeunload", warn);
		return () => window.removeEventListener("beforeunload", warn);
	}, [isDirty]);

	const handleBack = () => {
		if (isDirty) setShowUnsaved(true);
		else authActions.navigate("vault");
	};

	const handleSave = async () => {
		if (saving || state.status !== "success" || !charsetValid) return;
		setSaving(true);
		try {
			// v1.4.0: a changed shortcut binding is validated by actually
			// registering it (Rust command) BEFORE persisting. On failure the
			// previous binding is kept (revert the two fields to the loaded
			// values) and the error shows inline in red.
			const shortcutChanged =
				settings.global_shortcut_enabled !==
					state.settings.global_shortcut_enabled ||
				settings.global_shortcut !== state.settings.global_shortcut;
			if (shortcutChanged) {
				try {
					await registerGlobalShortcut(
						settings.global_shortcut_enabled,
						settings.global_shortcut,
					);
					setShortcutError(null);
				} catch (error) {
					const message = errorMessage(error, "Could not register shortcut");
					setShortcutError(message);
					setSettings((current) => ({
						...current,
						global_shortcut_enabled: state.settings.global_shortcut_enabled,
						global_shortcut: state.settings.global_shortcut,
					}));
					showToast("Shortcut not saved — keeping the previous binding");
					return;
				}
			}
			await actions.updateSettings(settings);
			showToast("Settings saved");
			authActions.navigate("vault");
		} catch {
			showToast("Failed to save settings");
		} finally {
			setSaving(false);
		}
	};

	const handleRevoke = async () => {
		if (revoking) return;
		setRevoking(true);
		try {
			await revokeExtensionAccess();
			setShowRevoke(false);
			showToast("Browser extension access revoked");
		} catch {
			showToast("Failed to revoke extension access");
		} finally {
			setRevoking(false);
		}
	};

	return (
		<div className="generator-screen screen-shell">
			<BackHeader title="Settings" onBack={handleBack} />

			{/* Update banner reuses the same install flow as the vault screen.
			    Mounted outside the disabled settings fieldset so its buttons
			    stay clickable during a settings load/save. */}
			{state.update && (
				<UpdateNotification
					version={state.update.version}
					phase={state.updatePhase}
					progress={state.downloadProgress}
					onUpdate={() => void actions.installUpdate()}
					onRelaunch={() => void actions.relaunchApp()}
					onDismiss={() => actions.dismissUpdate()}
				/>
			)}

			<div className="generator-content screen-scroll-region">
				{(state.status === "idle" || state.status === "loading") && (
					<div className="loading" role="status">
						<span className="spinner" />
						<span>Loading settings…</span>
					</div>
				)}
				{state.status === "error" && (
					<div className="resource-error" role="alert">
						<p>
							Could not load settings. Saving is disabled to protect your stored
							configuration.
						</p>
						<p className="text-muted-hint">{state.error}</p>
						<button
							className="btn btn-secondary"
							onClick={() => void actions.loadSettings()}
						>
							Retry
						</button>
					</div>
				)}
				<fieldset
					disabled={state.status !== "success" || saving}
					className="settings-fieldset"
				>
					<div className="settings-section">
						<h3 className="settings-section-title">Theme</h3>
						<div className="theme-selector">
							{themes.map((t) => (
								<button
									key={t}
									type="button"
									className={`theme-option ${theme === t ? "active" : ""}`}
									onClick={() => setTheme(t)}
									aria-pressed={theme === t}
									aria-label={`Use ${t} theme`}
								>
									<div className={`theme-option-dot theme-option-dot-${t}`} />
									<span className="theme-option-name">
										{t.charAt(0).toUpperCase() + t.slice(1)}
									</span>
								</button>
							))}
						</div>
					</div>

					<div className="settings-divider" />

					<div className="settings-section">
						<h3 className="settings-section-title">Browser Extension</h3>
						<p className="settings-hint settings-action-description">
							Invalidate all paired browser tokens. Extensions must pair again
							before they can access this vault.
						</p>
						<button
							type="button"
							className="btn btn-danger"
							onClick={() => setShowRevoke(true)}
						>
							Revoke Extension Access
						</button>
					</div>

					<div className="settings-divider" />

					<div className="settings-section">
						<h3 className="settings-section-title">Auto-Lock</h3>
						<div className="option-row">
							<label htmlFor="auto-lock">Lock after inactivity</label>
							<select
								id="auto-lock"
								className="settings-select"
								value={settings.auto_lock_secs}
								onChange={(e) =>
									setSettings({
										...settings,
										auto_lock_secs: parseInt(e.target.value),
									})
								}
							>
								{AUTO_LOCK_OPTIONS.map((opt) => (
									<option key={opt.value} value={opt.value}>
										{opt.label}
									</option>
								))}
							</select>
						</div>
						<p className="settings-hint">Vault locks automatically when idle</p>
					</div>

					<div className="settings-divider" />

					<div className="settings-section">
						<h3 className="settings-section-title">Trash Auto-Purge</h3>
						<div className="option-row">
							<label htmlFor="trash-auto-purge">Empty trash automatically</label>
							<select
								id="trash-auto-purge"
								className="settings-select"
								value={settings.trash_auto_purge_days}
								onChange={(e) =>
									setSettings({
										...settings,
										trash_auto_purge_days: parseInt(e.target.value),
									})
								}
							>
								{TRASH_PURGE_OPTIONS.map((opt) => (
									<option key={opt.value} value={opt.value}>
										{opt.label}
									</option>
								))}
							</select>
						</div>
						<p className="settings-hint">
							Permanently deletes recycle-bin items older than the selected
							number of days. The trash is only swept right after the vault
							is unlocked — an always-unlocked vault never sweeps, and a
							changed setting applies at the next unlock. At most 500 items
							are deleted per unlock.
						</p>
					</div>

					<div className="settings-divider" />

					<div className="settings-section">
						<h3 className="settings-section-title">Global Shortcut</h3>
						<div className="option-row">
							<label htmlFor="global-shortcut-enabled">
								Enable global shortcut
							</label>
							<input
								id="global-shortcut-enabled"
								type="checkbox"
								className="checkbox"
								checked={settings.global_shortcut_enabled}
								onChange={(e) =>
									setSettings({
										...settings,
										global_shortcut_enabled: e.target.checked,
									})
								}
							/>
						</div>
						<div className="option-row">
							<label htmlFor="global-shortcut">Shortcut</label>
							<input
								id="global-shortcut"
								type="text"
								className="settings-input"
								spellCheck={false}
								placeholder="CmdOrCtrl+Shift+Space"
								value={settings.global_shortcut}
								onChange={(e) =>
									setSettings({
										...settings,
										global_shortcut: e.target.value,
									})
								}
							/>
						</div>
						<p className="settings-hint">
							Shows and focuses PwdVault from anywhere. Example:
							CmdOrCtrl+Shift+Space. Takes effect on save.
						</p>
						{shortcutError && (
							<p className="error-message" role="alert">
								{shortcutError}
							</p>
						)}
					</div>

					<div className="settings-divider" />

					<UpdatesSettingsSection
						checkUpdates={settings.check_updates}
						onCheckUpdatesChange={(checked) =>
							setSettings({ ...settings, check_updates: checked })
						}
					/>

					<div className="settings-divider" />

					<div className="settings-section">
						<h3 className="settings-section-title">
							Default Generator Options
						</h3>
						<div className="option-row">
							<label htmlFor="def-length">
								Length: {settings.default_length}
							</label>
						</div>
						<div className="length-control">
							<input
								id="def-length"
								type="range"
								min="8"
								max="64"
								value={settings.default_length}
								aria-label="Default password length"
								aria-valuemin={8}
								aria-valuemax={64}
								aria-valuenow={settings.default_length}
								onChange={(e) =>
									setSettings({
										...settings,
										default_length: parseInt(e.target.value),
									})
								}
							/>
						</div>

						<div className="option-row">
							<label htmlFor="def-upper">Uppercase (A-Z)</label>
							<input
								id="def-upper"
								type="checkbox"
								className="checkbox"
								checked={settings.default_include_uppercase}
								onChange={(e) =>
									setSettings({
										...settings,
										default_include_uppercase: e.target.checked,
									})
								}
							/>
						</div>

						<div className="option-row">
							<label htmlFor="def-lower">Lowercase (a-z)</label>
							<input
								id="def-lower"
								type="checkbox"
								className="checkbox"
								checked={settings.default_include_lowercase}
								onChange={(e) =>
									setSettings({
										...settings,
										default_include_lowercase: e.target.checked,
									})
								}
							/>
						</div>

						<div className="option-row">
							<label htmlFor="def-numbers">Numbers (0-9)</label>
							<input
								id="def-numbers"
								type="checkbox"
								className="checkbox"
								checked={settings.default_include_numbers}
								onChange={(e) =>
									setSettings({
										...settings,
										default_include_numbers: e.target.checked,
									})
								}
							/>
						</div>

						<div className="option-row">
							<label htmlFor="def-symbols">Symbols (!@#$...)</label>
							<input
								id="def-symbols"
								type="checkbox"
								className="checkbox"
								checked={settings.default_include_symbols}
								onChange={(e) =>
									setSettings({
										...settings,
										default_include_symbols: e.target.checked,
									})
								}
							/>
						</div>
						{!charsetValid && (
							<p className="error-message" role="alert">
								Select at least one character set.
							</p>
						)}
					</div>
				</fieldset>

				{/* Phase 1: master password change / Touch ID / recovery key.
				    Owns its state and busy-guard, independent of the settings
				    load status above. */}
				<SecuritySettingsSection />

				{/* Phase 3: cloud sync (WebDAV / Baidu Netdisk). Same
				    self-contained pattern as the security section above. */}
				<SyncSettingsSection />
			</div>

			<div className="generator-actions">
				<button
					className="btn btn-primary"
					onClick={handleSave}
					disabled={saving || state.status !== "success" || !charsetValid}
				>
					{saving ? "Saving..." : "Save Settings"}
				</button>
				<button
					className="btn btn-secondary btn-full"
					onClick={() => authActions.navigate("importExport")}
				>
					Backup & Restore
				</button>
			</div>
			<UnsavedChangesModal
				isOpen={showUnsaved}
				onStay={() => setShowUnsaved(false)}
				onDiscard={() => {
					setShowUnsaved(false);
					authActions.navigate("vault");
				}}
			/>
			<AccessibleDialog
				isOpen={showRevoke}
				onClose={() => {
					if (!revoking) setShowRevoke(false);
				}}
				labelledBy="revoke-extension-title"
				describedBy="revoke-extension-description"
				className="confirm-modal"
				initialFocusSelector="[data-revoke-cancel]"
				closeOnOverlay={!revoking}
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
							<path d="M9 9l6 6M15 9l-6 6" />
						</svg>
					</div>
					<div>
						<h3 className="confirm-modal-title" id="revoke-extension-title">
							Revoke extension access?
						</h3>
						<p className="confirm-modal-subtitle">
							Vault data will not be changed
						</p>
					</div>
				</div>
				<div className="confirm-modal-body">
					<p id="revoke-extension-description">
						All currently paired browser extensions will be disconnected and
						must complete pairing again.
					</p>
				</div>
				<div className="confirm-modal-footer">
					<div className="confirm-modal-actions">
						<button
							className="btn btn-secondary"
							data-revoke-cancel
							onClick={() => setShowRevoke(false)}
							disabled={revoking}
						>
							Cancel
						</button>
						<button
							className="btn btn-danger"
							onClick={() => void handleRevoke()}
							disabled={revoking}
						>
							{revoking ? "Revoking…" : "Revoke Access"}
						</button>
					</div>
				</div>
			</AccessibleDialog>
		</div>
	);
}
