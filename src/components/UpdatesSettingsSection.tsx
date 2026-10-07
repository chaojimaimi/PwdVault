import { useEffect, useState } from "react";
import { useSettings } from "../context/AppContext";
import type { ManualCheckState } from "../context/SettingsContext";

function formatCheckedTime(ts: number): string {
	const at = new Date(ts);
	return `${String(at.getHours()).padStart(2, "0")}:${String(at.getMinutes()).padStart(2, "0")}`;
}

/** Status line copy for the manual update check (null = nothing to report). */
function updateCheckStatusText(
	manualCheck: ManualCheckState,
	appVersion: string | null,
): string | null {
	switch (manualCheck.phase) {
		case "checking":
			return "Checking for updates…";
		case "available":
			return `Update available: v${manualCheck.version} — use the banner above to install`;
		case "uptodate":
			return `You're up to date${appVersion ? ` (v${appVersion})` : ""} — checked ${manualCheck.checkedAt ? formatCheckedTime(manualCheck.checkedAt) : "just now"}`;
		case "error":
			return "Couldn't reach the update server — check your connection and try again";
		default:
			return null;
	}
}

interface UpdatesSettingsSectionProps {
	/** Screen-owned `settings.check_updates` value (the Settings screen holds
	    the draft until Save). */
	checkUpdates: boolean;
	/** Draft mutation for the startup auto-check toggle. */
	onCheckUpdatesChange: (checked: boolean) => void;
}

/**
 * Updates section of the Settings screen: the startup auto-check toggle plus
 * the v1.2.2 manual "Check for updates" block (status line, disabled
 * guards, current-version row). Unlike SecuritySettingsSection this section
 * is NOT fully self-contained — the auto-check toggle edits the screen's
 * draft `settings` object, so it arrives via props; the manual-check state
 * comes straight from the settings context.
 *
 * The UpdateNotification banner deliberately stays OUTSIDE this component:
 * it mounts outside the disabled settings fieldset so its buttons remain
 * clickable during a settings load/save.
 */
export function UpdatesSettingsSection({
	checkUpdates,
	onCheckUpdatesChange,
}: UpdatesSettingsSectionProps) {
	const { state, actions } = useSettings();
	const [appVersion, setAppVersion] = useState<string | null>(null);

	// Current app version ("Current version" row and the up-to-date hint).
	// Dynamic import matches the repo's Tauri API usage.
	useEffect(() => {
		let cancelled = false;
		import("@tauri-apps/api/app")
			.then(({ getVersion }) => getVersion())
			.then((version) => {
				if (!cancelled) setAppVersion(version);
			})
			.catch(() => {
				// Not in Tauri (tests / browser preview): keep the placeholder.
			});
		return () => {
			cancelled = true;
		};
	}, []);

	const manualCheck = state.manualCheck;
	// Mirrors the checkForUpdates guards: no re-check while one is in flight
	// or while an install is downloading / waiting for relaunch.
	const updateCheckDisabled =
		manualCheck.phase === "checking" ||
		state.updatePhase === "downloading" ||
		state.updatePhase === "ready";
	const updateCheckStatus = updateCheckStatusText(manualCheck, appVersion);

	return (
		<div className="settings-section">
			<h3 className="settings-section-title">Updates</h3>
			<div className="option-row">
				<label htmlFor="check-updates">Check for updates on startup</label>
				<input
					id="check-updates"
					type="checkbox"
					className="checkbox"
					checked={checkUpdates}
					onChange={(e) => onCheckUpdatesChange(e.target.checked)}
				/>
			</div>
			<div className="option-row">
				<span className="settings-hint">Current version: {appVersion ?? "…"}</span>
				{/* Manual check: independent of the startup toggle above. */}
				<button
					type="button"
					className="btn btn-secondary"
					onClick={() => void actions.checkForUpdates()}
					disabled={updateCheckDisabled}
				>
					{manualCheck.phase === "checking" ? "Checking…" : "Check for updates"}
				</button>
			</div>
			<p className="update-check-status" aria-live="polite">
				{updateCheckStatus}
			</p>
		</div>
	);
}
