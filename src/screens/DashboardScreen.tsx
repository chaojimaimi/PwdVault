import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth, useVault } from "../context/AppContext";
import { getSecurityReport } from "../api/vault";
import { errorMessage } from "../utils/errorMessage";
import { showToast } from "../utils/toast";
import { BackHeader } from "../components/BackHeader";
import { ShieldIcon } from "../components/Icons";
import type { EntrySummary, SecurityReport } from "../types";
import { securityScoreLabel } from "../types";

/**
 * Security Dashboard (v1.5.0 WP1): read-only report of weak / reused /
 * stale passwords. The backend aggregates over decrypted passwords but the
 * response carries ids and scores ONLY — this screen renders findings by
 * resolving ids against the vault entry list it already holds.
 * Row click opens the entry editor; there is no automatic fix behavior.
 */
export function DashboardScreen() {
	const { actions: authActions } = useAuth();
	const { state: vaultState, actions: vaultActions } = useVault();
	const [report, setReport] = useState<SecurityReport | null>(null);
	const [pending, setPending] = useState(true);
	const [loadError, setLoadError] = useState<string | null>(null);

	const loadReport = useCallback(async () => {
		setPending(true);
		try {
			const next = await getSecurityReport();
			setReport(next);
			setLoadError(null);
		} catch (error) {
			setLoadError(errorMessage(error, "Failed to build the security report"));
		} finally {
			setPending(false);
		}
	}, []);

	// The report carries ids only — the entry list supplies titles/usernames.
	useEffect(() => {
		void loadReport();
		void vaultActions.loadEntries().catch(() => {
			// Titles resolve against the vault list; a silent empty list would
			// render everything as "Untitled" with no explanation.
			showToast("Entry titles unavailable");
		});
		// Both actions are referentially stable (VaultContext memoizes on
		// dispatch), so this stays mount-only like the other screens' loads.
	}, [loadReport, vaultActions]);

	const entryById = useMemo(
		() => new Map(vaultState.entries.map((entry) => [entry.id, entry])),
		[vaultState.entries],
	);

	const describe = (id: string): EntrySummary | undefined => entryById.get(id);

	const handleOpenEntry = useCallback(
		async (id: string) => {
			try {
				await vaultActions.selectEntry(id);
				authActions.navigate("entry");
			} catch (error) {
				showToast(errorMessage(error, "Failed to open entry"));
			}
		},
		[vaultActions, authActions],
	);

	const allClear =
		report !== null &&
		report.weak.length === 0 &&
		report.reused.length === 0 &&
		report.stale.length === 0;

	const renderRow = (id: string, badge?: string) => {
		const entry = describe(id);
		return (
			<li key={id}>
				<button
					type="button"
					className="dashboard-row"
					onClick={() => void handleOpenEntry(id)}
				>
					<span className="dashboard-row-info">
						<span className="dashboard-row-title">
							{entry?.title || "Untitled"}
						</span>
						<span className="dashboard-row-username">
							{entry?.username || ""}
						</span>
					</span>
					{badge && <span className="dashboard-row-badge">{badge}</span>}
				</button>
			</li>
		);
	};

	return (
		<div className="generator-screen screen-shell">
			<BackHeader
				title="Security Dashboard"
				onBack={() => authActions.navigate("vault")}
			/>

			<div className="generator-content screen-scroll-region">
				{loadError ? (
					<div className="settings-section">
						<div className="resource-error" role="alert">
							<p>Could not build the security report.</p>
							<p className="text-muted-hint">{loadError}</p>
							<button
								className="btn btn-secondary btn-block"
								onClick={() => void loadReport()}
							>
								Retry
							</button>
						</div>
					</div>
				) : (
					<>
						<div className="settings-section">
							<div className="dashboard-summary">
								<ShieldIcon size={28} className="dashboard-summary-icon" />
								{/* flex:1 + min-width:0 — without it the summary text
								    collapses to one word per line (v1.5.1 fix). */}
								<div className="dashboard-summary-text">
									<h3 className="settings-section-title">
										{pending
											? "Scanning your vault…"
											: allClear
												? "All clear"
												: "Findings"}
									</h3>
									{report && (
										<p className="settings-hint">
											{report.total} password
											{report.total === 1 ? "" : "s"} scanned. Nothing is
											changed automatically — open an entry to fix it.
										</p>
									)}
								</div>
								<button
									className="btn btn-secondary btn-sm btn-inline dashboard-rerun"
									onClick={() => void loadReport()}
									disabled={pending}
								>
									{pending ? "Scanning…" : "Re-run check"}
								</button>
							</div>
							{report && allClear && (
								<p className="dashboard-healthy" role="status">
									No weak, reused, or stale passwords found. Keep it up.
								</p>
							)}
						</div>

						{report && report.weak.length > 0 && (
							<div className="settings-section">
								<h3 className="settings-section-title">
									Weak passwords ({report.weak.length})
								</h3>
								<p className="settings-hint">
									Flagged as weak by the leak-corpus scan or a low
									strength score.
								</p>
								<ul className="dashboard-list">
									{report.weak.map((finding) =>
										renderRow(finding.id, securityScoreLabel(finding.score)),
									)}
								</ul>
							</div>
						)}

						{report && report.reused.length > 0 && (
							<div className="settings-section">
								<h3 className="settings-section-title">
									Reused passwords ({report.reused.length}{" "}
									{report.reused.length === 1 ? "group" : "groups"})
								</h3>
								<p className="settings-hint">
									Entries sharing the exact same password.
								</p>
								{report.reused.map((group, index) => (
									<ul className="dashboard-list" key={`reused-${index}`}>
										{group.map((id) => renderRow(id))}
									</ul>
								))}
							</div>
						)}

						{report && report.stale.length > 0 && (
							<div className="settings-section">
								<h3 className="settings-section-title">
									Stale passwords ({report.stale.length})
								</h3>
								<p className="settings-hint">
									Unchanged for over a year — consider rotating them.
								</p>
								<ul className="dashboard-list">
									{report.stale.map((id) => {
										const entry = describe(id);
										const badge = entry
											? `Updated ${new Date(entry.updated_at * 1000).toLocaleDateString()}`
											: undefined;
										return renderRow(id, badge);
									})}
								</ul>
							</div>
						)}
					</>
				)}
			</div>
		</div>
	);
}
