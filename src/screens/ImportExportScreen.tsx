import { useEffect, useRef, useState } from "react";
import { useAuth, useVault } from "../context/AppContext";
import {
	exportVaultFile,
	readBackupFile,
	importCsvCommit,
	importCsvOpen,
	importCsvOpenBytes,
	syncStatus,
} from "../api/vault";
import { showToast } from "../utils/toast";
import { BackHeader } from "../components/BackHeader";
import { TrashIcon } from "../components/Icons";
import { AccessibleDialog } from "../components/AccessibleDialog";
import type { CsvImportPreview, VaultBackup } from "../types";
import { errorMessage } from "../utils/errorMessage";

function isTauriEnvironment(): boolean {
	return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

const MAX_BACKUP_FILE_BYTES = 14 * 1024 * 1024;
/** Same cap the backend enforces on staged CSV files (WP2). */
const MAX_CSV_FILE_BYTES = 10 * 1024 * 1024;

function isSupportedBackup(backup: VaultBackup): boolean {
	return backup.version === 1 || backup.version === 2;
}

export function ImportExportScreen() {
	const { actions: authActions } = useAuth();
	const { actions } = useVault();
	const [exportPassword, setExportPassword] = useState("");
	const [exportConfirm, setExportConfirm] = useState("");
	const [importPassword, setImportPassword] = useState("");
	const [selectedBackup, setSelectedBackup] = useState<VaultBackup | null>(
		null,
	);
	const [selectedFileName, setSelectedFileName] = useState("");
	const [exporting, setExporting] = useState(false);
	const [importing, setImporting] = useState(false);
	const [showImportConfirm, setShowImportConfirm] = useState(false);
	const [restoreConfirmation, setRestoreConfirmation] = useState("");
	// v1.5.0 (WP2): third-party CSV import state. The preview carries password
	// PRESENCE flags only — the plaintext rows stay in the backend staging.
	const [csvPending, setCsvPending] = useState(false);
	const [csvPreview, setCsvPreview] = useState<CsvImportPreview | null>(null);
	const [csvFileName, setCsvFileName] = useState("");
	const [csvError, setCsvError] = useState<string | null>(null);
	const [csvImporting, setCsvImporting] = useState(false);
	// v1.6.2 (F2): advisory-only cloud-sync warning while the restore confirm
	// dialog is open. One probe per dialog-open (the ref keeps duplicate
	// effect runs from issuing parallel probes); a response arriving after
	// close/unmount is dropped so it never sets state. A failed probe stays
	// silent by design — the restore itself does not depend on sync state.
	const [syncActive, setSyncActive] = useState(false);
	const syncProbeInFlight = useRef(false);
	useEffect(() => {
		if (!showImportConfirm) {
			syncProbeInFlight.current = false;
			return;
		}
		if (syncProbeInFlight.current) return;
		syncProbeInFlight.current = true;
		let cancelled = false;
		syncStatus()
			.then((status) => {
				// Mirror the probe result exactly (not just the true arm): today
				// enabled cannot flip within one mount, but keeping the state
				// equal to the latest probe removes the dependency on that
				// external fact.
				if (!cancelled) {
					setSyncActive(status.enabled === true);
				}
			})
			.catch(() => {
				// Advisory-only: a failed probe leaves the warning absent.
			});
		return () => {
			cancelled = true;
		};
	}, [showImportConfirm]);

	const handleBack = () => {
		authActions.navigate("settings");
	};

	const handleExport = async () => {
		if (!exportPassword) {
			showToast("Please enter an export password");
			return;
		}
		if (exportPassword.length < 8) {
			showToast("Password must be at least 8 characters");
			return;
		}
		if (exportPassword !== exportConfirm) {
			showToast("Passwords do not match");
			return;
		}

		setExporting(true);
		try {
			if (isTauriEnvironment()) {
				// SEC-M2: the backend opens the native save dialog, serializes the
				// encrypted container and writes it atomically. `null` means the
				// user cancelled the dialog — not an error.
				const savedPath = await exportVaultFile(exportPassword);
				if (savedPath) {
					const fileName = savedPath.split(/[\\/]/).pop() || "backup.pvault";
					showToast(`Backup exported successfully: ${fileName}`);
				}
			} else {
				// Browser fallback: generate the container here and download it
				// as a Blob (no fs capability needed).
				const backup = await actions.exportVault(exportPassword);
				const json = JSON.stringify(backup, null, 2);
				const blob = new Blob([json], { type: "application/json" });
				const url = URL.createObjectURL(blob);
				const a = document.createElement("a");
				a.href = url;
				a.download = `pwdvault-backup-${new Date().toISOString().slice(0, 10)}.pvault`;
				a.click();
				URL.revokeObjectURL(url);
				showToast("Backup exported successfully");
			}

			setExportPassword("");
			setExportConfirm("");
		} catch (error) {
			showToast(
				`Backup export failed: ${errorMessage(error, "Unknown file error")}`,
			);
		} finally {
			setExporting(false);
		}
	};

	const handleSelectFile = async () => {
		try {
			if (isTauriEnvironment()) {
				// SEC-M2: the backend opens the native open dialog and pre-validates
				// the file (size cap + envelope); `null` means the user cancelled.
				const backup = await readBackupFile();
				if (backup) {
					// Double guard: the backend already checked the envelope, but the
					// shape is still asserted before it reaches the import flow.
					if (!isSupportedBackup(backup)) {
						showToast("Unsupported backup version");
						return;
					}
					setSelectedBackup(backup);
					// The raw path never reaches the webview anymore, so the button
					// cannot show the picked file name.
					setSelectedFileName("Selected backup");
				}
			} else {
				const input = document.createElement("input");
				input.type = "file";
				input.accept = ".pvault";
				input.onchange = (e) => {
					const file = (e.target as HTMLInputElement).files?.[0];
					if (file) {
						if (file.size > MAX_BACKUP_FILE_BYTES) {
							showToast("Backup file is too large");
							return;
						}
						const reader = new FileReader();
						reader.onerror = () =>
							showToast("Failed to read the selected file");
						reader.onload = () => {
							try {
								const backup = JSON.parse(
									reader.result as string,
								) as VaultBackup;
								if (!isSupportedBackup(backup)) {
									showToast("Unsupported backup version");
									return;
								}
								setSelectedBackup(backup);
								setSelectedFileName(file.name);
							} catch {
								showToast("Invalid backup file");
							}
						};
						reader.readAsText(file);
					}
				};
				input.click();
			}
		} catch (error) {
			showToast(errorMessage(error, "Failed to read file"));
		}
	};

	const handleImport = async () => {
		if (!selectedBackup) {
			showToast("Please select a backup file first");
			return;
		}
		if (!importPassword) {
			showToast("Please enter the backup password");
			return;
		}

		setRestoreConfirmation("");
		setShowImportConfirm(true);
	};

	const confirmImport = async () => {
		setShowImportConfirm(false);
		setImporting(true);
		try {
			const result = await actions.importVault(selectedBackup!, importPassword);
			showToast(
				`Restored: ${result.entries_imported} entries, ${result.groups_imported} groups`,
			);
			setImportPassword("");
			setSelectedBackup(null);
			setSelectedFileName("");
		} catch (error) {
			showToast(errorMessage(error, "Import failed"));
		} finally {
			setImporting(false);
		}
	};

	// --- v1.5.0 (WP2): third-party CSV import -------------------------------

	// Render cap only — the import itself always commits every staged row.
	const CSV_PREVIEW_ROW_LIMIT = 100;

	const applyCsvPreview = (preview: CsvImportPreview, fileName: string) => {
		setCsvPreview(preview);
		setCsvFileName(fileName);
		setCsvError(null);
	};

	const handleSelectCsv = async () => {
		setCsvPending(true);
		setCsvError(null);
		if (!isTauriEnvironment()) {
			// RISK ACCEPTED (plan WP2): non-Tauri fallback — the webview reads
			// the file and ships the bytes to the same backend command, so the
			// plaintext crosses the webview on this path only. The dialog is
			// async: csvPending clears in the reader callbacks below (no shared
			// finally — it would re-enable the button while the dialog is open).
			const input = document.createElement("input");
			input.type = "file";
			input.accept = ".csv,text/csv";
			input.onchange = () => {
				const file = input.files?.[0];
				if (!file) return;
				if (file.size > MAX_CSV_FILE_BYTES) {
					showToast("CSV file is too large (10 MiB limit)");
					setCsvPending(false);
					return;
				}
				const reader = new FileReader();
				reader.onerror = () => {
					showToast("Failed to read the selected file");
					setCsvPending(false);
				};
				reader.onload = async () => {
					try {
						const preview = await importCsvOpenBytes(reader.result as string);
						if (preview) applyCsvPreview(preview, file.name);
					} catch (error) {
						setCsvError(errorMessage(error, "Could not read the CSV file"));
					} finally {
						setCsvPending(false);
					}
				};
				reader.readAsText(file);
			};
			input.click();
			return;
		}
		// SEC-M2: the backend opens the native dialog, reads and stages the
		// file; the webview never sees the bytes. `null` = cancelled.
		try {
			const preview = await importCsvOpen();
			if (preview) applyCsvPreview(preview, "Selected CSV");
		} catch (error) {
			// Recognition failures carry the per-preset expected headers — shown
			// inline so the user can compare against their export.
			setCsvError(errorMessage(error, "Could not read the CSV file"));
		} finally {
			setCsvPending(false);
		}
	};

	const handleCsvImport = async () => {
		if (!csvPreview || csvImporting) return;
		setCsvImporting(true);
		try {
			const result = await importCsvCommit();
			const skippedNote =
				result.skipped_rows > 0
					? `, ${result.skipped_rows} row${result.skipped_rows === 1 ? "" : "s"} skipped`
					: "";
			showToast(
				`Imported ${result.created_entries} entries from ${csvPreview.preset} (${result.created_groups} new group${result.created_groups === 1 ? "" : "s"}${skippedNote})`,
			);
			setCsvPreview(null);
			setCsvFileName("");
		} catch (error) {
			showToast(errorMessage(error, "CSV import failed"));
			// The backend consumed (and zeroized) the staging on every path, so
			// the preview just shown can never be committed — clear it rather
			// than let a retry fail with a misleading "pick a file first".
			setCsvPreview(null);
			setCsvFileName("");
		} finally {
			setCsvImporting(false);
		}
	};

	return (
		<div className="generator-screen screen-shell">
			<BackHeader title="Backup & Restore" onBack={handleBack} />

			<div className="generator-content screen-scroll-region">
				<div className="settings-section">
					<h3 className="settings-section-title">Export Backup</h3>
					<p className="settings-hint">
						Create an encrypted backup of your vault data
					</p>
					<div className="import-export-fields">
						<label htmlFor="export-password">Export password</label>
						<input
							id="export-password"
							type="password"
							className="input-field"
							placeholder="Export password"
							value={exportPassword}
							onChange={(e) => setExportPassword(e.target.value)}
						/>
						<label htmlFor="export-confirm">Confirm export password</label>
						<input
							id="export-confirm"
							type="password"
							className="input-field"
							placeholder="Confirm password"
							value={exportConfirm}
							onChange={(e) => setExportConfirm(e.target.value)}
						/>
					</div>
					<button
						className="btn btn-secondary btn-full"
						onClick={handleExport}
						disabled={exporting || !exportPassword || !exportConfirm}
					>
						{exporting ? "Exporting..." : "Export Backup"}
					</button>
				</div>

				<div className="settings-divider" />

				<div className="settings-section">
					<h3 className="settings-section-title">Restore Backup</h3>
					<p className="settings-hint">
						Restore from a previously exported backup file
					</p>
					<button
						className="btn btn-secondary btn-full"
						onClick={handleSelectFile}
					>
						{selectedFileName ? selectedFileName : "Select Backup File"}
					</button>
					{selectedBackup && (
						<div className="import-export-fields">
							<label htmlFor="import-password">Backup password</label>
							<input
								id="import-password"
								type="password"
								className="input-field"
								placeholder="Backup password"
								value={importPassword}
								onChange={(e) => setImportPassword(e.target.value)}
							/>
							<button
								className="btn btn-primary btn-full"
								onClick={handleImport}
								disabled={importing || !importPassword}
							>
								{importing ? "Restoring..." : "Restore Backup"}
							</button>
						</div>
					)}
				</div>

				<div className="settings-divider" />

				{/* v1.5.0 (WP2): third-party CSV import. Adds new entries — the
				    existing vault is never replaced (unlike .pvault restore). */}
				<div className="settings-section">
					<h3 className="settings-section-title">Import from Other Apps</h3>
					<p className="settings-hint">
						Import a CSV export from Bitwarden, 1Password, Chrome, or KeePassXC.
						Rows are added as new entries — nothing is replaced.
					</p>
					<button
						className="btn btn-secondary btn-full"
						onClick={() => void handleSelectCsv()}
						disabled={csvPending || csvImporting}
					>
						{csvFileName || "Select CSV File"}
					</button>
					{csvError && (
						<p className="error-message" role="alert">
							{csvError}
						</p>
					)}
					{csvPreview && (
						<div className="csv-import-block">
							<p className="settings-hint">
								Recognized as <strong>{csvPreview.preset}</strong> —{" "}
								{csvPreview.rows.length} of {csvPreview.total_rows} rows will
								import
								{csvPreview.skipped_rows > 0
									? ` (${csvPreview.skipped_rows} skipped as invalid)`
									: ""}
								.
							</p>
							{csvPreview.duplicate_candidates > 0 && (
								<p className="settings-hint csv-duplicate-hint">
									About {csvPreview.duplicate_candidates} row
									{csvPreview.duplicate_candidates === 1 ? " looks" : "s look"}{" "}
									like duplicates of existing entries — they will still be
									imported as new entries.
								</p>
							)}
							<div className="csv-preview-scroll">
								<table className="csv-preview-table">
									<thead>
										<tr>
											<th scope="col">Title</th>
											<th scope="col">Username</th>
											<th scope="col">URL</th>
											<th scope="col">Group</th>
											<th scope="col">Password</th>
										</tr>
									</thead>
									<tbody>
										{csvPreview.rows
											.slice(0, CSV_PREVIEW_ROW_LIMIT)
											.map((row, index) => (
												<tr key={`${row.title}-${index}`}>
													<td>{row.title || "Untitled"}</td>
													<td>{row.username}</td>
													<td className="csv-cell-url">{row.url || ""}</td>
													<td>{row.group || ""}</td>
													<td>{row.has_password ? "Yes" : "Missing"}</td>
												</tr>
											))}
										{csvPreview.rows.length > CSV_PREVIEW_ROW_LIMIT && (
											<tr>
												<td colSpan={5}>
													…and {csvPreview.rows.length - CSV_PREVIEW_ROW_LIMIT}{" "}
													more rows (all of them will be imported)
												</td>
											</tr>
										)}
									</tbody>
								</table>
							</div>
							<button
								className="btn btn-primary btn-full"
								onClick={() => void handleCsvImport()}
								disabled={csvImporting || csvPreview.rows.length === 0}
							>
								{csvImporting
									? "Importing..."
									: `Import ${csvPreview.rows.length} Entr${csvPreview.rows.length === 1 ? "y" : "ies"}`}
							</button>
						</div>
					)}
				</div>
			</div>

			<AccessibleDialog
				isOpen={showImportConfirm}
				onClose={() => setShowImportConfirm(false)}
				labelledBy="restore-dialog-title"
				describedBy="restore-dialog-description"
				className="confirm-modal"
				initialFocusSelector="[data-restore-confirmation]"
			>
				<div className="confirm-modal-header">
					<div className="confirm-modal-icon confirm-modal-icon-danger">
						<TrashIcon size={18} />
					</div>
					<div>
						<h3 className="confirm-modal-title" id="restore-dialog-title">
							Restore Backup?
						</h3>
					</div>
				</div>
				<div className="confirm-modal-body">
					<p className="confirm-delete-message" id="restore-dialog-description">
						This will replace all current vault data with the backup contents.
						This action cannot be undone.
					</p>
					{syncActive && (
						// role="status" (implied aria-live=polite): the warning is
						// inserted after the dialog opens, so without a live region
						// a screen reader that started announcing on open never
						// hears it. Advisory content, warning-tinted — not an error.
						<p className="restore-sync-warning" role="status">
							Cloud sync is active — after restoring, the next sync merges both
							sides by timestamp (newer wins). Entries deleted after this backup
							was taken stay deleted once their deletion has synced.
						</p>
					)}
					<label htmlFor="restore-confirmation">Type RESTORE to continue</label>
					<input
						id="restore-confirmation"
						data-restore-confirmation
						className="form-input"
						value={restoreConfirmation}
						onChange={(event) => setRestoreConfirmation(event.target.value)}
						autoComplete="off"
					/>
					{/* v1.6.2 (F3): visible answer to a disabled Restore button.
					    Empty input stays silent — the label right above already says
					    what to type, and an aria-live region must not announce on
					    dialog open. */}
					{restoreConfirmation.length > 0 &&
						restoreConfirmation !== "RESTORE" && (
							<p className="error-message" aria-live="polite">
								Type exactly RESTORE to continue (case-sensitive)
							</p>
						)}
				</div>
				<div className="confirm-modal-footer">
					<div className="confirm-modal-actions">
						<button
							className="btn btn-secondary"
							onClick={() => setShowImportConfirm(false)}
						>
							Cancel
						</button>
						<button
							className="btn btn-danger"
							onClick={confirmImport}
							disabled={importing || restoreConfirmation !== "RESTORE"}
						>
							Restore
						</button>
					</div>
				</div>
			</AccessibleDialog>
		</div>
	);
}
