import { useEffect, useState } from "react";
import {
	baiduCompleteAuth,
	baiduStartAuth,
	syncConnect,
	syncDisconnect,
	syncNow,
	syncStatus,
} from "../api/vault";
import { errorMessage } from "../utils/errorMessage";
import { showToast } from "../utils/toast";
import { AccessibleDialog } from "./AccessibleDialog";
import type { SyncBackendKind, SyncStatusResponse } from "../types";

/**
 * Sync section of the Settings screen (Phase 3 / P3.5): connect the vault to
 * WebDAV or Baidu Netdisk cloud storage, run a manual sync cycle, and
 * disconnect. Self-contained like SecuritySettingsSection: probes
 * `sync_status` on mount and refreshes after every successful operation.
 * Settings is only reachable in the unlocked state, so no extra unlock
 * guard is needed here (the backend re-checks the session anyway).
 */

type BusyOp =
	| "connect"
	| "sync"
	| "disconnect"
	| "baidu-start"
	| "baidu-complete"
	| null;

// Wire format for the backend kind as it appears in SyncStatusResponse.
type BackendKind = NonNullable<SyncStatusResponse["backend"]>;

const BACKEND_LABELS: Record<BackendKind, string> = {
	webdav: "WebDAV",
	baidu: "Baidu Netdisk",
};

function backendLabel(backend: string | null | undefined): string {
	if (backend && backend in BACKEND_LABELS) {
		return BACKEND_LABELS[backend as BackendKind];
	}
	return backend || "—";
}

/**
 * The Baidu OAuth commands reject with `VaultError::InvalidInput { code:
 * "SYNC_BACKEND_NOT_CONFIGURED", .. }` when this build carries no compiled-in
 * AppKey/SecretKey. Match on the code string in the serialized error so the
 * BAIDU-SETUP guidance shows instead of a raw message.
 */
function isBaiduNotConfigured(error: unknown): boolean {
	try {
		return JSON.stringify(error).includes("SYNC_BACKEND_NOT_CONFIGURED");
	} catch {
		return false;
	}
}

function formatSyncTime(unixSecs: number | null | undefined): string {
	if (!unixSecs) return "Never";
	return new Date(unixSecs * 1000).toLocaleString();
}

function openAuthorizeUrl(url: string): void {
	// opener is severed so the OAuth page cannot navigate this app window.
	window.open(url, "_blank", "noopener,noreferrer");
}

export function SyncSettingsSection() {
	const [status, setStatus] = useState<SyncStatusResponse | null>(null);
	const [busy, setBusy] = useState<BusyOp>(null);

	// Connect form (not-connected state)
	const [backend, setBackend] = useState<SyncBackendKind>("webdav");
	const [serverUrl, setServerUrl] = useState("");
	const [remoteDir, setRemoteDir] = useState("");
	const [username, setUsername] = useState("");
	const [webdavPassword, setWebdavPassword] = useState("");
	const [containerPassword, setContainerPassword] = useState("");
	const [connectError, setConnectError] = useState<string | null>(null);

	// Baidu OAuth flow state
	const [baiduAwaiting, setBaiduAwaiting] = useState(false);
	const [baiduAuthorized, setBaiduAuthorized] = useState(false);
	const [baiduGuide, setBaiduGuide] = useState(false);

	// Disconnect confirmation
	const [showDisconnect, setShowDisconnect] = useState(false);
	const [disconnectError, setDisconnectError] = useState<string | null>(null);

	const refreshStatus = async () => {
		try {
			setStatus(await syncStatus());
		} catch {
			/* keep last known state; the probe is non-critical */
		}
	};

	useEffect(() => {
		void refreshStatus();
	}, []);

	const resetConnectForm = () => {
		setWebdavPassword("");
		setContainerPassword("");
		setConnectError(null);
	};

	const handleConnect = async () => {
		if (busy) return;
		if (backend === "webdav") {
			if (!serverUrl.trim()) {
				setConnectError("Enter your WebDAV server URL");
				return;
			}
			if (!username.trim() || !webdavPassword) {
				setConnectError("Enter your WebDAV username and password");
				return;
			}
		}
		if (!containerPassword) {
			setConnectError("Enter the sync container password");
			return;
		}
		if (backend === "baidu" && !baiduAuthorized) {
			setConnectError("Authorize Baidu Netdisk first");
			return;
		}
		setBusy("connect");
		setConnectError(null);
		try {
			const next = await syncConnect(
				{
					enabled: true,
					backend,
					server_url: serverUrl.trim(),
					remote_dir: remoteDir.trim(),
					username: username.trim(),
				},
				containerPassword,
				backend === "webdav" ? webdavPassword : null,
			);
			setStatus(next);
			showToast("Cloud sync connected");
			resetConnectForm();
			setServerUrl("");
			setRemoteDir("");
			setUsername("");
		} catch (error) {
			setConnectError(errorMessage(error, "Failed to connect cloud sync"));
		} finally {
			setBusy(null);
		}
	};

	const handleBaiduStart = async () => {
		if (busy) return;
		setBusy("baidu-start");
		setConnectError(null);
		setBaiduGuide(false);
		try {
			const { auth_url } = await baiduStartAuth();
			openAuthorizeUrl(auth_url);
			setBaiduAwaiting(true);
		} catch (error) {
			if (isBaiduNotConfigured(error)) {
				setBaiduGuide(true);
			} else {
				setConnectError(
					errorMessage(error, "Failed to start Baidu authorization"),
				);
			}
		} finally {
			setBusy(null);
		}
	};

	const handleBaiduComplete = async () => {
		if (busy) return;
		setBusy("baidu-complete");
		setConnectError(null);
		try {
			// The fixed loopback callback captured the code while the user was
			// in the browser — null consumes it.
			await baiduCompleteAuth(null);
			setBaiduAwaiting(false);
			setBaiduAuthorized(true);
			await refreshStatus();
			showToast("Baidu Netdisk authorized");
		} catch (error) {
			setConnectError(errorMessage(error, "Baidu authorization failed"));
		} finally {
			setBusy(null);
		}
	};

	const handleSyncNow = async () => {
		if (busy) return;
		setBusy("sync");
		try {
			setStatus(await syncNow());
			showToast("Sync completed");
		} catch (error) {
			showToast(errorMessage(error, "Sync failed"));
		} finally {
			setBusy(null);
		}
	};

	const handleDisconnect = async () => {
		if (busy) return;
		setBusy("disconnect");
		setDisconnectError(null);
		try {
			await syncDisconnect();
			setShowDisconnect(false);
			setStatus(null);
			setBaiduAwaiting(false);
			setBaiduAuthorized(false);
			showToast("Cloud sync disconnected. Cloud files are kept.");
		} catch (error) {
			setDisconnectError(errorMessage(error, "Failed to disconnect cloud sync"));
		} finally {
			setBusy(null);
		}
	};

	const connected = status?.enabled === true;

	return (
		<>
			<div className="settings-divider" />
			<div className="settings-section">
				<h3 className="settings-section-title">Cloud Sync</h3>

				{connected ? (
					<>
						<div className="sync-status-list">
							<div className="option-row">
								<span className="sync-status-label">Backend</span>
								<span className="sync-status-value">
									{backendLabel(status!.backend)}
								</span>
							</div>
							<div className="option-row">
								<span className="sync-status-label">Last sync</span>
								<span className="sync-status-value">
									{formatSyncTime(status!.last_sync_at)}
								</span>
							</div>
							<div className="option-row">
								<span className="sync-status-label">Remote revision</span>
								<span className="sync-status-value">
									{status!.remote_rev ?? "—"}
								</span>
							</div>
							{status!.last_result && status!.last_result !== "ok" && (
								<p className="error-message" role="alert">
									Last sync failed: {status!.last_result}
								</p>
							)}
						</div>
						<p className="settings-hint settings-action-description">
							Sync merges this vault with the encrypted container on your
							cloud storage. The cloud only ever sees end-to-end encrypted
							data.
						</p>
						{connectError && (
							<p className="error-message" role="alert">
								{connectError}
							</p>
						)}
						<div className="security-status-row">
							<button
								type="button"
								className="btn btn-primary btn-sm"
								onClick={() => void handleSyncNow()}
								disabled={busy !== null}
							>
								{busy === "sync" ? "Syncing..." : "Sync Now"}
							</button>
							<button
								type="button"
								className="btn btn-danger btn-sm"
								onClick={() => setShowDisconnect(true)}
								disabled={busy !== null}
							>
								Disconnect
							</button>
						</div>
					</>
				) : (
					<>
						<p className="settings-hint settings-action-description">
							Keep multiple devices in sync through your own cloud storage.
							The cloud stores a single end-to-end encrypted container —
							neither the provider nor anyone else can read your passwords.
						</p>

						<div className="security-inline-form">
							<label htmlFor="sync-backend">Backend</label>
							<select
								id="sync-backend"
								className="settings-select"
								value={backend}
								onChange={(e) => {
									setBackend(e.target.value as SyncBackendKind);
									setConnectError(null);
								}}
								disabled={busy !== null}
							>
								<option value="webdav">WebDAV</option>
								<option value="baidu">Baidu Netdisk</option>
							</select>
						</div>

						{backend === "webdav" && (
							<div className="security-inline-form">
								<label htmlFor="sync-server-url">Server URL</label>
								<input
									id="sync-server-url"
									type="url"
									className="input-field"
									placeholder="https://dav.jianguoyun.com/dav"
									value={serverUrl}
									onChange={(e) => setServerUrl(e.target.value)}
									autoComplete="off"
									spellCheck={false}
									disabled={busy !== null}
								/>
								<label htmlFor="sync-remote-dir">Remote directory</label>
								<input
									id="sync-remote-dir"
									type="text"
									className="input-field"
									placeholder="PwdVault"
									value={remoteDir}
									onChange={(e) => setRemoteDir(e.target.value)}
									autoComplete="off"
									spellCheck={false}
									disabled={busy !== null}
								/>
								<label htmlFor="sync-username">Username</label>
								<input
									id="sync-username"
									type="text"
									className="input-field"
									placeholder="WebDAV username"
									value={username}
									onChange={(e) => setUsername(e.target.value)}
									autoComplete="off"
									disabled={busy !== null}
								/>
								<label htmlFor="sync-webdav-password">Password</label>
								<input
									id="sync-webdav-password"
									type="password"
									className="input-field"
									placeholder="WebDAV password"
									value={webdavPassword}
									onChange={(e) => setWebdavPassword(e.target.value)}
									autoComplete="off"
									disabled={busy !== null}
								/>
							</div>
						)}

						{backend === "baidu" && (
							<div className="security-inline-form">
								<p className="settings-hint settings-action-description">
									Authorize PwdVault in your Baidu account. A browser window
									opens for the login; this app then receives the result on a
									local loopback port.
								</p>
								{!baiduAwaiting ? (
									<button
										type="button"
										className="btn btn-secondary"
										onClick={() => void handleBaiduStart()}
										disabled={busy !== null}
									>
										{busy === "baidu-start"
											? "Opening..."
											: "Authorize Baidu Netdisk"}
									</button>
								) : (
									<>
										<p className="settings-hint settings-action-description">
											Waiting for authorization. Complete the login in the
											opened browser window, then confirm below.
										</p>
										<div className="security-status-row">
											<button
												type="button"
												className="btn btn-secondary btn-sm"
												onClick={() => {
													setBaiduAwaiting(false);
													setConnectError(null);
												}}
												disabled={busy !== null}
											>
												Cancel
											</button>
											<button
												type="button"
												className="btn btn-primary btn-sm"
												onClick={() => void handleBaiduComplete()}
												disabled={busy !== null}
											>
												{busy === "baidu-complete"
													? "Connecting..."
													: "I've authorized"}
											</button>
										</div>
									</>
								)}
								{baiduGuide && (
									<div className="sync-setup-guide" role="note">
										<p>
											Baidu Netdisk sync is not configured in this build. It
											requires a Baidu Open Platform app whose AppKey /
											SecretKey are compiled into the desktop client.
										</p>
										<p>
											Developers: see{" "}
											<span className="sync-guide-path">
												docs/BAIDU-SETUP.md
											</span>{" "}
											for registration and build instructions. WebDAV sync
											works without this step.
										</p>
									</div>
								)}
							</div>
						)}

						{/* The container password bootstraps the E2E container key for
						    both backends (D2) — independent from the master password. */}
						<div className="security-inline-form">
							<label htmlFor="sync-container-password">
								Container password
							</label>
							<input
								id="sync-container-password"
								type="password"
								className="input-field"
								placeholder="Sync container password"
								value={containerPassword}
								onChange={(e) => setContainerPassword(e.target.value)}
								autoComplete="off"
								disabled={busy !== null}
							/>
							<p className="settings-hint">
								The container password encrypts the sync container and is
								independent from your master password. Use the one chosen
								when sync was first set up on another device.
							</p>
						</div>

						{connectError && (
							<p className="error-message" role="alert">
								{connectError}
							</p>
						)}

						<button
							type="button"
							className="btn btn-primary"
							onClick={() => void handleConnect()}
							disabled={busy !== null || (backend === "baidu" && !baiduAuthorized)}
						>
							{busy === "connect" ? "Connecting..." : "Connect"}
						</button>
						{backend === "baidu" && !baiduAuthorized && (
							<p className="settings-hint">
								Connect unlocks after the Baidu authorization above.
							</p>
						)}
					</>
				)}
			</div>

			{/* Disconnect confirmation (DeleteConfirmModal pattern) */}
			<AccessibleDialog
				isOpen={showDisconnect}
				onClose={() => {
					if (busy === null) setShowDisconnect(false);
				}}
				labelledBy="sync-disconnect-title"
				describedBy="sync-disconnect-description"
				className="confirm-modal"
				initialFocusSelector="[data-sync-disconnect-cancel]"
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
							<path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
							<line x1="12" y1="2" x2="12" y2="12" />
						</svg>
					</div>
					<div>
						<h3 className="confirm-modal-title" id="sync-disconnect-title">
							Disconnect cloud sync?
						</h3>
					</div>
				</div>
				<div className="confirm-modal-body">
					<p id="sync-disconnect-description">
						This device stops syncing and forgets its sync credentials. The
						encrypted container and its history stay on your cloud storage,
						so other devices are unaffected. You can reconnect later with the
						container password.
					</p>
					{disconnectError && (
						<p className="error-message" role="alert">
							{disconnectError}
						</p>
					)}
				</div>
				<div className="confirm-modal-footer">
					<div className="confirm-modal-actions">
						<button
							className="btn btn-secondary"
							data-sync-disconnect-cancel
							onClick={() => setShowDisconnect(false)}
							disabled={busy !== null}
						>
							Cancel
						</button>
						<button
							className="btn btn-danger"
							onClick={() => void handleDisconnect()}
							disabled={busy !== null}
						>
							{busy === "disconnect" ? "Disconnecting..." : "Disconnect"}
						</button>
					</div>
				</div>
			</AccessibleDialog>
		</>
	);
}
