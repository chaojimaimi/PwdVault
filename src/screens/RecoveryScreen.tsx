import { useState } from "react";
import { useAuth } from "../context/AppContext";

export function RecoveryScreen() {
	const { state, actions } = useAuth();
	const [recoveryKey, setRecoveryKey] = useState("");
	const [newPassword, setNewPassword] = useState("");
	const [confirmPassword, setConfirmPassword] = useState("");
	const [localError, setLocalError] = useState<string | null>(null);

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		setLocalError(null);

		if (!recoveryKey.trim()) {
			setLocalError("Enter your recovery key");
			return;
		}
		if (!newPassword) {
			setLocalError("Enter a new master password");
			return;
		}
		if (newPassword !== confirmPassword) {
			setLocalError("Passwords do not match");
			return;
		}

		// Backend validation is authoritative for password strength; on
		// success recover_vault has already published the new session keys.
		await actions.recover(recoveryKey.trim(), newPassword);
	};

	const error = localError || state.error;

	return (
		<div className="screen">
			<div className="card">
				<div className="card-header">
					<h1>Recover Vault</h1>
					<p>
						Enter your recovery key and a new master password. The recovery
						key replaces the password you forgot; your vault data is kept.
					</p>
				</div>

				{error && (
					<div className="error-message" id="recovery-error" role="alert">
						{error}
					</div>
				)}

				<form onSubmit={handleSubmit}>
					<div className="form-group">
						<label htmlFor="recovery-key">Recovery Key</label>
						<input
							id="recovery-key"
							type="text"
							className="form-input"
							value={recoveryKey}
							onChange={(e) => setRecoveryKey(e.target.value)}
							placeholder="Paste your recovery key"
							ref={(el) => {
								// jsx-a11y/no-autofocus: focus at commit instead of the
								// autoFocus prop — same UX, programmatic.
								el?.focus();
							}}
							autoComplete="off"
							spellCheck={false}
							disabled={state.isLoading}
							aria-invalid={!!error}
							aria-describedby={error ? "recovery-error" : undefined}
						/>
					</div>

					<div className="form-group">
						<label htmlFor="new-password">New Master Password</label>
						<input
							id="new-password"
							type="password"
							className="form-input"
							value={newPassword}
							onChange={(e) => setNewPassword(e.target.value)}
							placeholder="Enter new master password"
							autoComplete="new-password"
							disabled={state.isLoading}
							aria-invalid={!!error}
							aria-describedby={error ? "recovery-error" : undefined}
						/>
					</div>

					<div className="form-group">
						<label htmlFor="confirm-password">Confirm New Password</label>
						<input
							id="confirm-password"
							type="password"
							className="form-input"
							value={confirmPassword}
							onChange={(e) => setConfirmPassword(e.target.value)}
							placeholder="Confirm new master password"
							autoComplete="new-password"
							disabled={state.isLoading}
							aria-invalid={!!error}
							aria-describedby={error ? "recovery-error" : undefined}
						/>
					</div>

					<button
						type="submit"
						className="btn btn-primary"
						disabled={
							state.isLoading || !recoveryKey || !newPassword || !confirmPassword
						}
					>
						{state.isLoading ? (
							<span className="loading">
								<span className="spinner" />
								Recovering...
							</span>
						) : (
							"Recover Vault"
						)}
					</button>
				</form>

				<button
					type="button"
					className="btn btn-link btn-full"
					onClick={() => actions.navigate("unlock")}
					disabled={state.isLoading}
				>
					Back to unlock
				</button>
			</div>
		</div>
	);
}
