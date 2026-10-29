import { useState } from "react";
import { useAuth } from "../context/AppContext";
import { ShieldIcon } from "../components/Icons";
import { PasswordField } from "../components/PasswordField";

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
		<div className="auth-screen">
			<div className="auth-card">
				<div className="auth-badge" aria-hidden="true">
					<ShieldIcon />
				</div>
				<h1 className="auth-title">Recover Vault</h1>
				<p className="auth-tagline">
					Enter your recovery key and a new master password. The recovery
					key replaces the password you forgot; your vault data is kept.
				</p>

				{error && (
					<div className="error-message" id="recovery-error" role="alert">
						{error}
					</div>
				)}

				<form onSubmit={handleSubmit} className="auth-form">
					{/* The recovery key is a pasted one-time secret, not typed
					   confidential input — plain text field, no show/hide eye. */}
					<div className="auth-group">
						<label className="auth-label" htmlFor="recovery-key">
							Recovery Key
						</label>
						<div className="auth-field">
							<input
								id="recovery-key"
								type="text"
								className="auth-input"
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
					</div>

					<PasswordField
						id="new-password"
						label="New Master password"
						value={newPassword}
						onChange={setNewPassword}
						placeholder="Enter new master password"
						autoComplete="new-password"
						disabled={state.isLoading}
						ariaInvalid={!!error}
						ariaDescribedBy={error ? "recovery-error" : undefined}
					/>

					<PasswordField
						id="confirm-password"
						label="Confirm New Password"
						value={confirmPassword}
						onChange={setConfirmPassword}
						placeholder="Confirm new master password"
						autoComplete="new-password"
						disabled={state.isLoading}
						ariaInvalid={!!error}
						ariaDescribedBy={error ? "recovery-error" : undefined}
					/>

					<button
						type="submit"
						className="auth-btn-primary"
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
					className="auth-link"
					onClick={() => actions.navigate("unlock")}
					disabled={state.isLoading}
				>
					Back to unlock
				</button>
			</div>
		</div>
	);
}
