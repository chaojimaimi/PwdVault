import { useState } from "react";
import { useAuth } from "../context/AppContext";
import { ShieldIcon } from "../components/Icons";
import { PasswordField } from "../components/PasswordField";

export function SetupScreen() {
	const { state, actions } = useAuth();
	const [password, setPassword] = useState("");
	const [confirmPassword, setConfirmPassword] = useState("");
	const [localError, setLocalError] = useState<string | null>(null);

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		setLocalError(null);

		if (password.length < 8) {
			setLocalError("Password must be at least 8 characters");
			return;
		}

		if (password !== confirmPassword) {
			setLocalError("Passwords do not match");
			return;
		}

		try {
			await actions.initialize(password);
		} catch {
			setLocalError("Failed to initialize vault");
		} finally {
			setPassword("");
			setConfirmPassword("");
		}
	};

	const error = localError || state.error;

	return (
		<div className="auth-screen">
			<div className="auth-card">
				<div className="auth-badge" aria-hidden="true">
					<ShieldIcon />
				</div>
				<h1 className="auth-title">PwdVault</h1>
				<p className="auth-tagline">Create your master password</p>

				{error && (
					<div className="error-message" id="setup-error" role="alert">
						{error}
					</div>
				)}

				<form onSubmit={handleSubmit} className="auth-form">
					<PasswordField
						id="password"
						label="Master password"
						value={password}
						onChange={setPassword}
						placeholder="Enter master password"
						disabled={state.isLoading}
						focusOnMount
						ariaInvalid={!!error}
						ariaDescribedBy={error ? "setup-error" : undefined}
					/>

					<PasswordField
						id="confirmPassword"
						label="Confirm Password"
						value={confirmPassword}
						onChange={setConfirmPassword}
						placeholder="Confirm master password"
						disabled={state.isLoading}
						ariaInvalid={!!error}
						ariaDescribedBy={error ? "setup-error" : undefined}
					/>

					<button
						type="submit"
						className="auth-btn-primary"
						disabled={state.isLoading || !password || !confirmPassword}
					>
						{state.isLoading ? (
							<span className="loading">
								<span className="spinner" />
								Creating...
							</span>
						) : (
							"Create Vault"
						)}
					</button>
				</form>
			</div>
		</div>
	);
}
