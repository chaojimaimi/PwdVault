import { useState } from "react";
import { useAuth } from "../context/AppContext";

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
		<div className="screen">
			<div className="card">
				<div className="card-header">
					<h1>PwdVault</h1>
					<p>Create your master password</p>
				</div>

				{error && (
					<div className="error-message" id="setup-error" role="alert">
						{error}
					</div>
				)}

				<form onSubmit={handleSubmit}>
					<div className="form-group">
						<label htmlFor="password">Master Password</label>
						<input
							id="password"
							type="password"
							className="form-input"
							value={password}
							onChange={(e) => setPassword(e.target.value)}
							placeholder="Enter master password"
							autoFocus
							disabled={state.isLoading}
							aria-invalid={!!error}
							aria-describedby={error ? "setup-error" : undefined}
						/>
					</div>

					<div className="form-group">
						<label htmlFor="confirmPassword">Confirm Password</label>
						<input
							id="confirmPassword"
							type="password"
							className="form-input"
							value={confirmPassword}
							onChange={(e) => setConfirmPassword(e.target.value)}
							placeholder="Confirm master password"
							disabled={state.isLoading}
							aria-invalid={!!error}
							aria-describedby={error ? "setup-error" : undefined}
						/>
					</div>

					<button
						type="submit"
						className="btn btn-primary"
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
