import { useEffect, useState } from "react";
import { useAuth } from "../context/AppContext";
import { biometricStatus, recoveryStatus } from "../api/vault";
import { FingerprintIcon, ShieldAlertIcon, ShieldCheckIcon, ShieldIcon } from "../components/Icons";
import { PasswordField } from "../components/PasswordField";
import type { BiometricStatus } from "../types";

export function UnlockScreen() {
	const { state, actions } = useAuth();
	const [password, setPassword] = useState("");
	const [localError, setLocalError] = useState<string | null>(null);
	// Phase 1 affordances. Both probes fail silently: they only enable extra
	// UI, so a transport failure must degrade to the plain password form
	// (never show an error for a missing Touch ID / recovery option).
	const [bioStatus, setBioStatus] = useState<BiometricStatus | null>(null);
	// Three-state by design (review P3): null = probe pending or failed. The
	// hint must not assert "no recovery key" until the probe CONFIRMS it —
	// on a transport failure we render no hint at all, and an enabled user
	// never sees the warning flash before the confirm flips in.
	const [recoveryEnabled, setRecoveryEnabled] = useState<boolean | null>(null);

	useEffect(() => {
		let cancelled = false;
		Promise.all([biometricStatus(), recoveryStatus()])
			.then(([bio, recovery]) => {
				if (cancelled) return;
				setBioStatus(bio);
				setRecoveryEnabled(recovery);
			})
			.catch(() => {
				/* silently degrade: probes are optional affordances */
			});
		return () => {
			cancelled = true;
		};
	}, []);

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();
		setLocalError(null);

		try {
			// A false return already wrote state.error ("Invalid password" or
			// the rate-limit message) inside AuthContext — showing it via
			// state.error avoids a local override that would mask lockout.
			await actions.unlock(password);
		} catch {
			setLocalError("Failed to unlock vault");
		} finally {
			setPassword("");
		}
	};

	// Touch ID unlock: success transitions to the vault through the shared
	// post-unlock path; BiometricCancelled (dismissed prompt) stays silent.
	const handleTouchId = async () => {
		setLocalError(null);
		await actions.unlockBiometric();
	};

	const showTouchId = !!bioStatus?.available && !!bioStatus?.enabled;
	const error = state.error || localError;

	return (
		<div className="auth-screen">
			<div className="auth-card">
				<div className="auth-badge" aria-hidden="true">
					<ShieldIcon />
				</div>
				<h1 className="auth-title">PwdVault</h1>
				<p className="auth-tagline">Local-first. Your passwords stay yours.</p>

				{error && (
					<div className="error-message" id="unlock-error" role="alert">
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
						ariaDescribedBy={error ? "unlock-error" : undefined}
					/>

					<button
						type="submit"
						className="auth-btn-primary"
						disabled={state.isLoading || !password}
					>
						{state.isLoading ? (
							<span className="loading">
								<span className="spinner" />
								Unlocking...
							</span>
						) : (
							"Unlock"
						)}
					</button>
				</form>

				{showTouchId && (
					<>
						<div className="auth-divider" aria-hidden="true">
							or
						</div>
						<button
							type="button"
							className="auth-btn-soft"
							onClick={() => void handleTouchId()}
							disabled={state.isLoading}
						>
							<FingerprintIcon />
							Use Touch ID
						</button>
					</>
				)}

				{recoveryEnabled && (
					<button
						type="button"
						className="auth-link"
						onClick={() => actions.navigate("recovery")}
					>
						Forgot password?
					</button>
				)}
			</div>

			{/* v1.7.0 recovery-key status hint. Pure display — the lock screen
			   has no settings route to navigate to. Rendered only after the
			   probe RESOLVES (null renders nothing): a transport failure must
			   not assert an unverified "no recovery key" fact, and an enabled
			   user never sees the warning flash before the confirm flips in. */}
			{recoveryEnabled === true && (
				<div className="auth-hint">
					<ShieldCheckIcon className="auth-hint-icon-accent" />
					<span>Recovery key enabled</span>
				</div>
			)}
			{recoveryEnabled === false && (
				<div className="auth-hint">
					<ShieldAlertIcon className="auth-hint-icon-warning" />
					<span>
						No recovery key set up — enable one in{" "}
						<strong>Settings → Security</strong> before you need it.
					</span>
				</div>
			)}
		</div>
	);
}
