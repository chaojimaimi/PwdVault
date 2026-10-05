import { Component, type ErrorInfo, type ReactNode } from "react";
import { relaunch } from "@tauri-apps/plugin-process";

interface ErrorBoundaryProps {
	children: ReactNode;
}

interface ErrorBoundaryState {
	hasError: boolean;
	message: string;
	componentStack: string | null;
	copied: boolean;
}

/**
 * SF-P2b (v1.1.9): last-resort crash guard around the whole app. A render
 * error anywhere used to blank the window with no way out; the fallback now
 * explains the state and offers a relaunch — the process restart is
 * equivalent to locking the vault (keys live only in memory) — plus a
 * best-effort copy of the error details for bug reports.
 */
export class ErrorBoundary extends Component<
	ErrorBoundaryProps,
	ErrorBoundaryState
> {
	state: ErrorBoundaryState = {
		hasError: false,
		message: "",
		componentStack: null,
		copied: false,
	};

	static getDerivedStateFromError(
		error: unknown,
	): Partial<ErrorBoundaryState> {
		return {
			hasError: true,
			message: error instanceof Error ? error.message : String(error),
		};
	}

	componentDidCatch(error: unknown, info: ErrorInfo): void {
		// Full details go to the devtools console; the fallback UI keeps the
		// message + component stack for the copy button.
		console.error(
			"Unhandled error caught by ErrorBoundary:",
			error,
			info.componentStack,
		);
		this.setState({ componentStack: info.componentStack ?? null });
	}

	handleRelaunch = (): void => {
		void relaunch();
	};

	handleCopyDetails = async (): Promise<void> => {
		const { message, componentStack } = this.state;
		const details = [
			"PwdVault crashed with an unhandled error:",
			message,
			componentStack,
		]
			.filter((part) => part && part.trim())
			.join("\n\n");
		try {
			// Best effort: the clipboard API may be unavailable in restricted
			// contexts — the error text stays on screen for manual selection.
			await navigator.clipboard.writeText(details);
			this.setState({ copied: true });
		} catch {
			/* ignore — copy is a convenience, never a hard requirement */
		}
	};

	render(): ReactNode {
		if (!this.state.hasError) {
			return this.props.children;
		}
		return (
			<div
				role="alert"
				style={{
					minHeight: "100vh",
					display: "flex",
					flexDirection: "column",
					alignItems: "center",
					justifyContent: "center",
					gap: "var(--space-lg)",
					padding: "var(--space-xl)",
					background: "var(--color-bg)",
					color: "var(--color-text)",
					textAlign: "center",
				}}
			>
				<h1 style={{ fontSize: "var(--text-h1)", margin: 0 }}>
					Something went wrong
				</h1>
				<p
					style={{
						margin: 0,
						maxWidth: "480px",
						color: "var(--color-text-secondary)",
					}}
				>
					An unexpected error occurred and the application cannot continue.
					Restarting the app also locks the vault.
				</p>
				{this.state.message && (
					<pre
						style={{
							maxWidth: "560px",
							maxHeight: "180px",
							overflow: "auto",
							margin: 0,
							padding: "var(--space-md)",
							border: "1px solid var(--color-border)",
							borderRadius: "var(--radius-md)",
							background: "var(--color-input)",
							color: "var(--color-text-secondary)",
							fontSize: "var(--text-label)",
							whiteSpace: "pre-wrap",
							wordBreak: "break-word",
							textAlign: "left",
						}}
					>
						{this.state.message}
					</pre>
				)}
				<div
					style={{
						display: "flex",
						gap: "var(--space-sm)",
						width: "340px",
						maxWidth: "100%",
					}}
				>
					<button
						type="button"
						className="btn btn-primary"
						onClick={this.handleRelaunch}
					>
						Restart App
					</button>
					<button
						type="button"
						className="btn btn-secondary"
						onClick={() => void this.handleCopyDetails()}
					>
						{this.state.copied ? "Copied" : "Copy Error Details"}
					</button>
				</div>
			</div>
		);
	}
}
