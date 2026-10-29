import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { AppProvider, useAuth } from "./context/AppContext";
import { useSettings } from "./context/SettingsContext";
import { touchActivity } from "./api/vault";
import { SetupScreen } from "./screens/SetupScreen";
import { UnlockScreen } from "./screens/UnlockScreen";
import { RecoveryScreen } from "./screens/RecoveryScreen";
import { VaultScreen } from "./screens/VaultScreen";
import { EntryScreen } from "./screens/EntryScreen";
import { GeneratorScreen } from "./screens/GeneratorScreen";
import GroupManager from "./screens/GroupManager";
import { SettingsScreen } from "./screens/SettingsScreen";
import { ImportExportScreen } from "./screens/ImportExportScreen";
import { DashboardScreen } from "./screens/DashboardScreen";
import { ThemeProvider } from "./components/ThemeProvider";
import { showPairingCodeToast, showToastWithType } from "./utils/toast";
import "./styles/themes.css";
import "./styles/base.css";
import "./styles/components.css";
// v1.7.0 WP4: auth screens (Setup/Unlock/Recovery) — must load after
// components.css so the .auth-* overrides win the cascade.
import "./styles/auth.css";
import "./styles/screens.css";
import "./styles/vault.css";
import "./styles/groups.css";
import "./styles/settings.css";

// A1: report user activity to the backend auto-lock timer so that reading or
// editing locally (no vault operations) keeps the session alive. The throttle
// is derived from the configured timeout in useAutoLockActivity — a fixed
// value would race the lock thread at short timeouts.
const MAX_ACTIVITY_THROTTLE_MS = 60_000;

/**
 * Forward pointer/keyboard activity to `touch_activity` while the vault is
 * unlocked. Reports at most once per `min(60s, autoLockSecs / 2)` so a report
 * window always opens strictly before the lock deadline can fire, even at the
 * shortest configured timeouts. Listeners are capture+passive (never block or
 * reorder page handling) and are removed as soon as the vault locks. Exported
 * for tests.
 */
export function useAutoLockActivity(enabled: boolean, autoLockSecs: number) {
	const lastReportRef = useRef(0);

	useEffect(() => {
		if (!enabled) return;
		const throttleMs = Math.max(
			5_000,
			Math.min(MAX_ACTIVITY_THROTTLE_MS, autoLockSecs * 500),
		);
		const reportActivity = () => {
			const now = Date.now();
			if (now - lastReportRef.current < throttleMs) return;
			lastReportRef.current = now;
			// Failures are expected right after a lock (vault no longer
			// unlocked) and must never surface as user-visible errors.
			touchActivity().catch(() => {});
		};
		const options: AddEventListenerOptions = { capture: true, passive: true };
		window.addEventListener("pointermove", reportActivity, options);
		window.addEventListener("pointerdown", reportActivity, options);
		window.addEventListener("keydown", reportActivity, options);
		return () => {
			window.removeEventListener("pointermove", reportActivity, options);
			window.removeEventListener("pointerdown", reportActivity, options);
			window.removeEventListener("keydown", reportActivity, options);
		};
	}, [enabled, autoLockSecs]);
}

function AppContent() {
	// AppContent subscribes to AuthContext (§5.6.1): screen routing depends
	// solely on auth state. The single SettingsContext read below feeds only
	// the auto-lock activity throttle period; screens pull vault/settings
	// directly.
	const { state, actions } = useAuth();
	const { state: settingsState } = useSettings();

	// A1: keep the auto-lock timer alive on local user input while unlocked.
	useAutoLockActivity(state.isUnlocked, settingsState.settings.auto_lock_secs);

	// v1.4.0 (WP5): the Rust-side global shortcut shows + focuses the window
	// and emits this event; while the vault is unlocked we complete the
	// action by routing to the vault screen and focusing the search input.
	// The listener is only armed while unlocked — before unlock, the
	// show+focus from Rust already lands the user on the unlock screen.
	useEffect(() => {
		if (!state.isUnlocked) return;
		let unlisten: (() => void) | undefined;
		let disposed = false;
		listen("global-shortcut-vault", () => {
			actions.navigate("vault");
			// Wait one frame so the vault screen (and its search input) exists.
			requestAnimationFrame(() => {
				document.querySelector<HTMLInputElement>(".search-input")?.focus();
			});
		}).then((stop) => {
			if (disposed) stop();
			else unlisten = stop;
		});
		return () => {
			disposed = true;
			unlisten?.();
		};
	}, [state.isUnlocked, actions]);

	if (state.isLoading) {
		return (
			<div className="screen">
				<div className="loading">
					<span className="spinner" />
					<span>Loading...</span>
				</div>
			</div>
		);
	}

	if (state.bootError) {
		return (
			<div className="screen">
				<div className="fatal-error" role="alert">
					<h1>PwdVault could not start</h1>
					<p>{state.bootError}</p>
					<button
						className="btn btn-primary btn-block"
						onClick={() => void actions.retryBoot()}
					>
						Retry
					</button>
				</div>
			</div>
		);
	}

	switch (state.screen) {
		case "setup":
			return <SetupScreen />;
		case "unlock":
			return <UnlockScreen />;
		case "recovery":
			return <RecoveryScreen />;
		case "vault":
			return <VaultScreen />;
		case "entry":
			return <EntryScreen />;
		case "generator":
			return <GeneratorScreen />;
		case "groupManager":
			return <GroupManager />;
		case "settings":
			return <SettingsScreen />;
		case "importExport":
			return <ImportExportScreen />;
		case "dashboard":
			return <DashboardScreen />;
		default:
			return <UnlockScreen />;
	}
}

/**
 * Native-event toasts (v1.5.0): the pairing-code toast, the trash
 * auto-purged notice, and the native-server-error warning. Extracted from
 * App's inline effect so tests can mount the hook against a mocked `listen`
 * (same pattern as useAutoLockActivity above). The listeners are global and
 * lifetime-of-app — they must not depend on auth state, because pairing and
 * the extension bridge exist before any unlock.
 */
export function useNativeEventToasts() {
	useEffect(() => {
		// Show the pairing code as a non-blocking toast. A modal dialog would
		// block subsequent pair-request events (each one creates a new session
		// and overwrites the previous code), making "Get New Code" in the
		// extension appear to do nothing until the user dismisses the dialog.
		// Toasts let multiple updates show in sequence without blocking.
		// WP5: the payload is { code, caller } — the caller digest gives the
		// user a comparison aid (forgeable on loopback, NOT authentication).
		const unlistenPair = listen("pair-request", (event) => {
			const payload = event.payload as { code: string; caller?: string };
			// V4 双主题配对码 toast：30s 与后端 SESSION_TTL 保持一致，
			// 确保用户看到的码在有效期内。
			showPairingCodeToast(payload.code, 30000, payload.caller);
		});

		// WP3 (v1.5.0): the Rust post-unlock sweep physically deleted expired
		// recycle-bin entries; the count arrives as the event payload
		// (never emitted for 0).
		const unlistenTrashPurge = listen<number>("trash-auto-purged", (event) => {
			showToastWithType(`回收站自动清理了 ${event.payload} 条`, "info");
		});

		// B3: warn loudly when the extension HTTP server could not start.
		// Long-lived toast (10s) — the user must restart the app after
		// freeing the port; there is no automatic retry by design.
		const unlistenServerError = listen<string>(
			"native-server-error",
			(event) => {
				showToastWithType(
					`${event.payload}. Please restart PwdVault.`,
					"error",
					10000,
				);
			},
		);
		return () => {
			unlistenPair.then((u) => u());
			unlistenTrashPurge.then((u) => u());
			unlistenServerError.then((u) => u());
		};
	}, []);
}

function App() {
	useNativeEventToasts();

	return (
		<ThemeProvider>
			<AppProvider>
				<AppContent />
			</AppProvider>
		</ThemeProvider>
	);
}

export default App;
