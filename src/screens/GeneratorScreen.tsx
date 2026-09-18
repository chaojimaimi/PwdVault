import { useState, useEffect, useRef } from "react";
import { useAuth, useSettings } from "../context/AppContext";
import { generatePassword } from "../api/vault";
import { copyWithTimeout } from "../utils/clipboard";
import { showToast } from "../utils/toast";
import { BackHeader } from "../components/BackHeader";
import { StrengthMeter } from "../components/StrengthMeter";
import type { PasswordGeneratorOptions } from "../types";

export function GeneratorScreen() {
	const { actions: authActions } = useAuth();
	const { state: settingsState } = useSettings();
	const [password, setPassword] = useState("");
	const [options, setOptions] = useState<PasswordGeneratorOptions>({
		length: settingsState.settings.default_length,
		includeUppercase: settingsState.settings.default_include_uppercase,
		includeLowercase: settingsState.settings.default_include_lowercase,
		includeNumbers: settingsState.settings.default_include_numbers,
		includeSymbols: settingsState.settings.default_include_symbols,
	});
	const [copied, setCopied] = useState(false);
	const [pending, setPending] = useState(false);
	// Guard: once the user edits an option, saved defaults must no longer
	// overwrite their choice.
	const touchedRef = useRef(false);
	// Mirrors `pending` for non-effect readers (the settings-resync effect
	// below) without adding it to that effect's dependencies.
	const pendingRef = useRef(pending);
	pendingRef.current = pending;
	const hasCharset = (opts: PasswordGeneratorOptions) =>
		opts.includeUppercase ||
		opts.includeLowercase ||
		opts.includeNumbers ||
		opts.includeSymbols;
	const charsetValid = hasCharset(options);

	const handleGenerate = async (overrides?: PasswordGeneratorOptions) => {
		const opts = overrides ?? options;
		if (!hasCharset(opts) || pending) return;
		setPending(true);
		try {
			const pwd = await generatePassword(opts);
			setPassword(pwd);
			setCopied(false);
		} catch (error) {
			showToast(
				error instanceof Error ? error.message : "Failed to generate password",
			);
		} finally {
			setPending(false);
		}
	};

	// H4: latestRef pattern — generation must stay mount-only; adding
	// handleGenerate (recreated per render, closes over options) to the deps
	// would auto-regenerate on every option toggle.
	const mountGenerateRef = useRef(handleGenerate);
	mountGenerateRef.current = handleGenerate;
	useEffect(() => {
		void mountGenerateRef.current();
	}, []);

	// E16: settings may finish loading AFTER this screen mounts (the useState
	// snapshot above can still hold DEFAULT_SETTINGS). When the load lands
	// while the user has not touched anything, resync the options once — and
	// regenerate with them (r2-P2), so the displayed password is not the one
	// generated from the pre-load parameters. The identity check keeps the
	// already-loaded mount case from generating twice.
	const lastLoadedSettingsRef = useRef(settingsState.settings);
	const resyncGenerateRef = useRef(handleGenerate);
	resyncGenerateRef.current = handleGenerate;
	useEffect(() => {
		if (settingsState.status !== "success") return;
		if (touchedRef.current) return;
		if (settingsState.settings === lastLoadedSettingsRef.current) return;
		lastLoadedSettingsRef.current = settingsState.settings;
		const next: PasswordGeneratorOptions = {
			length: settingsState.settings.default_length,
			includeUppercase: settingsState.settings.default_include_uppercase,
			includeLowercase: settingsState.settings.default_include_lowercase,
			includeNumbers: settingsState.settings.default_include_numbers,
			includeSymbols: settingsState.settings.default_include_symbols,
		};
		setOptions(next);
		if (!pendingRef.current) void resyncGenerateRef.current(next);
	}, [settingsState.status, settingsState.settings]);

	const handleCopy = async () => {
		await copyWithTimeout(password);
		setCopied(true);
		showToast("Password copied (auto-clears in 30s)");
		setTimeout(() => setCopied(false), 2000);
	};

	const handleBack = () => {
		authActions.navigate("vault");
	};

	const handleOptionChange = (
		key: keyof PasswordGeneratorOptions,
		value: boolean | number,
	) => {
		touchedRef.current = true;
		setOptions({ ...options, [key]: value });
	};

	return (
		<div className="generator-screen screen-shell">
			<BackHeader title="Password Generator" onBack={handleBack} />

			<div className="generator-content screen-scroll-region">
				<div className="password-preview">{password || "Generating..."}</div>
				<StrengthMeter password={password} />

				<div className="option-group">
					<div className="option-row">
						<label htmlFor="gen-length">Length: {options.length}</label>
					</div>
					<div className="length-control">
						<input
							id="gen-length"
							type="range"
							min="8"
							max="64"
							value={options.length}
							aria-label="Password length"
							aria-valuemin={8}
							aria-valuemax={64}
							aria-valuenow={options.length}
							onChange={(e) =>
								handleOptionChange("length", parseInt(e.target.value))
							}
						/>
					</div>
				</div>

				<div className="option-group">
					<div className="option-row">
						<label htmlFor="gen-upper">Uppercase (A-Z)</label>
						<input
							id="gen-upper"
							type="checkbox"
							className="checkbox"
							checked={options.includeUppercase}
							onChange={(e) =>
								handleOptionChange("includeUppercase", e.target.checked)
							}
						/>
					</div>

					<div className="option-row">
						<label htmlFor="gen-lower">Lowercase (a-z)</label>
						<input
							id="gen-lower"
							type="checkbox"
							className="checkbox"
							checked={options.includeLowercase}
							onChange={(e) =>
								handleOptionChange("includeLowercase", e.target.checked)
							}
						/>
					</div>

					<div className="option-row">
						<label htmlFor="gen-numbers">Numbers (0-9)</label>
						<input
							id="gen-numbers"
							type="checkbox"
							className="checkbox"
							checked={options.includeNumbers}
							onChange={(e) =>
								handleOptionChange("includeNumbers", e.target.checked)
							}
						/>
					</div>

					<div className="option-row">
						<label htmlFor="gen-symbols">Symbols (!@#$...)</label>
						<input
							id="gen-symbols"
							type="checkbox"
							className="checkbox"
							checked={options.includeSymbols}
							onChange={(e) =>
								handleOptionChange("includeSymbols", e.target.checked)
							}
						/>
					</div>
				</div>

				{!charsetValid && (
					<p className="error-message" role="alert">
						Select at least one character set.
					</p>
				)}

				<button
					className="btn btn-secondary"
					// handleGenerate now takes an optional options override — never
					// let the click event slip in as that argument.
					onClick={() => void handleGenerate()}
					disabled={!charsetValid || pending}
				>
					{pending ? "Generating…" : "Generate New Password"}
				</button>
			</div>

			<div className="generator-actions">
				<button
					className="btn btn-primary"
					onClick={handleCopy}
					disabled={!password}
				>
					{copied ? "Copied!" : "Copy to Clipboard"}
				</button>
			</div>
		</div>
	);
}
