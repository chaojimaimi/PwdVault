import { useEffect, useRef, useState } from "react";
import { useAuth, useSettings } from "../context/AppContext";
import { generatePassword } from "../api/vault";
import { copyWithTimeout } from "../utils/clipboard";
import { errorMessage } from "../utils/errorMessage";
import { showToast } from "../utils/toast";
import { BackHeader } from "../components/BackHeader";
import { StrengthMeter } from "../components/StrengthMeter";
import type {
	GeneratorMode,
	PasswordGeneratorOptions,
} from "../types";

/** Session-only generation history entry (v1.4.0): value + wall-clock time. */
interface HistoryItem {
	value: string;
	time: number;
}

const GENERATOR_MODES: Array<{ id: GeneratorMode; label: string }> = [
	{ id: "password", label: "Password" },
	{ id: "passphrase", label: "Passphrase" },
	{ id: "pin", label: "PIN" },
];

const PASSPHRASE_SEPARATORS = [
	{ label: "Hyphen (-)", value: "-" },
	{ label: "Space", value: " " },
	{ label: "Period (.)", value: "." },
	{ label: "Underscore (_)", value: "_" },
	{ label: "None", value: "" },
];

export function GeneratorScreen() {
	const { actions: authActions } = useAuth();
	const { state: settingsState } = useSettings();
	const [mode, setMode] = useState<GeneratorMode>("password");
	const [password, setPassword] = useState("");
	const [options, setOptions] = useState<PasswordGeneratorOptions>({
		length: settingsState.settings.default_length,
		includeUppercase: settingsState.settings.default_include_uppercase,
		includeLowercase: settingsState.settings.default_include_lowercase,
		includeNumbers: settingsState.settings.default_include_numbers,
		includeSymbols: settingsState.settings.default_include_symbols,
	});
	const [passphrase, setPassphrase] = useState({
		words: 6,
		separator: "-",
		capitalize: false,
		appendNumber: false,
	});
	const [pinLength, setPinLength] = useState(6);
	const [copied, setCopied] = useState(false);
	const [pending, setPending] = useState(false);
	// v1.4.0: last 10 generated values, SESSION-ONLY by design — persisting
	// generated secrets to disk would widen the attack surface (a new
	// unencrypted-at-rest surface next to the vault), while the session list
	// already covers the "find the password I just generated" use case.
	const [history, setHistory] = useState<HistoryItem[]>([]);
	// Guard: once the user edits an option, saved defaults must no longer
	// overwrite their choice.
	const touchedRef = useRef(false);
	// Mirrors `pending` for non-effect readers (the settings-resync effect
	// below) without adding it to that effect's dependencies.
	const pendingRef = useRef(pending);
	pendingRef.current = pending;
	// Mirrors `mode` for the resync effect without re-arming it on mode flips.
	const modeRef = useRef(mode);
	modeRef.current = mode;
	const hasCharset = (opts: PasswordGeneratorOptions) =>
		opts.includeUppercase ||
		opts.includeLowercase ||
		opts.includeNumbers ||
		opts.includeSymbols;
	const charsetValid = hasCharset(options);

	const buildRequest = (
		activeMode: GeneratorMode,
		overrides?: PasswordGeneratorOptions,
	): PasswordGeneratorOptions => {
		const base = overrides ?? options;
		if (activeMode === "passphrase") {
			return {
				...base,
				mode: "passphrase",
				words: passphrase.words,
				separator: passphrase.separator,
				capitalize: passphrase.capitalize,
				appendNumber: passphrase.appendNumber,
			};
		}
		if (activeMode === "pin") {
			return { ...base, length: pinLength, mode: "pin" };
		}
		return { ...base, mode: "password" };
	};

	// Serialization chain: a mode switch arriving while a generation is in
	// flight must be QUEUED, not dropped — the early-return-on-pending guard
	// the button uses would silently swallow it and leave a stale preview.
	const generationChain = useRef<Promise<void>>(Promise.resolve());

	const runGeneration = async (
		activeMode: GeneratorMode,
		overrides?: PasswordGeneratorOptions,
	) => {
		setPending(true);
		try {
			const pwd = await generatePassword(buildRequest(activeMode, overrides));
			setPassword(pwd);
			setCopied(false);
			setHistory((prev) =>
				[{ value: pwd, time: Date.now() }, ...prev].slice(0, 10),
			);
		} catch (error) {
			showToast(errorMessage(error, "Failed to generate password"));
		} finally {
			setPending(false);
		}
	};

	const handleGenerate = async (
		activeMode: GeneratorMode = mode,
		// The settings-resync path passes the freshly built options explicitly:
		// handleGenerate's closure still holds the pre-resync state in the same
		// event-loop tick (r2-P2 precedent).
		overrides?: PasswordGeneratorOptions,
	) => {
		if (activeMode === "password" && !hasCharset(overrides ?? options)) return;
		const run = () => runGeneration(activeMode, overrides);
		generationChain.current = generationChain.current.then(run, run);
		await generationChain.current;
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
	// while the user has not touched anything, resync the password options
	// once — and regenerate with them (r2-P2), so the displayed password is
	// not the one generated from the pre-load parameters. The identity check
	// keeps the already-loaded mount case from generating twice.
	// v1.4.0: regeneration only happens on the Password tab — settings carry
	// no passphrase/PIN defaults, so flipping those tabs keeps their options.
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
		if (!pendingRef.current && modeRef.current === "password") {
			void resyncGenerateRef.current("password", next);
		}
	}, [settingsState.status, settingsState.settings]);

	const handleModeChange = (next: GeneratorMode) => {
		setMode(next);
		void handleGenerate(next);
	};

	const handleCopy = async () => {
		await copyWithTimeout(password);
		setCopied(true);
		showToast("Password copied (auto-clears in 30s)");
		setTimeout(() => setCopied(false), 2000);
	};

	const handleHistoryCopy = async (value: string) => {
		await copyWithTimeout(value);
		showToast("Password copied (auto-clears in 30s)");
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
				<div className="mode-tabs" role="tablist" aria-label="Generator mode">
					{GENERATOR_MODES.map((m) => (
						<button
							key={m.id}
							type="button"
							role="tab"
							aria-selected={mode === m.id}
							className={`mode-tab ${mode === m.id ? "active" : ""}`}
							onClick={() => handleModeChange(m.id)}
						>
							{m.label}
						</button>
					))}
				</div>

				<div className="password-preview">{password || "Generating..."}</div>
				<StrengthMeter password={password} mode={mode} generatorParams={{
					words: passphrase.words,
					appendNumber: passphrase.appendNumber,
					length: mode === "pin" ? pinLength : options.length,
				}} />

				{mode === "password" && (
					<>
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
					</>
				)}

				{mode === "passphrase" && (
					<>
						<div className="option-group">
							<div className="option-row">
								<label htmlFor="gen-words">Words: {passphrase.words}</label>
							</div>
							<div className="length-control">
								<input
									id="gen-words"
									type="range"
									min="3"
									max="10"
									value={passphrase.words}
									aria-label="Passphrase word count"
									aria-valuemin={3}
									aria-valuemax={10}
									aria-valuenow={passphrase.words}
									onChange={(e) =>
										setPassphrase({
											...passphrase,
											words: parseInt(e.target.value),
										})
									}
								/>
							</div>
							<div className="option-row">
								<label htmlFor="gen-separator">Separator</label>
								<select
									id="gen-separator"
									className="settings-select"
									value={passphrase.separator}
									onChange={(e) =>
										setPassphrase({
											...passphrase,
											separator: e.target.value,
										})
									}
								>
									{PASSPHRASE_SEPARATORS.map((sep) => (
										<option key={sep.value} value={sep.value}>
											{sep.label}
										</option>
									))}
								</select>
							</div>
							<div className="option-row">
								<label htmlFor="gen-capitalize">Capitalize words</label>
								<input
									id="gen-capitalize"
									type="checkbox"
									className="checkbox"
									checked={passphrase.capitalize}
									onChange={(e) =>
										setPassphrase({
											...passphrase,
											capitalize: e.target.checked,
										})
									}
								/>
							</div>
							<div className="option-row">
								<label htmlFor="gen-append-number">Append number (0-99)</label>
								<input
									id="gen-append-number"
									type="checkbox"
									className="checkbox"
									checked={passphrase.appendNumber}
									onChange={(e) =>
										setPassphrase({
											...passphrase,
											appendNumber: e.target.checked,
										})
									}
								/>
							</div>
						</div>
					</>
				)}

				{mode === "pin" && (
					<div className="option-group">
						<div className="option-row">
							<label htmlFor="gen-pin-length">
								PIN length: {pinLength}
							</label>
						</div>
						<div className="length-control">
							<input
								id="gen-pin-length"
								type="range"
								min="4"
								max="16"
								value={pinLength}
								aria-label="PIN length"
								aria-valuemin={4}
								aria-valuemax={16}
								aria-valuenow={pinLength}
								onChange={(e) => setPinLength(parseInt(e.target.value))}
							/>
						</div>
					</div>
				)}

				<button
					className="btn btn-secondary btn-block"
					// handleGenerate takes the active mode explicitly — never let
					// the click event slip in as that argument.
					onClick={() => void handleGenerate()}
					disabled={pending || (mode === "password" && !charsetValid)}
				>
					{pending ? "Generating…" : "Generate New Password"}
				</button>

				{history.length > 0 && (
					<div className="option-group generator-history">
						<h3 className="settings-section-title">Session history</h3>
						<ul className="history-list">
							{history.map((item) => (
								<li key={`${item.time}-${item.value}`}>
									<button
										type="button"
										className="history-item"
										title="Copy to clipboard"
										onClick={() => void handleHistoryCopy(item.value)}
									>
										<span className="history-value">{item.value}</span>
										<span className="history-time">
											{new Date(item.time).toLocaleTimeString()}
										</span>
									</button>
								</li>
							))}
						</ul>
						<p className="settings-hint">
							Kept in memory for this session only — never written to disk.
						</p>
					</div>
				)}
			</div>

			<div className="generator-actions">
				<button
					className="btn btn-primary btn-block"
					onClick={handleCopy}
					disabled={!password}
				>
					{copied ? "Copied!" : "Copy to Clipboard"}
				</button>
			</div>
		</div>
	);
}
