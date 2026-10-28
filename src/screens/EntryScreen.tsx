import { useState, useEffect, useMemo } from "react";
import { useAuth, useSettings, useVault } from "../context/AppContext";
import { copyWithTimeout } from "../utils/clipboard";
import { errorMessage } from "../utils/errorMessage";
import { showToast } from "../utils/toast";
import {
	normalizeMatchMode,
	URL_MATCH_MODE_OPTIONS,
} from "../utils/urlMatchMode";
import { BackHeader } from "../components/BackHeader";
import { StrengthMeter } from "../components/StrengthMeter";
import { sameTags, TagsEditor } from "../components/TagsEditor";
import { TotpSecretField } from "../components/TotpSecretField";
import { EntryGeneratorModal } from "../components/EntryGeneratorModal";
import {
	CustomFieldsEditor,
	filterEmptyRows,
	stripCustomFieldRowIds,
} from "../components/CustomFieldsEditor";
import { useCustomFields } from "./useCustomFields";
// v1.6.1 F6: the save-confirmation diff lives in its own module (verbatim
// extraction for the line-count budget) — consumers import from there.
import { detectChanges } from "./entryChanges";
import {
	EyeIcon,
	EyeOffIcon,
	CopyIcon,
	GenerateIcon,
} from "../components/Icons";
import ConfirmationModal, { ChangeItem } from "../components/ConfirmationModal";
import DeleteConfirmModal from "../components/DeleteConfirmModal";
import GroupSelector from "../components/GroupSelector";
import { UnsavedChangesModal } from "../components/UnsavedChangesModal";
import type {
	CreateEntryRequest,
	UpdateEntryRequest,
	UrlMatchMode,
} from "../types";

export function EntryScreen() {
	const { actions: authActions } = useAuth();
	const { state, actions } = useVault();
	// A5: the quick generator must honour the user's saved generator
	// defaults (same source as GeneratorScreen), not hardcoded values.
	const { state: settingsState } = useSettings();
	const isEditing = !!state.selectedEntry?.id;
	const isNew = !state.selectedEntry;

	const [formData, setFormData] = useState<CreateEntryRequest>({
		title: "",
		url: "",
		username: "",
		password: "",
		notes: "",
		tags: [],
		group_id: null,
		url_match_mode: "auto",
	});
	const [originalSecret, setOriginalSecret] = useState<{
		password: string;
		notes: string;
	} | null>(null);
	const [passwordChanged, setPasswordChanged] = useState(false);
	const [notesLoaded, setNotesLoaded] = useState(false);
	const [notesChanged, setNotesChanged] = useState(false);
	// TOTP tri-state bookkeeping (untouched / cleared / set — same update
	// semantics as update_notes); the field itself renders in TotpSecretField.
	const [totpSecret, setTotpSecret] = useState("");
	const [totpChanged, setTotpChanged] = useState(false);
	// TOTP secrets are paste-only (no on-demand fetch like the password
	// field), so the toggle is a plain visibility switch that never exposes
	// the value by default.
	const [showTotpSecret, setShowTotpSecret] = useState(false);
	const [secretLoading, setSecretLoading] = useState(false);
	// v1.6.0: custom-field rows + secret-channel loading + the save-time
	// guarded fetch live in useCustomFields (contract documented there).
	const {
		customFields,
		setCustomFields,
		mergeLoadedCustomFields,
		hasContentRows,
		dirtyFromStored,
		loadValues,
		resolveForSave,
		patchFragment,
	} = useCustomFields({
		selectedEntry: state.selectedEntry,
		fetchSecret: async (id) => {
			const secret = await actions.getEntrySecret(id);
			if (!secret) throw new Error("Empty secret response");
			return secret;
		},
		onFetchFailed: () => setError("Failed to load custom fields"),
		setSecretLoading,
	});
	const [showPassword, setShowPassword] = useState(false);
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [showGenerator, setShowGenerator] = useState(false);
	const [showConfirmation, setShowConfirmation] = useState(false);
	const [pendingChanges, setPendingChanges] =
		useState<UpdateEntryRequest | null>(null);
	const [changesList, setChangesList] = useState<ChangeItem[]>([]);
	const [isSavingConfirmed, setIsSavingConfirmed] = useState(false);
	const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
	const [showUnsaved, setShowUnsaved] = useState(false);

	useEffect(() => {
		if (state.selectedEntry) {
			// Fill non-sensitive metadata immediately; secrets are fetched on demand
			// and kept only in this component's state while the user is on this screen.
			setFormData({
				title: state.selectedEntry.title,
				url: state.selectedEntry.url || "",
				username: state.selectedEntry.username,
				password: "",
				notes: "",
				tags: state.selectedEntry.tags,
				group_id: state.selectedEntry.group_id || null,
				// Absent on pre-v1.5.0 summaries → reads as "auto" (serde default).
				url_match_mode: normalizeMatchMode(state.selectedEntry.url_match_mode),
			});
			setOriginalSecret(null);
			setPasswordChanged(false);
			setNotesLoaded(false);
			setNotesChanged(false);
			setTotpSecret("");
			setTotpChanged(false);
			setShowTotpSecret(false);
		} else {
			setFormData({
				title: "",
				url: "",
				username: "",
				password: "",
				notes: "",
				tags: [],
				group_id: null,
				url_match_mode: "auto",
			});
			setOriginalSecret(null);
			setPasswordChanged(false);
			setNotesLoaded(true);
			setNotesChanged(false);
			setTotpSecret("");
			setTotpChanged(false);
			setShowTotpSecret(false);
		}
	}, [state.selectedEntry]);

	const metadataDirty = useMemo(() => {
		if (!state.selectedEntry) {
			return Boolean(
				formData.title ||
					formData.url ||
					formData.username ||
					formData.password ||
					formData.notes ||
					formData.tags.length ||
					formData.group_id ||
					// A non-default match override is unsaved content on a new entry.
					normalizeMatchMode(formData.url_match_mode) !== "auto" ||
					// v1.6.0: any row with content is unsaved content (blank rows
					// are dropped before the request); see useCustomFields.
					hasContentRows,
			);
		}
		return (
			state.selectedEntry.title !== formData.title ||
			(state.selectedEntry.url || "") !== (formData.url || "") ||
			normalizeMatchMode(state.selectedEntry.url_match_mode) !==
				normalizeMatchMode(formData.url_match_mode) ||
			state.selectedEntry.username !== formData.username ||
			!sameTags(state.selectedEntry.tags || [], formData.tags) ||
			(state.selectedEntry.group_id || null) !== (formData.group_id || null) ||
			// v1.6.0: the hook compares against the loaded values once the
			// secret channel has run, meta rows before — untouched rows stay
			// clean either way.
			dirtyFromStored
		);
	}, [formData, hasContentRows, dirtyFromStored, state.selectedEntry]);
	const isDirty =
		metadataDirty || passwordChanged || notesChanged || totpChanged;

	useEffect(() => {
		const warn = (event: BeforeUnloadEvent) => {
			if (!isDirty) return;
			event.preventDefault();
		};
		window.addEventListener("beforeunload", warn);
		return () => window.removeEventListener("beforeunload", warn);
	}, [isDirty]);

	const handleBack = () => {
		if (isDirty) {
			setShowUnsaved(true);
			return;
		}
		leaveEntry();
	};

	const leaveEntry = () => {
		actions.selectEntry(null);
		authActions.navigate("vault");
	};

	const handleSave = async () => {
		if (isLoading || isSavingConfirmed) return;
		if (
			!formData.title ||
			!formData.username ||
			(isNew && !formData.password)
		) {
			setError(
				isNew
					? "Title, username, and password are required"
					: "Title and username are required",
			);
			return;
		}
		setError(null);

		if (isNew) {
			setIsLoading(true);
			try {
				// Create always carries the rows; blank rows dropped, and the
				// UI-internal row id stripped at this IPC boundary.
				await actions.createEntry({
					...formData,
					custom_fields: stripCustomFieldRowIds(
						filterEmptyRows(customFields),
					),
				});
				leaveEntry();
			} catch (e: unknown) {
				setError(errorMessage(e, "Failed to create entry"));
			} finally {
				setIsLoading(false);
			}
			return;
		}

		if (!state.selectedEntry) return;

		// Rows + diff baseline resolution incl. the one guarded secret fetch
		// (empty-box wipe protection; contract in the hook). The no-fetch
		// path resolves synchronously (the modal opens same-tick); the fetch
		// path holds the create path's re-entry lock (guard + button state
		// ride isLoading).
		const resolution = resolveForSave();
		let resolved = resolution;
		if (resolved instanceof Promise) {
			setIsLoading(true);
			resolved = await resolved.finally(() => setIsLoading(false));
		}
		if (!resolved) return; // fetch failed; the hook reported the error
		const { rows: currentRows, baseline: customBaseline } = resolved;

		const currentForm: CreateEntryRequest = {
			...formData,
			custom_fields: currentRows,
		};
		const changes = detectChanges(
			state.selectedEntry,
			originalSecret,
			currentForm,
			passwordChanged,
			notesChanged,
			totpChanged,
			customBaseline,
		);
		if (changes.length === 0) {
			leaveEntry();
			return;
		}

		setPendingChanges({
			title: formData.title,
			url: formData.url,
			username: formData.username,
			...(passwordChanged ? { password: formData.password } : {}),
			...(notesChanged ? { notes: formData.notes || undefined } : {}),
			update_notes: notesChanged,
			tags: formData.tags,
			group_id: formData.group_id,
			// v1.5.0: replaced wholesale with every update (metadata semantics).
			url_match_mode: normalizeMatchMode(formData.url_match_mode),
			// TOTP tri-state: omit when untouched, "" clears, value sets.
			...(totpChanged ? { totp_secret: totpSecret.trim() } : {}),
			...patchFragment(customBaseline, currentRows),
		});
		setChangesList(changes);
		setShowConfirmation(true);
	};

	const handleDelete = () => {
		if (!state.selectedEntry) return;
		setShowDeleteConfirm(true);
	};

	const onConfirmDelete = async () => {
		if (!state.selectedEntry) return;
		setIsLoading(true);
		try {
			await actions.deleteEntry(state.selectedEntry.id);
			setShowDeleteConfirm(false);
			leaveEntry();
		} catch {
			setError("Failed to delete entry");
		} finally {
			setIsLoading(false);
		}
	};

	const onConfirmSave = async () => {
		if (!pendingChanges || !state.selectedEntry) return;
		setIsSavingConfirmed(true);
		try {
			await actions.updateEntry(state.selectedEntry.id, pendingChanges);
			setShowConfirmation(false);
			leaveEntry();
		} catch (e: unknown) {
			setError(errorMessage(e, "Failed to save entry"));
		} finally {
			setIsSavingConfirmed(false);
		}
	};

	// The generation call itself lives in EntryGeneratorModal (WP5 split);
	// this closes the loop: insert into the form and dismiss.
	const handleUseGenerated = (password: string) => {
		setFormData({ ...formData, password });
		setPasswordChanged(true);
		setShowGenerator(false);
	};

	const handleCopyPassword = async () => {
		let password = passwordChanged || isNew ? formData.password : "";
		if (state.selectedEntry && !passwordChanged) {
			try {
				const secret = await actions.getEntrySecret(state.selectedEntry.id);
				password = secret?.password || "";
			} catch {
				setError("Failed to copy password");
				return;
			}
		}
		if (!password) return;
		await copyWithTimeout(password);
		showToast("Password copied (auto-clears in 30s)");
	};

	const handleTogglePassword = async () => {
		if (showPassword) {
			setShowPassword(false);
			if (!passwordChanged && isEditing)
				setFormData((prev) => ({ ...prev, password: "" }));
			return;
		}
		if (
			isEditing &&
			!passwordChanged &&
			!formData.password &&
			state.selectedEntry
		) {
			setSecretLoading(true);
			try {
				const secret = await actions.getEntrySecret(state.selectedEntry.id);
				if (!secret) throw new Error("Empty secret response");
				setFormData((prev) => ({ ...prev, password: secret.password }));
				setOriginalSecret({
					password: secret.password,
					notes: originalSecret?.notes || "",
				});
				mergeLoadedCustomFields(secret);
			} catch {
				setError("Failed to reveal password");
				return;
			} finally {
				setSecretLoading(false);
			}
		}
		setShowPassword(true);
	};

	const handleLoadNotes = async () => {
		if (!state.selectedEntry || notesLoaded || secretLoading) return;
		setSecretLoading(true);
		try {
			const secret = await actions.getEntrySecret(state.selectedEntry.id);
			if (!secret) throw new Error("Empty secret response");
			const notes = secret.notes || "";
			setFormData((prev) => ({ ...prev, notes }));
			setOriginalSecret({ password: originalSecret?.password || "", notes });
			mergeLoadedCustomFields(secret);
			setNotesLoaded(true);
		} catch {
			setError("Failed to load notes");
		} finally {
			setSecretLoading(false);
		}
	};

	return (
		<div className="entry-screen screen-shell">
			<BackHeader
				title={isNew ? "New Password" : "Edit Password"}
				onBack={handleBack}
				headerClass="entry-header"
			/>

			{/* Form semantics (v1.3.2): the content area is a form so Enter in a
			    text field submits the entry. The Save button lives OUTSIDE the
			    form (in .entry-actions) and is associated via the form attribute —
			    a type="submit" there would not reach this form. onSubmit always
			    preventDefaults: the SPA owns navigation. */}
			<form
				id="pwdvault-entry-form"
				className="entry-content screen-scroll-region"
				onSubmit={(e) => {
					e.preventDefault();
					void handleSave();
				}}
			>
				{/* v1.6.1 F1: while the confirmation modal is open the error is
				    shown INSIDE the modal (its own error channel); after Cancel it
				    falls back to this banner. Never both at once. */}
				{error && !showConfirmation && (
					<div className="error-message" id="entry-error" role="alert">
						{error}
					</div>
				)}

				<div className="form-group">
					<label htmlFor="entry-title">Title *</label>
					<input
						id="entry-title"
						type="text"
						className="form-input"
						value={formData.title}
						onChange={(e) =>
							setFormData({ ...formData, title: e.target.value })
						}
						placeholder="e.g., Google, GitHub"
						aria-required="true"
						aria-invalid={!!error && !formData.title}
						/* v1.6.1 F1: the banner is suppressed while the modal is
						   open — never reference a node that is not rendered
						   (same condition on the two other secret inputs below). */
						aria-describedby={
							error && !showConfirmation ? "entry-error" : undefined
						}
					/>
				</div>

				<div className="form-group">
					<label htmlFor="entry-url">URL</label>
					<input
						id="entry-url"
						type="url"
						className="form-input"
						value={formData.url}
						onChange={(e) => setFormData({ ...formData, url: e.target.value })}
						placeholder="https://example.com"
					/>
					{/* v1.5.0 WP4: per-entry autofill match override. The label
					    references the visible option text (no aria-label), and the
					    hint is programmatically associated so screen readers get the
					    explanation with the control. */}
					<label htmlFor="entry-url-match-mode">Browser autofill matches</label>
					<select
						id="entry-url-match-mode"
						className="form-input"
						value={normalizeMatchMode(formData.url_match_mode)}
						onChange={(e) =>
							setFormData({
								...formData,
								url_match_mode: e.target.value as UrlMatchMode,
							})
						}
						aria-describedby="entry-url-match-mode-hint"
					>
						{URL_MATCH_MODE_OPTIONS.map((opt) => (
							<option key={opt.value} value={opt.value}>
								{opt.label}
							</option>
						))}
					</select>
					<p className="url-match-hint" id="entry-url-match-mode-hint">
						{
							URL_MATCH_MODE_OPTIONS.find(
								(o) => o.value === normalizeMatchMode(formData.url_match_mode),
							)?.hint
						}
					</p>
				</div>

				<div className="form-group">
					<label htmlFor="entry-username">Username *</label>
					<input
						id="entry-username"
						type="text"
						className="form-input"
						value={formData.username}
						onChange={(e) =>
							setFormData({ ...formData, username: e.target.value })
						}
						placeholder="email@example.com"
						aria-required="true"
						aria-invalid={!!error && !formData.username}
						aria-describedby={
							error && !showConfirmation ? "entry-error" : undefined
						}
					/>
				</div>

				<div className="form-group">
					<label htmlFor="entry-password">Password *</label>
					<div className="password-field field-value">
						<input
							id="entry-password"
							type={showPassword ? "text" : "password"}
							value={formData.password}
							onChange={(e) => {
								setFormData({ ...formData, password: e.target.value });
								setPasswordChanged(true);
							}}
							placeholder={isEditing && !passwordChanged ? "Unchanged" : ""}
							aria-required={isNew}
							aria-invalid={!!error && isNew && !formData.password}
							aria-describedby={
								error && !showConfirmation ? "entry-error" : undefined
							}
						/>
						<button
							onClick={() => void handleTogglePassword()}
							type="button"
							disabled={secretLoading}
							aria-label={showPassword ? "Hide password" : "Show password"}
						>
							{showPassword ? <EyeOffIcon /> : <EyeIcon />}
						</button>
						<button
							onClick={handleCopyPassword}
							type="button"
							disabled={secretLoading}
							aria-label="Copy password"
						>
							<CopyIcon />
						</button>
						<button
							onClick={() => setShowGenerator(true)}
							type="button"
							aria-label="Generate password"
						>
							<GenerateIcon />
						</button>
					</div>
					<StrengthMeter password={formData.password} />
				</div>

				{/* TOTP (Phase 2): edit mode only — the backend create request
				    carries no TOTP field, so new entries add it via a second edit. */}
				{isEditing && state.selectedEntry && (
					<TotpSecretField
						entryId={state.selectedEntry.id}
						value={totpSecret}
						visible={showTotpSecret}
						onChangeValue={(v) => {
							setTotpSecret(v);
							setTotpChanged(true);
						}}
						onToggleVisible={() => setShowTotpSecret((s) => !s)}
					/>
				)}

				<div className="form-group">
					{isEditing && !notesLoaded ? (
						<>
							<span className="form-label">Notes</span>
							<button
								className="btn btn-secondary btn-block"
								type="button"
								onClick={() => void handleLoadNotes()}
								disabled={secretLoading}
							>
								{secretLoading ? "Loading…" : "Load notes to edit"}
							</button>
						</>
					) : (
						<>
							<label htmlFor="entry-notes">Notes</label>
							<textarea
								id="entry-notes"
								className="form-input"
								value={formData.notes}
								onChange={(e) => {
									setFormData({ ...formData, notes: e.target.value });
									setNotesChanged(true);
								}}
								placeholder="Additional notes..."
								rows={3}
							/>
						</>
					)}
				</div>

				<div className="form-group">
					<GroupSelector
						value={formData.group_id || null}
						onChange={(id) => setFormData({ ...formData, group_id: id })}
					/>
					<TagsEditor
						value={formData.tags}
						onChange={(tags) => setFormData({ ...formData, tags })}
					/>
				</div>

				{/* v1.6.1 F5: Custom Fields get their own form-group — the shared
				    one squeezed the section against Tags and broke the vertical
				    rhythm of the other sections. */}
				{/* v1.6.1 F3: first interaction with the area lazy-loads the
				    stored values (focus capture — click or Tab into any input
				    fires it; jsdom's change/click never dispatch focus, only an
				    explicit focus event does). ACCEPTED POSTURE: keyboard Tab
				    pass-through decrypts stored values and bumps last_used_at —
				    asymmetric with the explicit notes button, but the user is
				    already inside the unlocked entry editor, so the on-demand
				    decrypt ratio is the same as the reveal path. */}
				<div
					className="form-group"
					onFocusCapture={() => loadValues("focus")}
				>
					<CustomFieldsEditor
						value={customFields}
						onChange={setCustomFields}
						onRevealRequest={() => loadValues("explicit")}
					/>
				</div>
			</form>

			<div className="entry-actions">
				{isEditing && (
					// Explicit type="button": without it this button would default
					// to submit semantics (harmless here since it sits outside the
					// form, but explicit beats implicit inside a form screen).
					<button
						type="button"
						className="btn btn-danger"
						onClick={handleDelete}
						disabled={isLoading}
					>
						Delete
					</button>
				)}
				{/* The form's submit button, associated across the DOM via form=
				    (it sits outside .entry-content). type=submit + form= makes it
				    the form's DEFAULT button, which is what lets Enter in any text
				    field run implicit submission — a type=button here would leave
				    the form with no default button and Enter would do nothing
				    (multi-field implicit-submission block). No onClick: the submit
				    event is the single save path, so a click cannot double-fire.
				    Re-entry while saving is blocked by disabled + handleSave. */}
				<button
					type="submit"
					form="pwdvault-entry-form"
					className="btn btn-primary"
					disabled={isLoading}
				>
					{isLoading ? "Saving..." : "Save"}
				</button>
			</div>

			<ConfirmationModal
				isOpen={showConfirmation}
				changes={changesList}
				onCancel={() => setShowConfirmation(false)}
				onConfirm={onConfirmSave}
				isSaving={isSavingConfirmed}
				/* v1.6.1 F1: a rejected save surfaces inside the modal — the
				   modal stays open on failure, so the main-form banner (gated
				   above) would hide the message behind the overlay. */
				error={showConfirmation ? error : null}
			/>

			<DeleteConfirmModal
				isOpen={showDeleteConfirm}
				message={`Are you sure you want to delete "${state.selectedEntry?.title || "this entry"}"? This cannot be undone.`}
				onConfirm={onConfirmDelete}
				onCancel={() => setShowDeleteConfirm(false)}
				isDeleting={isLoading}
			/>
			{/* Quick generator (A5): honours the saved defaults; owns its
			    generated-value state — see EntryGeneratorModal. */}
			<EntryGeneratorModal
				isOpen={showGenerator}
				onClose={() => setShowGenerator(false)}
				onUse={handleUseGenerated}
				onError={setError}
				options={{
					length: settingsState.settings.default_length,
					includeUppercase: settingsState.settings.default_include_uppercase,
					includeLowercase: settingsState.settings.default_include_lowercase,
					includeNumbers: settingsState.settings.default_include_numbers,
					includeSymbols: settingsState.settings.default_include_symbols,
				}}
			/>
			<UnsavedChangesModal
				isOpen={showUnsaved}
				onStay={() => setShowUnsaved(false)}
				onDiscard={() => {
					setShowUnsaved(false);
					leaveEntry();
				}}
			/>
		</div>
	);
}
