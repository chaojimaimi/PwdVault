import { useState, useEffect, useMemo } from "react";
import { useAuth, useSettings, useVault } from "../context/AppContext";
import { generatePassword } from "../api/vault";
import { copyWithTimeout } from "../utils/clipboard";
import { showToast } from "../utils/toast";
import { BackHeader } from "../components/BackHeader";
import { StrengthMeter } from "../components/StrengthMeter";
import { TotpCode } from "../components/TotpCode";
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
import { AccessibleDialog } from "../components/AccessibleDialog";
import type {
	CreateEntryRequest,
	EntrySummary,
	UpdateEntryRequest,
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
	});
	const [originalSecret, setOriginalSecret] = useState<{
		password: string;
		notes: string;
	} | null>(null);
	const [passwordChanged, setPasswordChanged] = useState(false);
	const [notesLoaded, setNotesLoaded] = useState(false);
	const [notesChanged, setNotesChanged] = useState(false);
	// TOTP tri-state (same update semantics as update_notes): untouched (no
	// totp_secret in the patch), cleared ("" in the field), or set. Only
	// shown while editing — create_entry has no TOTP field in the backend
	// contract (CreateEntryRequest), so new entries add TOTP via a second edit.
	const [totpSecret, setTotpSecret] = useState("");
	const [totpChanged, setTotpChanged] = useState(false);
	const isOtpauthUri = totpSecret.trim().startsWith("otpauth://");
	const [secretLoading, setSecretLoading] = useState(false);
	const [showPassword, setShowPassword] = useState(false);
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [tagInput, setTagInput] = useState("");
	const [showGenerator, setShowGenerator] = useState(false);
	const [generatedPassword, setGeneratedPassword] = useState("");
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
			});
			setOriginalSecret(null);
			setPasswordChanged(false);
			setNotesLoaded(false);
			setNotesChanged(false);
			setTotpSecret("");
			setTotpChanged(false);
		} else {
			setFormData({
				title: "",
				url: "",
				username: "",
				password: "",
				notes: "",
				tags: [],
				group_id: null,
			});
			setOriginalSecret(null);
			setPasswordChanged(false);
			setNotesLoaded(true);
			setNotesChanged(false);
			setTotpSecret("");
			setTotpChanged(false);
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
					formData.group_id,
			);
		}
		return (
			state.selectedEntry.title !== formData.title ||
			(state.selectedEntry.url || "") !== (formData.url || "") ||
			state.selectedEntry.username !== formData.username ||
			JSON.stringify(state.selectedEntry.tags || []) !==
				JSON.stringify(formData.tags) ||
			(state.selectedEntry.group_id || null) !== (formData.group_id || null)
		);
	}, [formData, state.selectedEntry]);
	const isDirty = metadataDirty || passwordChanged || notesChanged || totpChanged;

	useEffect(() => {
		const warn = (event: BeforeUnloadEvent) => {
			if (!isDirty) return;
			event.preventDefault();
		};
		window.addEventListener("beforeunload", warn);
		return () => window.removeEventListener("beforeunload", warn);
	}, [isDirty]);

	// Clear plaintext secrets from component state as soon as the user leaves
	// the screen, minimizing the time they reside in memory.
	useEffect(() => {
		return () => {
			setFormData((prev) => ({ ...prev, password: "", notes: "" }));
			setOriginalSecret(null);
			setTotpSecret("");
		};
	}, []);

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
				await actions.createEntry(formData);
				leaveEntry();
			} catch {
				setError("Failed to create entry");
			} finally {
				setIsLoading(false);
			}
			return;
		}

		if (!state.selectedEntry) return;

		const changes = detectChanges(
			state.selectedEntry,
			originalSecret,
			formData,
			passwordChanged,
			notesChanged,
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
			// TOTP tri-state: omit when untouched, "" clears, value sets.
			...(totpChanged ? { totp_secret: totpSecret.trim() } : {}),
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

	function detectChanges(
		originalMeta: EntrySummary,
		originalSecret: { password: string; notes: string } | null,
		current: CreateEntryRequest,
		passwordChanged: boolean,
		notesChanged: boolean,
	): ChangeItem[] {
		const changes: ChangeItem[] = [];
		if (originalMeta.title !== current.title) {
			changes.push({
				fieldId: "title",
				label: "Title",
				oldValue: originalMeta.title,
				newValue: current.title,
				valueType: "text",
			});
		}
		if ((originalMeta.url || "") !== (current.url || "")) {
			changes.push({
				fieldId: "url",
				label: "URL",
				oldValue: originalMeta.url || "",
				newValue: current.url || "",
				valueType: "text",
			});
		}
		if (originalMeta.username !== current.username) {
			changes.push({
				fieldId: "username",
				label: "Username",
				oldValue: originalMeta.username,
				newValue: current.username,
				valueType: "text",
			});
		}
		if (passwordChanged) {
			changes.push({
				fieldId: "password",
				label: "Password",
				valueType: "password",
			});
		}
		if (notesChanged) {
			const originalNotes = originalSecret?.notes ?? "";
			changes.push({
				fieldId: "notes",
				label: "Notes",
				oldValue: originalNotes.slice(0, 200),
				newValue: (current.notes || "").slice(0, 200),
				valueType: "notes",
			});
		}
		const origTags = originalMeta.tags || [];
		const added = current.tags.filter((t) => !origTags.includes(t));
		const removed = origTags.filter((t) => !current.tags.includes(t));
		if (added.length || removed.length) {
			changes.push({
				fieldId: "tags",
				label: "Tags",
				oldValue: removed.join(", "),
				newValue: added.join(", "),
				valueType: "tags",
			});
		}
		if ((originalMeta.group_id || null) !== (current.group_id || null)) {
			changes.push({
				fieldId: "group_id",
				label: "Group",
				oldValue: originalMeta.group_id || "",
				newValue: current.group_id || "",
				valueType: "text",
			});
		}
		if (totpChanged) {
			changes.push({
				fieldId: "totp_secret",
				label: "TOTP Secret",
				valueType: "password",
			});
		}
		return changes;
	}

	const onConfirmSave = async () => {
		if (!pendingChanges || !state.selectedEntry) return;
		setIsSavingConfirmed(true);
		try {
			await actions.updateEntry(state.selectedEntry.id, pendingChanges);
			setShowConfirmation(false);
			leaveEntry();
		} catch (e: unknown) {
			const msg = e instanceof Error ? e.message : "";
			setError("Failed to save entry" + (msg ? ": " + msg : ""));
		} finally {
			setIsSavingConfirmed(false);
		}
	};

	const handleAddTag = () => {
		if (tagInput.trim() && !formData.tags.includes(tagInput.trim())) {
			setFormData({ ...formData, tags: [...formData.tags, tagInput.trim()] });
			setTagInput("");
		}
	};

	const handleRemoveTag = (tag: string) => {
		setFormData({ ...formData, tags: formData.tags.filter((t) => t !== tag) });
	};

	const handleGeneratePassword = async () => {
		try {
			const pwd = await generatePassword({
				length: settingsState.settings.default_length,
				includeUppercase: settingsState.settings.default_include_uppercase,
				includeLowercase: settingsState.settings.default_include_lowercase,
				includeNumbers: settingsState.settings.default_include_numbers,
				includeSymbols: settingsState.settings.default_include_symbols,
			});
			setGeneratedPassword(pwd);
		} catch {
			setError("Failed to generate password");
		}
	};

	const handleUseGenerated = () => {
		setFormData({ ...formData, password: generatedPassword });
		setPasswordChanged(true);
		setShowGenerator(false);
		setGeneratedPassword("");
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

			<div className="entry-content screen-scroll-region">
				{error && (
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
						aria-describedby={error ? "entry-error" : undefined}
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
						aria-describedby={error ? "entry-error" : undefined}
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
							aria-describedby={error ? "entry-error" : undefined}
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
				    carries no TOTP field, so new entries add it via a second edit.
				    The live code view renders once the saved entry has a secret
				    (TotpCode hides itself while the backend reports none). */}
				{isEditing && state.selectedEntry && (
					<div className="form-group">
						<TotpCode entryId={state.selectedEntry.id} />
						<label htmlFor="entry-totp">TOTP Secret</label>
						<input
							id="entry-totp"
							type="text"
							className="form-input"
							value={totpSecret}
							onChange={(e) => {
								setTotpSecret(e.target.value);
								setTotpChanged(true);
							}}
							placeholder="Unchanged"
							autoComplete="off"
							spellCheck={false}
						/>
						{isOtpauthUri ? (
							<p className="totp-hint totp-hint-active" role="status">
								otpauth:// URI detected — it will be saved as-is and the code
								parameters parsed automatically.
							</p>
						) : (
							<p className="totp-hint">
								Paste a base32 secret or a full otpauth:// URI. Clearing this
								field and saving removes the TOTP secret.
							</p>
						)}
					</div>
				)}

				<div className="form-group">
					{isEditing && !notesLoaded ? (
						<>
							<span className="form-label">Notes</span>
							<button
								className="btn btn-secondary"
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

					<label htmlFor="tag-input" className="tag-label">
						Tags
					</label>
					<div className="entry-tags">
						{formData.tags.map((tag) => (
							<button
								key={tag}
								className="tag"
								type="button"
								onClick={() => handleRemoveTag(tag)}
								aria-label={`Remove tag ${tag}`}
							>
								{tag} ×
							</button>
						))}
					</div>
					<div className="tag-input-row">
						<input
							id="tag-input"
							type="text"
							className="form-input"
							value={tagInput}
							onChange={(e) => setTagInput(e.target.value)}
							onKeyDown={(e) => e.key === "Enter" && handleAddTag()}
							placeholder="Add tag..."
						/>
						<button
							className="btn btn-secondary"
							onClick={handleAddTag}
							type="button"
						>
							Add
						</button>
					</div>
				</div>
			</div>

			<div className="entry-actions">
				{isEditing && (
					<button
						className="btn btn-danger"
						onClick={handleDelete}
						disabled={isLoading}
					>
						Delete
					</button>
				)}
				<button
					className="btn btn-primary"
					onClick={handleSave}
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
			/>

			<DeleteConfirmModal
				isOpen={showDeleteConfirm}
				message={`Are you sure you want to delete "${state.selectedEntry?.title || "this entry"}"? This cannot be undone.`}
				onConfirm={onConfirmDelete}
				onCancel={() => setShowDeleteConfirm(false)}
				isDeleting={isLoading}
			/>
			<AccessibleDialog
				isOpen={showGenerator}
				onClose={() => setShowGenerator(false)}
				labelledBy="entry-generator-title"
				describedBy="entry-generator-description"
				initialFocusSelector="[data-generate-password]"
			>
				<div className="modal-header">
					<h3 id="entry-generator-title">Generate Password</h3>
					<button
						className="btn btn-icon"
						onClick={() => setShowGenerator(false)}
						aria-label="Close generator"
					>
						×
					</button>
				</div>
				<div className="modal-body">
					<p id="entry-generator-description" className="visually-hidden">
						Generate a password and insert it into this entry.
					</p>
					<div className="password-preview">
						{generatedPassword || "Click generate to create a password"}
					</div>
					<button
						className="btn btn-secondary"
						data-generate-password
						onClick={handleGeneratePassword}
					>
						Generate New
					</button>
				</div>
				<div className="modal-footer">
					<button
						className="btn btn-secondary"
						onClick={() => setShowGenerator(false)}
					>
						Cancel
					</button>
					<button
						className="btn btn-primary"
						onClick={handleUseGenerated}
						disabled={!generatedPassword}
					>
						Use Password
					</button>
				</div>
			</AccessibleDialog>
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

export default EntryScreen;
