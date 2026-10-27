import {
	normalizeMatchMode,
	URL_MATCH_MODE_OPTIONS,
} from "../utils/urlMatchMode";
import { appendCustomFieldChanges } from "../components/CustomFieldsEditor";
import type { ChangeItem } from "../components/ConfirmationModal";
import type {
	CreateEntryRequest,
	CustomFieldInput,
	EntrySummary,
	UrlMatchMode,
} from "../types";

/**
 * Pure diff between the saved entry and the current form, for the save
 * confirmation modal. Every "changed" flag is passed in explicitly (secrets
 * are fetched on demand, so password/notes/TOTP edits are tracked outside
 * `current`); `totpChanged` implements the TOTP tri-state (untouched / cleared / set).
 * Exported for the pure-function test matrix (sameTags precedent).
 *
 * v1.6.1: extracted verbatim from EntryScreen (line-count budget) — this is
 * a module move, not a behavior change; the pure-function test matrices
 * (urlmatch / customFields) pin the semantics. No re-export shim: consumers
 * import from here directly.
 */
export function detectChanges(
	originalMeta: EntrySummary,
	originalSecret: { password: string; notes: string } | null,
	current: CreateEntryRequest,
	passwordChanged: boolean,
	notesChanged: boolean,
	totpChanged: boolean,
	// v1.6.0: the effective custom-field baseline — loaded values when the
	// secret channel ran, meta-derived rows otherwise. null reads as "no
	// stored fields" (pure-function convenience for the test matrix).
	originalCustomFields: CustomFieldInput[] | null,
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
	if (
		normalizeMatchMode(originalMeta.url_match_mode) !==
		normalizeMatchMode(current.url_match_mode)
	) {
		const labelOf = (mode: UrlMatchMode | undefined) =>
			URL_MATCH_MODE_OPTIONS.find((o) => o.value === normalizeMatchMode(mode))
				?.label ?? "";
		changes.push({
			fieldId: "url_match_mode",
			label: "URL Match",
			oldValue: labelOf(originalMeta.url_match_mode),
			newValue: labelOf(current.url_match_mode),
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
	// v1.6.0: the custom-field diff logic (whole-replacement, label pairing,
	// secret masking) lives beside its helpers in CustomFieldsEditor.
	return appendCustomFieldChanges(
		changes,
		originalCustomFields,
		current.custom_fields || [],
	);
}
